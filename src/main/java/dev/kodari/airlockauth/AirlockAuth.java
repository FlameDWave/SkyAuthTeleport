package dev.kodari.airlockauth;

import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.context.CommandContext;
import net.fabricmc.api.ModInitializer;
import net.fabricmc.fabric.api.command.v2.CommandRegistrationCallback;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerTickEvents;
import net.fabricmc.fabric.api.networking.v1.ServerPlayConnectionEvents;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.commands.arguments.GameProfileArgument;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.MutableComponent;
import net.minecraft.network.chat.contents.PlainTextContents;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.permissions.Permissions;
import net.minecraft.server.players.NameAndId;
import net.minecraft.world.entity.Entity;
import net.minecraft.world.level.storage.LevelResource;
import net.minecraft.world.level.portal.TeleportTransition;
import net.minecraft.world.phys.Vec3;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;

public class AirlockAuth implements ModInitializer {
	private static final Logger LOGGER = LoggerFactory.getLogger("airlockauth");
	private static final SecureRandom RANDOM = new SecureRandom();
	private static final int HASH_ITERATIONS = 210_000;
	private static final int HASH_BITS = 256;
	private static final double AUTH_Y = 1000.0;
	private static final double AUTH_START_X = 1_000_000.0;
	private static final double AUTH_SPACING = 2048.0;
	private static final double AUTH_Z = 1_000_000.0;
	private static final Map<UUID, Credentials> ACCOUNTS = new HashMap<>();
	private static final Map<UUID, Session> SESSIONS = new HashMap<>();
	private static MinecraftServer loadedServer;
	private static Path accountFile;

	@Override
	public void onInitialize() {
		ServerPlayConnectionEvents.JOIN.register((handler, sender, server) -> onJoin(server, handler.player));
		ServerPlayConnectionEvents.DISCONNECT.register((handler, server) -> onDisconnect(handler.player));
		ServerTickEvents.END_SERVER_TICK.register(server -> holdUnauthenticatedPlayers());
		CommandRegistrationCallback.EVENT.register((dispatcher, buildContext, selection) -> registerCommands(dispatcher));
	}

	public static boolean isAllowedCommand(UUID playerId, String command) {
		if (!SESSIONS.containsKey(playerId)) {
			return true;
		}

		String normalized = command.stripLeading();
		int end = 0;
		while (end < normalized.length() && !Character.isWhitespace(normalized.charAt(end))) {
			end++;
		}
		String root = normalized.substring(0, end);
		if (root.startsWith("/")) {
			root = root.substring(1);
		}
		return root.equals("register") || root.equals("login");
	}

	private static void registerCommands(CommandDispatcher<CommandSourceStack> dispatcher) {
		dispatcher.register(Commands.literal("register")
			.then(Commands.argument("password", StringArgumentType.word())
				.then(Commands.argument("confirm_password", StringArgumentType.word())
					.executes(context -> register(context)))));

		dispatcher.register(Commands.literal("login")
			.then(Commands.argument("password", StringArgumentType.word())
				.executes(context -> login(context))));

		dispatcher.register(Commands.literal("auth")
			.requires(source -> source.permissions().hasPermission(Permissions.COMMANDS_MODERATOR))
			.then(Commands.literal("reset")
				.then(Commands.argument("player", GameProfileArgument.gameProfile())
					.executes(context -> resetPassword(context)))));
	}

	private static int resetPassword(CommandContext<CommandSourceStack> context) throws com.mojang.brigadier.exceptions.CommandSyntaxException {
		Collection<NameAndId> targets = GameProfileArgument.getGameProfiles(context, "player");
		if (targets.size() != 1) {
			context.getSource().sendFailure(message("Choose exactly one player to reset."));
			return 0;
		}

		NameAndId target = targets.iterator().next();
		MinecraftServer server = context.getSource().getServer();
		ensureAccountsLoaded(server);
		Credentials credentials = ACCOUNTS.remove(target.id());
		if (credentials == null) {
			context.getSource().sendFailure(message("No registered account was found for " + target.name() + "."));
			return 0;
		}
		if (!saveAccounts(server)) {
			ACCOUNTS.put(target.id(), credentials);
			context.getSource().sendFailure(message("The account reset could not be saved."));
			return 0;
		}

		context.getSource().sendSuccess(() -> message("Reset the account for " + target.name() + ". They can register a new password the next time they join."), false);
		return 1;
	}

	private static int register(CommandContext<CommandSourceStack> context) throws com.mojang.brigadier.exceptions.CommandSyntaxException {
		ServerPlayer player = context.getSource().getPlayerOrException();
		Session session = SESSIONS.get(player.getUUID());
		if (session == null) {
			player.sendSystemMessage(message("You are already authenticated."));
			return 1;
		}
		if (ACCOUNTS.containsKey(player.getUUID())) {
			player.sendSystemMessage(message("This account is already registered. Use /login <password>."));
			return 0;
		}

		String password = StringArgumentType.getString(context, "password");
		String confirmation = StringArgumentType.getString(context, "confirm_password");
		if (!password.equals(confirmation)) {
			player.sendSystemMessage(message("The passwords do not match. Try /register <password> <confirm password>."));
			return 0;
		}

		byte[] salt = new byte[16];
		RANDOM.nextBytes(salt);
		try {
			ACCOUNTS.put(player.getUUID(), new Credentials(salt, hashPassword(password, salt)));
			if (!saveAccounts(context.getSource().getServer())) {
				ACCOUNTS.remove(player.getUUID());
				player.sendSystemMessage(message("Registration could not be saved. Please contact a server administrator."));
				return 0;
			}
		} catch (GeneralSecurityException exception) {
			LOGGER.error("Could not hash a registration password", exception);
			player.sendSystemMessage(message("Registration failed. Please try again later."));
			return 0;
		}

		completeAuthentication(player, session, "Registration successful.");
		return 1;
	}

	private static int login(CommandContext<CommandSourceStack> context) throws com.mojang.brigadier.exceptions.CommandSyntaxException {
		ServerPlayer player = context.getSource().getPlayerOrException();
		Session session = SESSIONS.get(player.getUUID());
		if (session == null) {
			player.sendSystemMessage(message("You are already authenticated."));
			return 1;
		}

		Credentials credentials = ACCOUNTS.get(player.getUUID());
		if (credentials == null) {
			player.sendSystemMessage(message("No registration was found. Use /register <password> <confirm password>."));
			return 0;
		}

		String password = StringArgumentType.getString(context, "password");
		try {
			byte[] candidate = hashPassword(password, credentials.salt());
			if (!MessageDigest.isEqual(credentials.hash(), candidate)) {
				player.sendSystemMessage(message("Incorrect password. Try /login <password>."));
				return 0;
			}
		} catch (GeneralSecurityException exception) {
			LOGGER.error("Could not verify a login password", exception);
			player.sendSystemMessage(message("Login failed. Please try again later."));
			return 0;
		}

		completeAuthentication(player, session, "Login successful.");
		return 1;
	}

	private static void onJoin(MinecraftServer server, ServerPlayer player) {
		ensureAccountsLoaded(server);
		if (server.usesAuthentication()) {
			return;
		}

		int slot = allocateSlot();
		double authX = AUTH_START_X + slot * AUTH_SPACING;
		Session session = new Session(player, player.level(), player.getX(), player.getY(), player.getZ(), player.getYRot(), player.getXRot(), player.isInvisible(), authX, AUTH_Z, slot);
		SESSIONS.put(player.getUUID(), session);
		player.setNoGravity(true);
		player.setInvisible(true);
		player.setDeltaMovement(Vec3.ZERO);
		teleportToAuthSpot(player, session);

		String prompt = ACCOUNTS.containsKey(player.getUUID())
			? "Login: /login <password>"
			: "Register: /register <password> <confirm password>";
		player.sendSystemMessage(message(prompt));
	}

	private static void onDisconnect(ServerPlayer player) {
		Session session = SESSIONS.remove(player.getUUID());
		if (session != null) {
			restorePlayer(player, session);
		}
	}

	private static void holdUnauthenticatedPlayers() {
		for (Session session : new ArrayList<>(SESSIONS.values())) {
			ServerPlayer player = session.player();
			player.setNoGravity(true);
			player.setDeltaMovement(Vec3.ZERO);
			if (Math.abs(player.getX() - session.authX()) > 0.01
				|| Math.abs(player.getY() - AUTH_Y) > 0.01
				|| Math.abs(player.getZ() - session.authZ()) > 0.01) {
				teleportToAuthSpot(player, session);
			}
		}
	}

	private static int allocateSlot() {
		Set<Integer> occupied = new HashSet<>();
		for (Session session : SESSIONS.values()) {
			occupied.add(session.slot());
		}
		int slot = 0;
		while (occupied.contains(slot)) {
			slot++;
		}
		return slot;
	}

	private static void teleportToAuthSpot(ServerPlayer player, Session session) {
		player.teleportTo(player.level(), session.authX(), AUTH_Y, session.authZ(), Set.of(), player.getYRot(), player.getXRot(), true);
	}

	private static void completeAuthentication(ServerPlayer player, Session session, String response) {
		SESSIONS.remove(player.getUUID());
		player.setNoGravity(false);
		player.setInvisible(session.wasInvisible());
		player.setDeltaMovement(Vec3.ZERO);
		player.teleport(player.findRespawnPositionAndUseSpawnBlock(false, TeleportTransition.DO_NOTHING));
		player.sendSystemMessage(message(response));
	}

	private static void restorePlayer(ServerPlayer player, Session session) {
		player.setNoGravity(false);
		player.setInvisible(session.wasInvisible());
		player.setDeltaMovement(Vec3.ZERO);
		player.teleportTo(session.returnLevel(), session.returnX(), session.returnY(), session.returnZ(), Set.of(), session.returnYaw(), session.returnPitch(), true);
	}

	private static void ensureAccountsLoaded(MinecraftServer server) {
		if (loadedServer == server) {
			return;
		}
		ACCOUNTS.clear();
		SESSIONS.clear();
		loadedServer = server;
		accountFile = server.getWorldPath(LevelResource.ROOT).resolve("airlockauth.properties");
		if (!Files.exists(accountFile)) {
			return;
		}

		Properties properties = new Properties();
		try (InputStream input = Files.newInputStream(accountFile)) {
			properties.load(input);
			for (String key : properties.stringPropertyNames()) {
				try {
					String value = properties.getProperty(key);
					int separator = value.indexOf(':');
					if (separator < 0) {
						throw new IllegalArgumentException("Missing credential separator");
					}
					byte[] salt = Base64.getDecoder().decode(value.substring(0, separator));
					byte[] hash = Base64.getDecoder().decode(value.substring(separator + 1));
					ACCOUNTS.put(UUID.fromString(key), new Credentials(salt, hash));
				} catch (IllegalArgumentException exception) {
					LOGGER.warn("Ignoring malformed account entry {} in {}", key, accountFile);
				}
			}
		} catch (IOException exception) {
			LOGGER.error("Could not load account credentials from {}", accountFile, exception);
		}
	}

	private static boolean saveAccounts(MinecraftServer server) {
		ensureAccountsLoaded(server);
		Properties properties = new Properties();
		for (Map.Entry<UUID, Credentials> entry : ACCOUNTS.entrySet()) {
			Credentials credentials = entry.getValue();
			properties.setProperty(entry.getKey().toString(), Base64.getEncoder().encodeToString(credentials.salt()) + ":" + Base64.getEncoder().encodeToString(credentials.hash()));
		}
		try {
			Files.createDirectories(accountFile.getParent());
			try (OutputStream output = Files.newOutputStream(accountFile)) {
				properties.store(output, "AirlockAuth password hashes");
			}
			return true;
		} catch (IOException exception) {
			LOGGER.error("Could not save account credentials to {}", accountFile, exception);
			return false;
		}
	}

	private static byte[] hashPassword(String password, byte[] salt) throws GeneralSecurityException {
		char[] characters = password.toCharArray();
		PBEKeySpec spec = new PBEKeySpec(characters, salt, HASH_ITERATIONS, HASH_BITS);
		try {
			return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
		} finally {
			Arrays.fill(characters, '\0');
			spec.clearPassword();
		}
	}

	private static Component message(String text) {
		return MutableComponent.create(new PlainTextContents.LiteralContents(text));
	}

	private record Credentials(byte[] salt, byte[] hash) {
	}

	private record Session(ServerPlayer player, ServerLevel returnLevel, double returnX, double returnY, double returnZ, float returnYaw, float returnPitch, boolean wasInvisible, double authX, double authZ, int slot) {
	}
}