package dev.flamedwave.airlockauth;

import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.context.CommandContext;
import net.fabricmc.api.ModInitializer;
import net.fabricmc.fabric.api.command.v2.CommandRegistrationCallback;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerTickEvents;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerLifecycleEvents;
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
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
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
	private static final Map<UUID, LoginAttempts> LOGIN_ATTEMPTS = new HashMap<>();
	private static MinecraftServer loadedServer;
	private static Path accountFile;
	private static MinecraftServer configServer;
	private static AuthConfig config = AuthConfig.defaults();

	@Override
	public void onInitialize() {
		ServerPlayConnectionEvents.JOIN.register((handler, sender, server) -> onJoin(server, handler.player));
		ServerPlayConnectionEvents.DISCONNECT.register((handler, server) -> onDisconnect(handler.player));
		ServerTickEvents.END_SERVER_TICK.register(server -> holdUnauthenticatedPlayers());
		ServerLifecycleEvents.SERVER_STOPPING.register(server -> {
			if (loadedServer == server && accountFile != null) {
				saveAccounts(server);
			}
		});
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

		dispatcher.register(Commands.literal("changepassword")
			.then(Commands.argument("old_password", StringArgumentType.word())
				.then(Commands.argument("new_password", StringArgumentType.word())
					.executes(context -> changePassword(context)))));

		dispatcher.register(Commands.literal("auth")
			.requires(source -> source.permissions().hasPermission(Permissions.COMMANDS_MODERATOR))
			.then(Commands.literal("reset")
				.then(Commands.argument("player", GameProfileArgument.gameProfile())
					.executes(context -> resetPassword(context))))
				.then(Commands.literal("set-password")
					.requires(source -> source.getEntity() == null)
					.then(Commands.argument("player", GameProfileArgument.gameProfile())
						.then(Commands.argument("new_password", StringArgumentType.word())
							.executes(context -> setPassword(context)))))
			.then(Commands.literal("status")
				.then(Commands.argument("player", GameProfileArgument.gameProfile())
					.executes(context -> accountStatus(context))))
			.then(Commands.literal("force-login")
				.then(Commands.argument("player", GameProfileArgument.gameProfile())
					.executes(context -> forceLogin(context))))
			.then(Commands.literal("remove")
				.then(Commands.argument("player", GameProfileArgument.gameProfile())
					.executes(context -> removeAccount(context)))));
	}

	private static int accountStatus(CommandContext<CommandSourceStack> context) throws com.mojang.brigadier.exceptions.CommandSyntaxException {
		NameAndId target = getSingleTarget(context);
		if (target == null) {
			return 0;
		}
		ensureAccountsLoaded(context.getSource().getServer());
		boolean registered = ACCOUNTS.containsKey(target.id());
		context.getSource().sendSuccess(() -> message(target.name() + (registered ? " has a registered account." : " does not have a registered account.")), false);
		return 1;
	}

	private static int forceLogin(CommandContext<CommandSourceStack> context) throws com.mojang.brigadier.exceptions.CommandSyntaxException {
		NameAndId target = getSingleTarget(context);
		if (target == null) {
			return 0;
		}
		MinecraftServer server = context.getSource().getServer();
		ensureAccountsLoaded(server);
		ServerPlayer player = server.getPlayerList().getPlayer(target.id());
		if (player == null) {
			context.getSource().sendFailure(message(target.name() + " must be online to force a new login."));
			return 0;
		}
		if (SESSIONS.containsKey(player.getUUID())) {
			context.getSource().sendFailure(message(target.name() + " is already being asked to authenticate."));
			return 0;
		}
		beginAuthentication(player);
		LOGGER.info("Operator {} forced authentication for account {} ({})", context.getSource().getTextName(), target.name(), target.id());
		context.getSource().sendSuccess(() -> message("Forced " + target.name() + " to authenticate again."), false);
		return 1;
	}

	private static int removeAccount(CommandContext<CommandSourceStack> context) throws com.mojang.brigadier.exceptions.CommandSyntaxException {
		NameAndId target = getSingleTarget(context);
		if (target == null) {
			return 0;
		}
		MinecraftServer server = context.getSource().getServer();
		ensureAccountsLoaded(server);
		Credentials credentials = ACCOUNTS.remove(target.id());
		if (credentials == null) {
			context.getSource().sendFailure(message("No registered account was found for " + target.name() + "."));
			return 0;
		}
		if (!saveAccounts(server)) {
			ACCOUNTS.put(target.id(), credentials);
			context.getSource().sendFailure(message("The account removal could not be saved."));
			return 0;
		}
		LOGIN_ATTEMPTS.remove(target.id());
		LOGGER.info("Operator {} removed authentication account {} ({})", context.getSource().getTextName(), target.name(), target.id());
		context.getSource().sendSuccess(() -> message("Removed the registered account for " + target.name() + "."), false);
		return 1;
	}

	private static int changePassword(CommandContext<CommandSourceStack> context) throws com.mojang.brigadier.exceptions.CommandSyntaxException {
		ServerPlayer player = context.getSource().getPlayerOrException();
		if (SESSIONS.containsKey(player.getUUID())) {
			player.sendSystemMessage(message("Authenticate before changing your password."));
			return 0;
		}
		Credentials previous = ACCOUNTS.get(player.getUUID());
		if (previous == null) {
			player.sendSystemMessage(message("No registered account was found for you."));
			return 0;
		}

		String oldPassword = StringArgumentType.getString(context, "old_password");
		String newPassword = StringArgumentType.getString(context, "new_password");
		try {
			if (!MessageDigest.isEqual(previous.hash(), hashPassword(oldPassword, previous.salt()))) {
				player.sendSystemMessage(message("The current password is incorrect."));
				return 0;
			}
			if (!isValidPassword(newPassword)) {
				player.sendSystemMessage(message("Choose a password between " + config.minPasswordLength() + " and " + config.maxPasswordLength() + " characters."));
				return 0;
			}
			byte[] salt = new byte[16];
			RANDOM.nextBytes(salt);
			ACCOUNTS.put(player.getUUID(), new Credentials(salt, hashPassword(newPassword, salt)));
			if (!saveAccounts(context.getSource().getServer())) {
				ACCOUNTS.put(player.getUUID(), previous);
				player.sendSystemMessage(message("The password change could not be saved. Please try again later."));
				return 0;
			}
		} catch (GeneralSecurityException exception) {
			LOGGER.error("Could not hash a password change", exception);
			player.sendSystemMessage(message("The password change failed. Please try again later."));
			return 0;
		}

		player.sendSystemMessage(message(config.passwordChangedMessage()));
		return 1;
	}

	private static NameAndId getSingleTarget(CommandContext<CommandSourceStack> context) throws com.mojang.brigadier.exceptions.CommandSyntaxException {
		Collection<NameAndId> targets = GameProfileArgument.getGameProfiles(context, "player");
		if (targets.size() != 1) {
			context.getSource().sendFailure(message("Choose exactly one player."));
			return null;
		}
		return targets.iterator().next();
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

		LOGIN_ATTEMPTS.remove(target.id());
		LOGGER.info("Operator {} reset authentication account {} ({})", context.getSource().getTextName(), target.name(), target.id());
		context.getSource().sendSuccess(() -> message("Reset the account for " + target.name() + ". They can register a new password the next time they join."), false);
		return 1;
	}

	private static int setPassword(CommandContext<CommandSourceStack> context) {
		NameAndId target;
		try {
			target = getSingleTarget(context);
		} catch (com.mojang.brigadier.exceptions.CommandSyntaxException exception) {
			context.getSource().sendFailure(message("Could not resolve that account. No password was changed."));
			return 0;
		}
		if (target == null) {
			return 0;
		}

		MinecraftServer server = context.getSource().getServer();
		ensureAccountsLoaded(server);
		ensureConfigLoaded(server);
		Credentials previous = ACCOUNTS.get(target.id());
		if (previous == null) {
			context.getSource().sendFailure(message("No registered account was found for " + target.name() + "."));
			return 0;
		}

		String newPassword = StringArgumentType.getString(context, "new_password");
		if (!isValidPassword(newPassword)) {
			context.getSource().sendFailure(message("Choose a password between " + config.minPasswordLength() + " and " + config.maxPasswordLength() + " characters."));
			return 0;
		}

		try {
			byte[] salt = new byte[16];
			RANDOM.nextBytes(salt);
			ACCOUNTS.put(target.id(), new Credentials(salt, hashPassword(newPassword, salt)));
			if (!saveAccounts(server)) {
				ACCOUNTS.put(target.id(), previous);
				context.getSource().sendFailure(message("The password change could not be saved."));
				return 0;
			}
		} catch (GeneralSecurityException exception) {
			LOGGER.error("Could not hash an administrative password change", exception);
			context.getSource().sendFailure(message("The password change failed. Please try again later."));
			return 0;
		}

		LOGIN_ATTEMPTS.remove(target.id());
		LOGGER.info("Operator {} set the password for authentication account {} ({})", context.getSource().getTextName(), target.name(), target.id());
		context.getSource().sendSuccess(() -> message("Set the password for registered account " + target.name() + "."), false);
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
		if (!isValidPassword(password)) {
			player.sendSystemMessage(message("Choose a password between " + config.minPasswordLength() + " and " + config.maxPasswordLength() + " characters."));
			return 0;
		}
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

		completeAuthentication(player, session, config.registrationSuccessMessage());
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
		long now = System.nanoTime();
		LoginAttempts attempts = LOGIN_ATTEMPTS.get(player.getUUID());
		if (attempts != null && attempts.lockoutUntilNanos() > now) {
			long secondsRemaining = (attempts.lockoutUntilNanos() - now + 999_999_999L) / 1_000_000_000L;
			player.sendSystemMessage(message(config.lockoutMessage().replace("{seconds}", Long.toString(secondsRemaining))));
			return 0;
		}

		String password = StringArgumentType.getString(context, "password");
		try {
			byte[] candidate = hashPassword(password, credentials.salt());
			if (!MessageDigest.isEqual(credentials.hash(), candidate)) {
					int failedAttempts = attempts == null || attempts.lockoutUntilNanos() > 0 ? 1 : attempts.failedAttempts() + 1;
					if (failedAttempts >= config.maxFailedAttempts()) {
						LOGIN_ATTEMPTS.put(player.getUUID(), new LoginAttempts(0, System.nanoTime() + config.lockoutSeconds() * 1_000_000_000L));
						player.sendSystemMessage(message(config.lockoutMessage().replace("{seconds}", Integer.toString(config.lockoutSeconds()))));
				} else {
					LOGIN_ATTEMPTS.put(player.getUUID(), new LoginAttempts(failedAttempts, 0));
						player.sendSystemMessage(message(config.incorrectPasswordMessage().replace("{attempts}", Integer.toString(config.maxFailedAttempts() - failedAttempts))));
				}
				return 0;
			}
		} catch (GeneralSecurityException exception) {
			LOGGER.error("Could not verify a login password", exception);
			player.sendSystemMessage(message("Login failed. Please try again later."));
			return 0;
		}

		LOGIN_ATTEMPTS.remove(player.getUUID());
		completeAuthentication(player, session, config.loginSuccessMessage());
		return 1;
	}

	private static void onJoin(MinecraftServer server, ServerPlayer player) {
		ensureAccountsLoaded(server);
		ensureConfigLoaded(server);
		if (server.usesAuthentication()) {
			return;
		}

		beginAuthentication(player);
	}

	private static void beginAuthentication(ServerPlayer player) {
		int slot = allocateSlot();
		double authX = AUTH_START_X + slot * AUTH_SPACING;
		Session session = new Session(player, player.level(), player.getX(), player.getY(), player.getZ(), player.getYRot(), player.getXRot(), player.isInvisible(), authX, AUTH_Z, slot, System.nanoTime());
		SESSIONS.put(player.getUUID(), session);
		player.setNoGravity(true);
		player.setInvisible(true);
		player.setDeltaMovement(Vec3.ZERO);
		teleportToAuthSpot(player, session);

		String prompt = ACCOUNTS.containsKey(player.getUUID())
			? config.loginPrompt()
			: config.registerPrompt();
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
			if (config.loginTimeoutSeconds() > 0
				&& System.nanoTime() - session.startedAtNanos() >= config.loginTimeoutSeconds() * 1_000_000_000L) {
				player.connection.disconnect(message(config.loginTimeoutMessage()));
				continue;
			}
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
		Path temporaryFile = accountFile.resolveSibling(accountFile.getFileName() + ".tmp");
		Path backupFile = accountFile.resolveSibling(accountFile.getFileName() + ".bak");
		try {
			Files.createDirectories(accountFile.getParent());
			try (OutputStream output = Files.newOutputStream(temporaryFile)) {
				properties.store(output, "AirlockAuth password hashes");
			}
			if (Files.exists(accountFile)) {
				Files.copy(accountFile, backupFile, StandardCopyOption.REPLACE_EXISTING);
			}
			try {
				Files.move(temporaryFile, accountFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
			} catch (AtomicMoveNotSupportedException exception) {
				Files.move(temporaryFile, accountFile, StandardCopyOption.REPLACE_EXISTING);
			}
			return true;
		} catch (IOException exception) {
			try {
				Files.deleteIfExists(temporaryFile);
			} catch (IOException cleanupException) {
				exception.addSuppressed(cleanupException);
			}
			LOGGER.error("Could not save account credentials to {}", accountFile, exception);
			return false;
		}
	}

	private static boolean isValidPassword(String password) {
		return password.length() >= config.minPasswordLength() && password.length() <= config.maxPasswordLength();
	}

	private static void ensureConfigLoaded(MinecraftServer server) {
		if (configServer == server) {
			return;
		}
		configServer = server;
		Path configFile = server.getWorldPath(LevelResource.ROOT).resolve("airlockauth-config.properties");
		Properties properties = new Properties();
		properties.setProperty("min_password_length", "8");
		properties.setProperty("max_password_length", "64");
		properties.setProperty("max_failed_attempts", "5");
		properties.setProperty("lockout_seconds", "60");
		properties.setProperty("login_timeout_seconds", "120");
		properties.setProperty("message.login_prompt", "Login with /login <password>.");
		properties.setProperty("message.register_prompt", "Register with /register <password> <confirm_password>.");
		properties.setProperty("message.login_success", "Login successful.");
		properties.setProperty("message.register_success", "Registration successful.");
		properties.setProperty("message.password_changed", "Your password has been changed.");
		properties.setProperty("message.incorrect_password", "Incorrect password. {attempts} attempts remain.");
		properties.setProperty("message.lockout", "Too many failed login attempts. Try again in {seconds} seconds.");
		properties.setProperty("message.login_timeout", "Authentication timed out. Please reconnect and try again.");
		boolean saveConfig = !Files.exists(configFile);
		if (Files.exists(configFile)) {
			try (InputStream input = Files.newInputStream(configFile)) {
				properties.load(input);
				saveConfig = true;
			} catch (IOException exception) {
				LOGGER.error("Could not load settings from {}", configFile, exception);
			}
		}

		int minimumLength = readInteger(properties, "min_password_length", 8, 1, 256);
		int maximumLength = readInteger(properties, "max_password_length", 64, minimumLength, 256);
		config = new AuthConfig(
			minimumLength,
			maximumLength,
			readInteger(properties, "max_failed_attempts", 5, 1, 100),
			readInteger(properties, "lockout_seconds", 60, 1, 3600),
			readInteger(properties, "login_timeout_seconds", 120, 0, 86400),
			properties.getProperty("message.login_prompt"),
			properties.getProperty("message.register_prompt"),
			properties.getProperty("message.login_success"),
			properties.getProperty("message.register_success"),
			properties.getProperty("message.password_changed"),
			properties.getProperty("message.incorrect_password"),
			properties.getProperty("message.lockout"),
			properties.getProperty("message.login_timeout")
		);
		if (saveConfig) {
			try {
				Files.createDirectories(configFile.getParent());
				try (OutputStream output = Files.newOutputStream(configFile)) {
					properties.store(output, "AirlockAuth authentication settings");
				}
			} catch (IOException exception) {
				LOGGER.error("Could not save settings to {}", configFile, exception);
			}
		}
	}

	private static int readInteger(Properties properties, String key, int fallback, int minimum, int maximum) {
		try {
			return Math.clamp(Integer.parseInt(properties.getProperty(key)), minimum, maximum);
		} catch (NumberFormatException exception) {
			return fallback;
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

	private record LoginAttempts(int failedAttempts, long lockoutUntilNanos) {
	}

	private record AuthConfig(int minPasswordLength, int maxPasswordLength, int maxFailedAttempts, int lockoutSeconds, int loginTimeoutSeconds, String loginPrompt, String registerPrompt, String loginSuccessMessage, String registrationSuccessMessage, String passwordChangedMessage, String incorrectPasswordMessage, String lockoutMessage, String loginTimeoutMessage) {
		private static AuthConfig defaults() {
			return new AuthConfig(8, 64, 5, 60, 120, "Login with /login <password>.", "Register with /register <password> <confirm_password>.", "Login successful.", "Registration successful.", "Your password has been changed.", "Incorrect password. {attempts} attempts remain.", "Too many failed login attempts. Try again in {seconds} seconds.", "Authentication timed out. Please reconnect and try again.");
		}
	}

	private record Session(ServerPlayer player, ServerLevel returnLevel, double returnX, double returnY, double returnZ, float returnYaw, float returnPitch, boolean wasInvisible, double authX, double authZ, int slot, long startedAtNanos) {
	}
}