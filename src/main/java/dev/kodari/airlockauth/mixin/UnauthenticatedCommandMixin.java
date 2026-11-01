package dev.kodari.airlockauth.mixin;

import dev.kodari.airlockauth.AirlockAuth;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.MutableComponent;
import net.minecraft.network.chat.contents.PlainTextContents;
import net.minecraft.network.protocol.game.ServerboundChatCommandPacket;
import net.minecraft.network.protocol.game.ServerboundChatCommandSignedPacket;
import net.minecraft.server.network.ServerGamePacketListenerImpl;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

@Mixin(ServerGamePacketListenerImpl.class)
abstract class UnauthenticatedCommandMixin {
	@Inject(method = "handleChatCommand", at = @At("HEAD"), cancellable = true)
	private void airlockauth$guardUnsignedCommand(ServerboundChatCommandPacket packet, CallbackInfo callback) {
		checkCommand(packet.command(), callback);
	}

	@Inject(method = "handleSignedChatCommand", at = @At("HEAD"), cancellable = true)
	private void airlockauth$guardSignedCommand(ServerboundChatCommandSignedPacket packet, CallbackInfo callback) {
		checkCommand(packet.command(), callback);
	}

	private void checkCommand(String command, CallbackInfo callback) {
		ServerGamePacketListenerImpl listener = (ServerGamePacketListenerImpl) (Object) this;
		if (!AirlockAuth.isAllowedCommand(listener.player.getUUID(), command)) {
			Component message = MutableComponent.create(new PlainTextContents.LiteralContents("Authenticate with /register or /login before using other commands."));
			listener.player.sendSystemMessage(message);
			callback.cancel();
		}
	}
}