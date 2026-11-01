# AirlockAuth

AirlockAuth adds password registration and login protection for Fabric servers running in offline mode. Passwords are stored as salted PBKDF2 hashes, never as recoverable plaintext.

## Commands

- `/register <password> <confirm_password>` — create an account.
- `/login <password>` — authenticate an existing account.
- `/changepassword <old_password> <new_password>` — change your password after authenticating.
- `/auth reset <player>` — operator command; remove the saved credential so the player can register a new password.
- `/auth set-password <player> <new_password>` — server-console/RCON-only operator command; set a new password for an existing account.
- `/auth status <player>` — operator command; check whether an account is registered.
- `/auth force-login <player>` — operator command; require an online player to authenticate again.
- `/auth remove <player>` — operator command; delete a registered account.

Administrative account changes are recorded in the server log. Password values are not included in those audit messages.
The set-password command accepts its password as console command input. Use a trusted console and ensure your terminal or RCON client does not retain command history; never run it in public chat.

## Settings and account data

The first server join creates `airlockauth-config.properties` in the world root. It controls minimum and maximum password length, failed-login limit, lockout duration, authentication timeout, and player-facing authentication messages. Set `login_timeout_seconds=0` to disable the login timeout. Message values support `{attempts}` in `message.incorrect_password` and `{seconds}` in `message.lockout`.

Account credentials are stored in `airlockauth.properties` in the world root. Each successful account-data save first preserves the previous file as `airlockauth.properties.bak`, then replaces the live file using an atomic move when the filesystem supports it. Account data is also saved when the server begins shutting down. Stop the server before manually restoring the backup.

## Online-mode and proxy notes

The mod skips its password flow when Minecraft reports that server-side online authentication is enabled. Offline-mode servers require AirlockAuth authentication, including offline-mode backends behind a proxy; the mod does not currently inspect proxy forwarding metadata to distinguish a proxy-verified Microsoft session from an unverified offline connection.

For proxy deployments, configure secure forwarding correctly in both the proxy and backend, restrict backend network access so players cannot bypass the proxy, and test account behavior before opening the server. AirlockAuth is not a replacement for proxy forwarding or backend firewall rules.

Accounts are keyed by the UUID supplied to the server, not by a display name. Online-mode UUIDs remain stable across normal name changes. Offline-mode UUIDs are name-derived, so changing a player's name can produce a different account identity. Switching online mode or changing proxy UUID forwarding can also change the UUID seen by the mod. Back up `airlockauth.properties` before changing those settings. The mod does not automatically merge accounts by name because an unverified name is not a safe proof of account ownership.