# Google OAuth and Drive setup

1. Create or select a Google Cloud project in the Google Cloud Console.
2. Enable the Google Drive API.
3. Configure the OAuth consent screen. For private testing, use External/Testing when appropriate and add the owner's Google account as a test user.
4. Create an OAuth client ID with application type **Web application**.
5. Add authorized JavaScript origin `http://localhost:3000`.
6. Add redirect URI `http://localhost:3000/api/drive/callback` exactly.
7. Copy `.env.example` to `.env.local` in the project root. Fill `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `GOOGLE_REDIRECT_URI` with local values. Do not commit `.env.local`.
8. Generate a random 32-byte secret and base64 encode it for `APP_TOKEN_ENCRYPTION_KEY`. Keep it separate from source control and the vault recovery key. Back up this setting securely if you need the encrypted OAuth token file to remain usable after a reinstall.
9. Start the app with `npm run dev` and open `http://localhost:3000`. Select **Connect Google Drive**. Google authorization is independent of unlocking the vault.
10. Disconnect in the app's Drive panel to revoke the refresh token and remove the local encrypted token file. The encrypted Drive vault is not deleted. You can also revoke app permissions in Google Account security settings.
11. If consent is revoked, the token expires, or the OAuth client changes, reconnect from the local app and grant only the appDataFolder access.

The requested scope is `https://www.googleapis.com/auth/drive.appdata`; the app does not ask for broad Drive access. The appDataFolder is hidden from the Drive UI and is not a replacement for independently exported backups.

The refresh token is encrypted at rest using AES-256-GCM under `APP_TOKEN_ENCRYPTION_KEY` and stored in `%LOCALAPPDATA%/SecureVault/google-token.enc`. Keeping the key as an environment variable means protection is only against casual inspection of the token file. Malware, another process in the same Windows user, or a compromised account can often read both.

The OAuth callback validates a 256-bit state against a single-use, five-minute HTTP-only SameSite cookie. Tokens and authorization codes are not placed in client storage or application logs, and the callback immediately redirects to a clean path.

## Localhost only

Do not use a tunnel, public bind address, router forwarding, or public deployment for this build. Before remote access, review the threat model and redesign local Host/origin assumptions, authentication, token storage, CSRF protection, session handling, and deployment secrets.
