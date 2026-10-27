# Google OAuth, Neon, and Vercel setup

## Create the database

1. Create a Neon Postgres project.
2. Run [`../database/schema.sql`](../database/schema.sql) against its database before starting the app.
3. Copy the pooled connection string into `DATABASE_URL`. Keep it server-side; do not prefix it with `NEXT_PUBLIC_`.
4. In the project root, run `neon init -y --org-id YOUR_ORG_ID --project-id YOUR_PROJECT_ID --branch production --service postgres --service object-storage`, then run `neon deploy`. Neon provisions the private `assets` bucket and pulls the database and S3 credentials into `.env.local`.
5. Run `npm run test:neon` to verify the app tables and exercise a temporary object upload/download/delete. This bucket is provisioned for future use; vault sync continues to use each user's own Google Drive and this smoke test does not copy vault data into Neon Object Storage.

## Configure Google OAuth

1. Create or select a Google Cloud project.
2. Enable the Google Drive API.
3. Configure the OAuth consent screen and publish/verify it as required for your intended audience. During testing, add allowed Google accounts as test users. Google may expire refresh tokens for apps left in Testing.
4. Create an OAuth client ID with application type **Web application**.
5. Add the local JavaScript origin `http://localhost:3000` and local redirect URI `http://localhost:3000/api/drive/callback` for development, if needed.
6. Add the production JavaScript origin `https://YOUR_DOMAIN` and exact redirect URI `https://YOUR_DOMAIN/api/drive/callback`.
7. Add the scopes `openid`, `email`, `profile`, and `https://www.googleapis.com/auth/drive.appdata`. This app requests only access to its own hidden app-data folder, not the user's general Drive files.

## Configure and deploy

1. Set these server-side environment variables in Vercel for Production (and Preview only if you explicitly configure matching OAuth callback URLs):
   - `APP_BASE_URL=https://YOUR_DOMAIN` (origin only, no trailing path).
   - `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`.
   - `GOOGLE_REDIRECT_URI=https://YOUR_DOMAIN/api/drive/callback` (must exactly match the Cloud Console and APP_BASE_URL).
   - `DATABASE_URL` (Neon pooled connection string).
   - `APP_TOKEN_ENCRYPTION_KEY` (base64 encoding of a cryptographically random 32-byte key).
2. Use the same values in `.env.local` for local development, with `APP_BASE_URL=http://localhost:3000` and the local redirect URI. Never commit `.env.local` or expose secrets through client-side `NEXT_PUBLIC_` variables.
3. Deploy the project to Vercel and attach the canonical production domain. Do not use preview domains for OAuth unless you register their exact origins/redirect URIs and configure matching environment variables.
4. Open the production domain and select **Continue with Google**. Users authorize sign-in and Drive app-data access in one OAuth flow. Each Google account maps to its own app account and Drive appDataFolder.
5. After signing in, create a vault or choose **Check Google Drive for a vault**. Vault encryption/decryption stays in the browser; Vercel receives encrypted envelopes only.
6. Disconnecting Drive revokes/removes that user's stored Drive refresh token but does not delete the encrypted file or sign the user out. Sign out to revoke the current app session.

The encrypted vault in `appDataFolder` is hidden from the normal Drive file list; it is not a replacement for independently exported backups. Neon stores account identity, hashed session tokens, and AES-GCM-encrypted Google refresh tokens, but not vault contents.

The Google refresh token is encrypted at rest using AES-256-GCM under `APP_TOKEN_ENCRYPTION_KEY`. The encryption key is a server-side Vercel secret, separate from Neon. Anyone who can access both the production environment key and database can decrypt the tokens. Rotate the key only with an explicit token re-encryption migration; replacing it directly makes existing tokens unreadable.

The OAuth callback validates a 256-bit state against a five-minute HTTP-only SameSite cookie. App sessions use random opaque values in HTTP-only SameSite cookies; only SHA-256 session-token hashes are stored in Neon. Drive access is resolved by the authenticated user ID on every server request.

## Production security

This is a multi-user deployment design, but it has not had an independent security audit. Restrict Neon and Vercel console access, use MFA, set billing/abuse alerts, keep dependencies updated, and review [the threat model](./THREAT_MODEL.md) and [security checklist](./SECURITY_REVIEW_CHECKLIST.md). Google sign-in does not protect or recover a user's vault master password. Users should export encrypted backups and keep their recovery keys securely.
