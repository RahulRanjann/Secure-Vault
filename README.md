# Secure Vault

A private password manager built with Next.js, React, TypeScript, Tailwind CSS, Web Crypto, Zod, Neon Postgres, and Google Drive appDataFolder. Google sign-in identifies each user; vault encryption and decryption happen in the browser. Neon stores account/session metadata and encrypted Google refresh tokens; each user's Google Drive receives only their encrypted vault envelope.

> **Private testing only.** This project has not received an independent security audit. Complete the production setup and security checklist before public use. Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before storing real credentials.

## Current features

- Create, unlock, manually lock, and inactivity-lock a vault.
- Optional per-browser quick unlock with a PIN, pattern, app password, or device passkey/biometric unlock where WebAuthn PRF is supported. The master password and recovery key remain available.
- AES-256-GCM authenticated vault encryption; random DEK; PBKDF2-HMAC-SHA-256 key-encryption key; one-time independent recovery key.
- Add/edit/view/search/delete login, phone-lock, and app-lock items; organize them with categories and favorites, reveal/copy secrets, and generate secure random passwords.
- Encrypted local persistence, encrypted JSON export/restore, optional Google Drive appDataFolder sync.
- Google OAuth sign-in with per-user opaque server sessions and encrypted Drive refresh tokens.
- Per-user Google Drive appDataFolder sync; local vault and quick-unlock data are namespaced by signed-in account.
- Tests for crypto primitives, password generation, OAuth state, and a Playwright vault flow.

## Requirements

- Node.js 22 (verified in this workspace), npm.
- A current browser with Web Crypto support.
- Optional: Google Cloud project with Drive API and OAuth web client.

## Run locally

The project is in the `secure-vault` subfolder because the workspace directory name contains a space and is not a valid npm package name.

1. In a terminal, change into `secure-vault`.
2. Run `npm install`.
3. This version requires Google sign-in, including for local use. Create a Neon database, run [database/schema.sql](database/schema.sql), copy `.env.example` to `.env.local`, fill the local OAuth/database values, and generate a separate 32-byte base64 `APP_TOKEN_ENCRYPTION_KEY`.
4. Follow [docs/GOOGLE_OAUTH_SETUP.md](docs/GOOGLE_OAUTH_SETUP.md) to configure the local Google OAuth origin and callback, then run `npm run dev` and open `http://localhost:3000`. The development and production servers bind to `127.0.0.1` and are not intended to be exposed to your network.

## Deploy to Vercel

This version is designed for multiple Google accounts and per-user Google Drive sync. Follow the complete [Vercel deployment and OAuth setup](docs/GOOGLE_OAUTH_SETUP.md) before deploying. Configure Vercel environment variables, the Neon pooled connection string, Google OAuth production redirect URI, `APP_BASE_URL`, and a strong independent token-encryption key. Run `database/schema.sql` against Neon before first sign-in.

Vercel hosts the application, not vault plaintext. Users must separately choose a strong vault master password; Google sign-in does not unlock or recover it. The encrypted vault is held in that user's Drive appDataFolder and locally in browser storage.

## Commands

- `npm run dev` — local development.
- `npm run build` — optimized production build.
- `npm start` — production server bound to `127.0.0.1` for local operation; Vercel runs its own serverless adapter.
- `npm run lint` — ESLint.
- `npm run typecheck` — strict TypeScript validation.
- `npm run test` — Vitest unit tests.
- `npm run test:neon` — verify Neon Postgres schema and perform a temporary private-bucket upload/download/delete test using `.env.local`.
- `npm run test:e2e` — Playwright browser test (install a Playwright browser if needed with `npx playwright install chromium`).
- `npm run check` — lint, typecheck, unit tests, and production build.

## Crypto choices

`argon2-browser` is currently stale (latest npm package version 1.18.0 was published five years ago), so this project uses Web Crypto PBKDF2-HMAC-SHA-256 at 600,000 iterations rather than claiming a maintained Argon2id integration. AES-GCM uses fresh random 96-bit nonces for each encryption operation. Header parameters are validated before KDF work and bound to ciphertext using additional authenticated data. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

Master password and recovery key loss means permanent data loss. See [docs/RECOVERY_AND_BACKUPS.md](docs/RECOVERY_AND_BACKUPS.md).

Quick-unlock settings are stored locally as an encrypted copy of the vault key. PINs and patterns are weaker than a strong password and can be guessed offline if an attacker copies browser storage. Keep a strong master password and recovery key; device unlock depends on browser and authenticator support.

## Environment variables

- `GOOGLE_CLIENT_ID` — OAuth web client ID.
- `GOOGLE_CLIENT_SECRET` — server-only OAuth secret.
- `GOOGLE_REDIRECT_URI` — exact OAuth callback URI (`${APP_BASE_URL}/api/drive/callback`).
- `APP_BASE_URL` — exact app origin; use the canonical HTTPS Vercel domain in production.
- `DATABASE_URL` — Neon Postgres connection string; use Neon’s pooled connection string for Vercel.
- `APP_TOKEN_ENCRYPTION_KEY` — base64 encoding of a random 32-byte server-side Google refresh-token encryption key, separate from vault keys.

Never commit `.env.local`. Token encryption does not protect against a compromised Vercel environment, database owner, browser, or user account.
