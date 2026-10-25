# Secure Vault

A private, localhost-only personal password manager built with Next.js, React, TypeScript, Tailwind CSS, Web Crypto, Zod, and Google Drive appDataFolder. Vault encryption and decryption happen in the browser. Google Drive receives encrypted vault envelopes only.

> **Private testing only.** This project has not received an independent security audit. Do not expose it using tunnels, public interfaces, or port forwarding. Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before storing real credentials.

## Current features

- Create, unlock, manually lock, and inactivity-lock a vault.
- Optional per-browser quick unlock with a PIN, pattern, app password, or device passkey/biometric unlock where WebAuthn PRF is supported. The master password and recovery key remain available.
- AES-256-GCM authenticated vault encryption; random DEK; PBKDF2-HMAC-SHA-256 key-encryption key; one-time independent recovery key.
- Add/edit/view/search/delete credentials, categories, favorites, reveal/copy, and secure random password generator.
- Encrypted local persistence, encrypted JSON export/restore, optional Google Drive appDataFolder sync.
- Server-side Google OAuth authorization-code flow with state cookie and encrypted local token persistence.
- Tests for crypto primitives, password generation, OAuth state, and a Playwright vault flow.

## Requirements

- Node.js 22 (verified in this workspace), npm.
- A current browser with Web Crypto support.
- Optional: Google Cloud project with Drive API and OAuth web client.

## Run locally

The project is in the `secure-vault` subfolder because the workspace directory name contains a space and is not a valid npm package name.

1. In a terminal, change into `secure-vault`.
2. Run `npm install`.
3. For local-only use without Drive, run `npm run dev` and open `http://localhost:3000`.
4. To enable Drive, copy `.env.example` to `.env.local`, fill the OAuth values, and generate a separate 32-byte base64 `APP_TOKEN_ENCRYPTION_KEY`. Follow [docs/GOOGLE_OAUTH_SETUP.md](docs/GOOGLE_OAUTH_SETUP.md), then restart the development server.

## Commands

- `npm run dev` — local development.
- `npm run build` — optimized production build.
- `npm start` — production server; keep bound to localhost.
- `npm run lint` — ESLint.
- `npm run typecheck` — strict TypeScript validation.
- `npm run test` — Vitest unit tests.
- `npm run test:e2e` — Playwright browser test (install a Playwright browser if needed with `npx playwright install chromium`).
- `npm run check` — lint, typecheck, unit tests, and production build.

## Crypto choices

`argon2-browser` is currently stale (latest npm package version 1.18.0 was published five years ago), so this project uses Web Crypto PBKDF2-HMAC-SHA-256 at 600,000 iterations rather than claiming a maintained Argon2id integration. AES-GCM uses fresh random 96-bit nonces for each encryption operation. Header parameters are validated before KDF work and bound to ciphertext using additional authenticated data. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

Master password and recovery key loss means permanent data loss. See [docs/RECOVERY_AND_BACKUPS.md](docs/RECOVERY_AND_BACKUPS.md).

Quick-unlock settings are stored locally as an encrypted copy of the vault key. PINs and patterns are weaker than a strong password and can be guessed offline if an attacker copies browser storage. Keep a strong master password and recovery key; device unlock depends on browser and authenticator support.

## Environment variables

- `GOOGLE_CLIENT_ID` — OAuth web client ID.
- `GOOGLE_CLIENT_SECRET` — server-only OAuth secret.
- `GOOGLE_REDIRECT_URI` — exact local callback URI, normally `http://localhost:3000/api/drive/callback`.
- `APP_TOKEN_ENCRYPTION_KEY` — base64 encoding of a random 32-byte local token-file encryption key, separate from vault keys.

Never commit `.env.local`. Token encryption does not protect against malware or an attacker controlling the same Windows account.
