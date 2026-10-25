# Architecture

## Data flow

- The browser owns every decrypted credential and every vault key. The server receives only a versioned encrypted envelope during Drive sync.
- Google OAuth authorization is a separate server-side flow. Its authorization code is exchanged server-side; access/refresh tokens never enter browser JavaScript.
- Refresh-token JSON is encrypted with AES-256-GCM under `APP_TOKEN_ENCRYPTION_KEY` and stored in the Windows `%LOCALAPPDATA%/SecureVault/google-token.enc` location. File permissions are restricted where the OS honors them. The key is kept in the local environment, so this does not protect against malware or a compromised Windows account.
- The default vault is in browser localStorage only as an encrypted envelope. This is exposed to same-origin JavaScript, so a successful XSS can still steal decrypted data while unlocked; CSP and no third-party scripts reduce but cannot eliminate that risk.

## Key hierarchy

1. A 32-byte random DEK encrypts serialized vault records with AES-256-GCM.
2. A user master password is imported as PBKDF2 input. A random 16-byte salt and 600,000 PBKDF2-HMAC-SHA-256 iterations derive an AES-256-GCM KEK.
3. The KEK encrypts the random DEK using a fresh 12-byte nonce. The KDF algorithm, salt, iteration count, and purpose are included in authenticated additional data.
4. A separate random 32-byte recovery key independently encrypts the same DEK using AES-256-GCM and a fresh nonce. It is displayed only once and never stored with the Drive vault or exported backup.
5. Vault content and key-wrap entries have distinct purpose/version AAD; ciphertext, nonce, and format header are validated before KDF work. Wrong passwords and authenticated-data/ciphertext tampering fail closed.
6. Optional PIN, pattern, or app-password quick unlock uses a separate 600,000-iteration PBKDF2-HMAC-SHA-256 derivation and AES-GCM wrapper for a local copy of the DEK. On supported browsers, device unlock derives its wrapper from a platform authenticator's WebAuthn PRF output. These quick-unlock wrappers are stored only in browser localStorage, are not included in backups or Drive sync, and are cleared when restoring another vault.

PBKDF2 is used because the previously considered `argon2-browser` npm package is still version 1.18.0 from 2021 and its upstream repository's latest commit is five years old; that does not meet the project's maintained dependency requirement. No unmaintained Argon2 WASM is included. The iteration count is bounded 600,000–1,000,000 to avoid attacker-controlled excessive KDF work; the default should be benchmarked on target devices before long-term use.

JavaScript cannot promise reliable zeroization. Password strings, serialized records, and Web Crypto keys may be copied by the runtime/GC. The UI drops references on lock and clears mutable byte arrays where possible.

## Google Drive

The only requested OAuth scope is `https://www.googleapis.com/auth/drive.appdata`. A single file named `secure-vault.v1.json` is created in the hidden `appDataFolder`. Drive stores ciphertext only. Sync checks for duplicates, compares the current remote envelope before an upload when no version snapshot exists, sends If-Match where an ETag is available, checks metadata version, and downloads uploaded content for byte-for-byte verification. Google Drive does not document a dependable compare-and-swap precondition for all media uploads; concurrent edits can still race. The app fails closed on detected differences. Keep independent encrypted backups.

Drive appDataFolder cannot be inspected directly from the Drive UI, is specific to this app, and may be removed if the user uninstalls the app or deletes its app data. Export independent backups.

## Local security boundaries

- Development should bind to localhost and never be exposed using tunnels, public interfaces, or port forwarding.
- Mutating endpoints require matching same-origin requests and localhost Host values. OAuth uses 256-bit single-use state in a short-lived HTTP-only SameSite cookie.
- API routes impose encrypted envelope size limits, validate Zod schemas, avoid logging secrets, and mark responses no-store.
- `src/proxy.ts` configures CSP and security headers. Development permits eval only for Next.js diagnostics; production removes it.
- No server-side credential search exists. Search is performed against decrypted in-memory browser data.
