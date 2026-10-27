# Threat model

This multi-user app can be hosted on Vercel with Neon-backed accounts and per-user Google Drive storage. It has not undergone an independent security audit. "Encrypted" does not mean safe against a compromised client or hosting environment.

| Threat | Assessment |
|---|---|
| Attacker accesses Google account | Drive appDataFolder is limited to the app. An attacker who also obtains the encrypted vault can attempt offline password guesses; a strong unique master passphrase and PBKDF2 slow guesses but do not make a weak password safe. Revoke app access and restore from a trusted backup. |
| Copied encrypted vault | AES-256-GCM protects confidentiality/integrity if keys/passwords remain secret; metadata leaks format, sizes, and timestamps. Offline guessing remains possible. |
| Weak/guessed master password | PBKDF2 600,000 iterations adds cost; no password can compensate for a guessable secret. The envelope provides no remote rate-limiting for offline guesses. |
| Weak/guessed quick-unlock secret | Optional PIN, pattern, or app-password unlock wraps a copy of the vault key using PBKDF2 (600,000 iterations) and AES-GCM in local browser storage. Anyone copying that storage can try guesses offline. A PIN or pattern is substantially weaker than a strong password; use device unlock only on a trusted authenticator, and retain the master password and recovery key. |
| Stolen quick-unlock device credential | Platform passkey PRF output is used to derive the local key wrapper when supported. Device authentication depends on the browser, OS, authenticator, and their enrollment; the master password remains the fallback. |
| Malicious browser extensions | Not mitigated. Extensions with page access may read fields, clipboard, and in-memory vault keys. Use a clean, trusted browser profile. |
| Network access to the local service | The provided development and production scripts bind to `127.0.0.1`. Host and origin checks are defense-in-depth, not proof of a local network connection; do not run with a LAN/public bind, reverse proxy, tunnel, or port forwarding. |
| XSS | CSP, validation, no third-party script, and React escaping reduce risk. If script execution occurs on the origin while unlocked, decrypted data and keys are exposed. |
| Malicious npm dependencies | Lockfile and limited dependencies reduce exposure, not eliminate supply-chain risk. Review changes, use trusted package sources, and audit lockfile updates. |
| OAuth token theft | Tokens are server-only and encrypted at rest with a separate app key. A process with access to the running app, environment key, or Windows account can decrypt them. Revoke Google app access after suspected compromise. |
| Compromised user device/account | Not mitigated. Browser profile, local encrypted vault, and any unlocked session are available to malware or an attacker with sufficient account/process access. Production OAuth refresh tokens and their encryption key are held by the hosting/database services, not on end-user devices. |
| Malware/keylogger | Not mitigated. Malware can capture master password, recovery key, clipboard, and unlocked entries. |
| Browser developer tools | Not mitigated. The owner (or someone controlling the browser) can inspect memory and DOM while unlocked. Lock when unattended. |
| Lost device | Encrypted vault helps against offline access but does not protect a logged-in/unlocked session, a locally configured quick-unlock wrapper, or a compromised OS. Use Windows device encryption and OS account protection; keep the master password strong. |
| Corrupted or rolled-back backups | GCM detects corruption/tampering but cannot prove freshness. Drive revision IDs and envelope timestamps are not trusted anti-rollback counters. Maintain independent dated backups and verify restores. |
| Concurrent edits | Remote envelope comparison, version metadata, ETag precondition if available, duplicate detection, and read-back verification reduce lost updates. Drive media updates are not a fully dependable compare-and-swap API; a race remains. Do not edit from two devices simultaneously. |
| Compromised application update | Not mitigated cryptographically. A malicious update can exfiltrate data the next time the vault is unlocked. Review code/dependency updates and do not deploy unreviewed builds. |
| Phishing/fake login | Use the locally opened URL and verify browser origin. Google OAuth does not establish master-password correctness. Never enter recovery material into a page not known to be this local app. |

## Residual risks and scope limits

- No independent penetration test or security audit has been performed.
- The architecture supports multiple signed-in users on a shared deployment, but production readiness still depends on correct Vercel, Neon, and Google OAuth configuration. It has not had an independent security audit and is not intended for browser-extension distribution or hostile multi-device concurrent editing.
- Local development uses HTTP localhost, which modern browsers treat as a secure context, but traffic is not encrypted against local processes. Production should use HTTPS and a canonical configured origin.
- Browser localStorage can be read by same-origin JavaScript. The saved value is ciphertext, but an XSS while unlocked bypasses that protection.
- Clipboard clearing is best effort only. Clipboard managers/history and other applications may retain copied data.
- The PBKDF2 iteration count needs performance review on each intended device; there is no Argon2id because the reviewed browser implementation is stale.
