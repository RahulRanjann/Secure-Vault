# Security review checklist

This checklist is not an audit certificate. Complete it before storing real credentials and repeat after dependency, crypto-format, OAuth, or deployment changes.

## Before first real use

- [ ] Use a long, unique master passphrase from a trusted password source.
- [ ] Save the one-time recovery key offline; verify it in Security settings before relying on it.
- [ ] Export an encrypted backup and test its restore in a separate browser profile.
- [ ] Configure Google OAuth with only Drive appDataFolder scope and owner test account.
- [ ] Keep `.env.local`, OAuth secret, and token encryption key out of Git/backups shared with the vault.
- [ ] Confirm the server is bound to localhost only and no tunnel/port forwarding is active.
- [ ] Use Windows account protection and full-device encryption.
- [ ] Use a trusted browser profile without unnecessary extensions.
- [ ] Verify encrypted localStorage and exported file do not contain credential text.
- [ ] Review `npm audit` results and lockfile changes.

## Code and operation

- [ ] Run lint, type check, unit tests, E2E tests, and production build.
- [ ] Review CSP and response headers in the browser.
- [ ] Test wrong password, tampered ciphertext, invalid KDF parameters, and recovery.
- [ ] Test Drive token revocation, network failure, duplicate files, and remote conflict using mocks.
- [ ] Ensure no credential contents, master password, recovery key, access token, refresh token, authorization code, or secret are logged.
- [ ] Avoid simultaneous editing across devices; keep dated independent encrypted backups.
- [ ] Lock before leaving the device or opening untrusted content.

## Known limitations

- No external audit or penetration test has been performed.
- Browser JavaScript memory cannot be reliably zeroized; an XSS or malicious extension while unlocked can access plaintext.
- PBKDF2 is a deliberate fallback because the browser Argon2 package reviewed is stale. Benchmark iteration performance before use across all target devices.
- Drive does not give this implementation a fully reliable cross-device compare-and-swap guarantee for media updates; detected conflicts fail closed, but races remain.
- Encrypted token storage does not protect against malware or a compromised Windows account with access to the application secret.
- No public internet deployment, multi-user mode, or server-side vault access is supported.
