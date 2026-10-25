# Recovery and encrypted backups

## Recovery key

Vault creation generates a random 256-bit recovery key. The browser displays it once. The key encrypts the random data-encryption key independently of the master password and is never uploaded to Drive or included in an exported vault backup. Save it offline in a separate secure location (for example, a protected physical copy or a separate encrypted secret store). Do not keep the only copy beside your vault file.

The recovery key does not reveal the master password. It can unlock the vault and authorize setting a new master password. If both the master password and recovery key are lost, the data is unrecoverable. The app has no server-side key, default password, or backdoor.

## Encrypted export

Use **Backup & restore → Export encrypted backup**. Export includes ciphertext, format/KDF parameters, salt/nonces, and wrapped key metadata, not decrypted credential records or the recovery key. Store copies in separate secure locations and date them. Drive appDataFolder can be deleted independently and does not appear in the Drive UI.

## Restore safely

1. Keep the original vault and recovery key unchanged.
2. Use a duplicate backup file and a separate browser profile for a restore test.
3. Import the encrypted file. The browser validates size, version, schema, and KDF parameters before attempting the master password.
4. The app verifies authenticated decryption locally before replacing its local encrypted envelope. A failed import does not modify the existing vault.
5. Confirm expected record count and contents in the test profile before relying on that backup.
6. Do not import a stale backup over the only current vault. The app does not infer freshness from timestamps.

When importing a backup, Google Drive is not modified. Uploading a restored backup later requires explicit sync and a separate remote revision comparison. If Drive contains a different version, the sync should fail closed; compare copies before proceeding.

Clipboard copy/clearing is best effort: clipboard managers, clipboard history, and other applications may retain copied passwords or the recovery key.
