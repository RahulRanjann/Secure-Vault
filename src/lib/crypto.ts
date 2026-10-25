import {
  encryptedVaultSchema,
  vaultDataSchema,
  type EncryptedVault,
  type VaultData,
} from "@/lib/vault-schema";

export const KDF_ITERATIONS = 600_000;
export const MAX_VAULT_BYTES = 1_500_000;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const VAULT_AAD = encoder.encode("secure-vault:data:v1:AES-256-GCM");
const RECOVERY_AAD = encoder.encode("secure-vault:recovery-wrap:v1:AES-256-GCM");
const QUICK_UNLOCK_AAD = encoder.encode("secure-vault:quick-unlock:v1:AES-256-GCM");

function wrappingAad(salt: string, iterations: number): Uint8Array {
  return encoder.encode(`secure-vault:key-wrap:v1:AES-256-GCM:PBKDF2-HMAC-SHA-256:${iterations}:${salt}`);
}

function randomBytes(length: number): Uint8Array {
  if (!globalThis.crypto?.getRandomValues) throw new Error("Secure randomness is unavailable.");
  return crypto.getRandomValues(new Uint8Array(length));
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer as ArrayBuffer;
}

async function deriveWrappingKey(password: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
  if (!Number.isInteger(iterations) || iterations < 600_000 || iterations > 1_000_000) {
    throw new Error("Unsupported key derivation parameters.");
  }
  if (password.length < 12 || password.length > 1024) throw new Error("Master password must be 12–1024 characters.");
  const material = await crypto.subtle.importKey("raw", asArrayBuffer(encoder.encode(password)), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: asArrayBuffer(salt), iterations },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function aesKey(raw: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", asArrayBuffer(raw), { name: "AES-GCM" }, true, usages);
}

async function encryptBytes(key: CryptoKey, plaintext: Uint8Array, additionalData: Uint8Array): Promise<{ nonce: string; ciphertext: string }> {
  const nonce = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: asArrayBuffer(nonce), additionalData: asArrayBuffer(additionalData), tagLength: 128 }, key, asArrayBuffer(plaintext));
  return { nonce: toBase64(nonce), ciphertext: toBase64(new Uint8Array(ciphertext)) };
}

async function decryptBytes(key: CryptoKey, nonce: string, ciphertext: string, additionalData: Uint8Array): Promise<Uint8Array> {
  const clear = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: asArrayBuffer(fromBase64(nonce)), additionalData: asArrayBuffer(additionalData), tagLength: 128 },
    key,
    asArrayBuffer(fromBase64(ciphertext)),
  );
  return new Uint8Array(clear);
}

export type CreatedVault = { envelope: EncryptedVault; recoveryKey: string };
export type QuickUnlockMethod = "pin" | "pattern" | "password" | "device";
export type QuickUnlockConfig = {
  version: 1;
  method: QuickUnlockMethod;
  salt: string;
  nonce: string;
  ciphertext: string;
  credentialId?: string;
  prfSalt?: string;
};

function deriveQuickUnlockKey(secret: string | Uint8Array, salt: Uint8Array): Promise<CryptoKey> {
  const bytes = typeof secret === "string" ? encoder.encode(secret) : secret;
  if (!bytes.byteLength || bytes.byteLength > 1024) throw new Error("Invalid quick-unlock secret.");
  return crypto.subtle.importKey("raw", asArrayBuffer(bytes), "PBKDF2", false, ["deriveKey"]).then((material) =>
    crypto.subtle.deriveKey(
      { name: "PBKDF2", hash: "SHA-256", salt: asArrayBuffer(salt), iterations: KDF_ITERATIONS },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    ),
  );
}

export async function createQuickUnlock(
  key: CryptoKey,
  method: QuickUnlockMethod,
  secret: string | Uint8Array,
  credentialId?: string,
  prfSalt?: string,
): Promise<QuickUnlockConfig> {
  if (method === "device" && (!credentialId || !prfSalt)) throw new Error("A device credential is required.");
  const salt = randomBytes(16);
  const quickKey = await deriveQuickUnlockKey(secret, salt);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  try {
    const wrapped = await encryptBytes(quickKey, raw, QUICK_UNLOCK_AAD);
    return {
      version: 1,
      method,
      salt: toBase64(salt),
      ...wrapped,
      ...(credentialId && prfSalt ? { credentialId, prfSalt } : {}),
    };
  } finally {
    raw.fill(0);
  }
}

export function parseQuickUnlock(input: unknown): QuickUnlockConfig {
  if (!input || typeof input !== "object") throw new Error("Invalid quick-unlock settings.");
  const config = input as Partial<QuickUnlockConfig>;
  if (
    config.version !== 1
    || !["pin", "pattern", "password", "device"].includes(config.method ?? "")
    || typeof config.salt !== "string"
    || typeof config.nonce !== "string"
    || typeof config.ciphertext !== "string"
    || (config.method === "device" && (typeof config.credentialId !== "string" || !config.credentialId || typeof config.prfSalt !== "string"))
  ) {
    throw new Error("Invalid quick-unlock settings.");
  }
  if (
    fromBase64(config.salt).byteLength !== 16
    || fromBase64(config.nonce).byteLength !== 12
    || fromBase64(config.ciphertext).byteLength < 16
    || (config.method === "device" && fromBase64(config.prfSalt as string).byteLength !== 32)
  ) {
    throw new Error("Invalid quick-unlock settings.");
  }
  return config as QuickUnlockConfig;
}

export async function unlockQuickVault(
  input: unknown,
  quickUnlockInput: unknown,
  secret: string | Uint8Array,
): Promise<{ data: VaultData; key: CryptoKey }> {
  const envelope = parseEnvelope(input);
  const quickUnlock = parseQuickUnlock(quickUnlockInput);
  const quickKey = await deriveQuickUnlockKey(secret, fromBase64(quickUnlock.salt));
  const dekRaw = await decryptBytes(quickKey, quickUnlock.nonce, quickUnlock.ciphertext, QUICK_UNLOCK_AAD);
  try {
    const key = await aesKey(dekRaw, ["encrypt", "decrypt"]);
    const clear = await decryptBytes(key, envelope.nonce, envelope.ciphertext, VAULT_AAD);
    try {
      const data = vaultDataSchema.parse(JSON.parse(decoder.decode(clear)));
      return { data, key };
    } finally {
      clear.fill(0);
    }
  } finally {
    dekRaw.fill(0);
  }
}

export async function createVault(password: string, data: VaultData = { version: 1, credentials: [] }): Promise<CreatedVault> {
  const safeData = vaultDataSchema.parse(data);
  const dekRaw = randomBytes(32);
  const dek = await aesKey(dekRaw, ["encrypt", "decrypt"]);
  const salt = randomBytes(16);
  const kek = await deriveWrappingKey(password, salt, KDF_ITERATIONS);
  const saltEncoded = toBase64(salt);
  const wrappedKey = await encryptBytes(kek, dekRaw, wrappingAad(saltEncoded, KDF_ITERATIONS));
  const recoveryRaw = randomBytes(32);
  const recoveryKey = toBase64(recoveryRaw);
  const recoveryKek = await aesKey(recoveryRaw, ["encrypt", "decrypt"]);
  const recovery = await encryptBytes(recoveryKek, dekRaw, RECOVERY_AAD);
  const vaultCipher = await encryptBytes(dek, encoder.encode(JSON.stringify(safeData)), VAULT_AAD);
  const envelope = encryptedVaultSchema.parse({
    format: "secure-vault", version: 1, cipher: "AES-256-GCM", kdf: "PBKDF2-HMAC-SHA-256",
    iterations: KDF_ITERATIONS, salt: saltEncoded, ...vaultCipher, wrappedKey, recovery,
    updatedAt: new Date().toISOString(),
  });
  dekRaw.fill(0);
  recoveryRaw.fill(0);
  return { envelope, recoveryKey };
}

export async function unlockVault(input: unknown, password: string): Promise<{ data: VaultData; key: CryptoKey }> {
  const envelope = parseEnvelope(input);
  const kek = await deriveWrappingKey(password, fromBase64(envelope.salt), envelope.iterations);
  const dekRaw = await decryptBytes(kek, envelope.wrappedKey.nonce, envelope.wrappedKey.ciphertext, wrappingAad(envelope.salt, envelope.iterations));
  try {
    const key = await aesKey(dekRaw, ["encrypt", "decrypt"]);
    const clear = await decryptBytes(key, envelope.nonce, envelope.ciphertext, VAULT_AAD);
    const data = vaultDataSchema.parse(JSON.parse(decoder.decode(clear)));
    clear.fill(0);
    return { data, key };
  } finally {
    dekRaw.fill(0);
  }
}

export async function unlockWithRecovery(input: unknown, recoveryKey: string): Promise<{ data: VaultData; key: CryptoKey }> {
  const envelope = parseEnvelope(input);
  const raw = fromBase64(recoveryKey.trim());
  if (raw.byteLength !== 32) throw new Error("Invalid recovery key.");
  const recoveryKek = await aesKey(raw, ["encrypt", "decrypt"]);
  raw.fill(0);
  const dekRaw = await decryptBytes(recoveryKek, envelope.recovery.nonce, envelope.recovery.ciphertext, RECOVERY_AAD);
  try {
    const key = await aesKey(dekRaw, ["encrypt", "decrypt"]);
    const clear = await decryptBytes(key, envelope.nonce, envelope.ciphertext, VAULT_AAD);
    const data = vaultDataSchema.parse(JSON.parse(decoder.decode(clear)));
    clear.fill(0);
    return { data, key };
  } finally {
    dekRaw.fill(0);
  }
}

export async function saveVault(key: CryptoKey, data: VaultData, previous: unknown): Promise<EncryptedVault> {
  const envelope = parseEnvelope(previous);
  const safeData = vaultDataSchema.parse(data);
  const encrypted = await encryptBytes(key, encoder.encode(JSON.stringify(safeData)), VAULT_AAD);
  return encryptedVaultSchema.parse({ ...envelope, ...encrypted, updatedAt: new Date().toISOString() });
}

export async function changeMasterPassword(input: unknown, oldPassword: string, newPassword: string): Promise<EncryptedVault> {
  const envelope = parseEnvelope(input);
  const { key } = await unlockVault(envelope, oldPassword);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  try {
    const salt = randomBytes(16);
    const kek = await deriveWrappingKey(newPassword, salt, KDF_ITERATIONS);
    const saltEncoded = toBase64(salt);
    const wrappedKey = await encryptBytes(kek, raw, wrappingAad(saltEncoded, KDF_ITERATIONS));
    return encryptedVaultSchema.parse({ ...envelope, salt: saltEncoded, wrappedKey, iterations: KDF_ITERATIONS, updatedAt: new Date().toISOString() });
  } finally {
    raw.fill(0);
  }
}

export function parseEnvelope(input: unknown): EncryptedVault {
  const serialized = typeof input === "string" ? input : JSON.stringify(input);
  if (new TextEncoder().encode(serialized).byteLength > MAX_VAULT_BYTES) throw new Error("Vault file is too large.");
  return encryptedVaultSchema.parse(typeof input === "string" ? JSON.parse(input) : input);
}

export function exportEncryptedBackup(envelope: unknown): Blob {
  return new Blob([JSON.stringify(parseEnvelope(envelope), null, 2)], { type: "application/json" });
}

export async function resetMasterPasswordWithRecovery(input: unknown, recoveryKey: string, newPassword: string): Promise<EncryptedVault> {
  const envelope = parseEnvelope(input);
  const { key } = await unlockWithRecovery(envelope, recoveryKey);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  try {
    const salt = randomBytes(16);
    const saltEncoded = toBase64(salt);
    const kek = await deriveWrappingKey(newPassword, salt, KDF_ITERATIONS);
    const wrappedKey = await encryptBytes(kek, raw, wrappingAad(saltEncoded, KDF_ITERATIONS));
    return encryptedVaultSchema.parse({ ...envelope, salt: saltEncoded, wrappedKey, iterations: KDF_ITERATIONS, updatedAt: new Date().toISOString() });
  } finally {
    raw.fill(0);
  }
}