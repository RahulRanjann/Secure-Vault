import { z } from "zod";

export const credentialSchema = z.object({
  id: z.string().uuid(),
  title: z.string().trim().min(1).max(120),
  url: z.string().max(2048).refine((value) => {
    if (!value) return true;
    try {
      return ["http:", "https:"].includes(new URL(value).protocol);
    } catch {
      return false;
    }
  }, "Use an http or https URL"),
  username: z.string().max(320),
  password: z.string().max(4096),
  notes: z.string().max(10_000),
  category: z.string().max(80),
  favorite: z.boolean(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});

export const vaultDataSchema = z.object({
  version: z.literal(1),
  credentials: z.array(credentialSchema).max(10_000),
});

export type Credential = z.infer<typeof credentialSchema>;
export type VaultData = z.infer<typeof vaultDataSchema>;

const base64RegExp = /^[A-Za-z0-9+/]+={0,2}$/;

const base64String = z.string().min(1).max(2_000_000).regex(base64RegExp);

const decodeBase64Bytes = (value: string): Uint8Array | null => {
  try {
    return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
  } catch {
    return null;
  }
};

const nonceString = base64String.refine((value) => {
  const bytes = decodeBase64Bytes(value);
  return bytes !== null && bytes.byteLength === 12;
}, "Nonce must decode to 12 bytes.");

const saltString = base64String.refine((value) => {
  const bytes = decodeBase64Bytes(value);
  return bytes !== null && bytes.byteLength === 16;
}, "Salt must decode to 16 bytes.");

const ciphertextString = base64String.refine((value) => {
  const bytes = decodeBase64Bytes(value);
  return bytes !== null && bytes.byteLength >= 16;
}, "Ciphertext must decode to at least 16 bytes.");

export const encryptedVaultSchema = z.object({
  format: z.literal("secure-vault"),
  version: z.literal(1),
  cipher: z.literal("AES-256-GCM"),
  kdf: z.literal("PBKDF2-HMAC-SHA-256"),
  iterations: z.number().int().min(600_000).max(1_000_000),
  salt: saltString,
  nonce: nonceString,
  ciphertext: ciphertextString,
  wrappedKey: z.object({ nonce: nonceString, ciphertext: ciphertextString }),
  recovery: z.object({ nonce: nonceString, ciphertext: ciphertextString }),
  updatedAt: z.string().datetime(),
});

export type EncryptedVault = z.infer<typeof encryptedVaultSchema>;