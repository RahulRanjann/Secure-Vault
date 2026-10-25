import { beforeAll, describe, expect, it } from "vitest";
import { webcrypto } from "node:crypto";
import {
  changeMasterPassword, createQuickUnlock, createVault, parseEnvelope, parseQuickUnlock,
  resetMasterPasswordWithRecovery, unlockQuickVault, unlockVault, unlockWithRecovery,
} from "@/lib/crypto";
import { generatePassword } from "@/lib/password-generator";

beforeAll(() => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, "crypto", { value: webcrypto });
});

describe("encrypted vault", () => {
  it("encrypts/decrypts and uses unique 96-bit nonces", async () => {
    const { envelope, recoveryKey } = await createVault("correct horse battery staple 42");
    expect(atob(envelope.nonce)).toHaveLength(12);
    expect(atob(envelope.wrappedKey.nonce)).toHaveLength(12);
    expect(atob(envelope.recovery.nonce)).toHaveLength(12);
    expect(new Set([envelope.nonce, envelope.wrappedKey.nonce, envelope.recovery.nonce]).size).toBe(3);
    const opened = await unlockVault(envelope, "correct horse battery staple 42");
    expect(opened.data).toEqual({ version: 1, credentials: [] });
    expect((await unlockWithRecovery(envelope, recoveryKey)).data).toEqual(opened.data);
  });

  it("rejects wrong passwords, modified authenticated metadata, and tampered ciphertext", async () => {
    const { envelope } = await createVault("correct horse battery staple 42");
    await expect(unlockVault(envelope, "not the correct master password")).rejects.toThrow();
    await expect(unlockVault({ ...envelope, iterations: 600_001 }, "correct horse battery staple 42")).rejects.toThrow();
    const bytes = atob(envelope.ciphertext).split("");
    bytes[0] = String.fromCharCode(bytes[0].charCodeAt(0) ^ 1);
    await expect(unlockVault({ ...envelope, ciphertext: btoa(bytes.join("")) }, "correct horse battery staple 42")).rejects.toThrow();
  });

  it("rewraps the data key for master password change and recovery reset", async () => {
    const { envelope, recoveryKey } = await createVault("correct horse battery staple 42");
    const changed = await changeMasterPassword(envelope, "correct horse battery staple 42", "another strong passphrase 987");
    await expect(unlockVault(changed, "correct horse battery staple 42")).rejects.toThrow();
    await expect(unlockVault(changed, "another strong passphrase 987")).resolves.toMatchObject({ data: { version: 1 } });
    const reset = await resetMasterPasswordWithRecovery(changed, recoveryKey, "recovered secure passphrase 876");
    await expect(unlockVault(reset, "recovered secure passphrase 876")).resolves.toMatchObject({ data: { version: 1 } });
  });

  it("supports locally encrypted quick unlock without changing the master-password envelope", async () => {
    const { envelope } = await createVault("correct horse battery staple 42");
    const { key } = await unlockVault(envelope, "correct horse battery staple 42");
    const quickUnlock = await createQuickUnlock(key, "pin", "12345678");

    expect(parseQuickUnlock(quickUnlock)).toEqual(quickUnlock);
    await expect(unlockQuickVault(envelope, quickUnlock, "12345678")).resolves.toMatchObject({
      data: { version: 1, credentials: [] },
    });
    await expect(unlockQuickVault(envelope, quickUnlock, "87654321")).rejects.toThrow();
    await expect(unlockQuickVault(envelope, { ...quickUnlock, ciphertext: "bad" }, "12345678")).rejects.toThrow();
    await expect(unlockVault(envelope, "correct horse battery staple 42")).resolves.toMatchObject({
      data: { version: 1, credentials: [] },
    });
  });

  it("rejects invalid KDF parameters and oversized/malformed envelopes", async () => {
    const { envelope } = await createVault("correct horse battery staple 42");
    expect(() => parseEnvelope({ ...envelope, iterations: 1 })).toThrow();
    expect(() => parseEnvelope("{" + " ".repeat(1_500_001))).toThrow();
    expect(() => parseEnvelope({ ...envelope, nonce: "short" })).toThrow();
  });
});

describe("password generator", () => {
  it("creates a configured password without ambiguous characters", () => {
    const password = generatePassword({ length: 32, uppercase: true, lowercase: true, digits: true, symbols: true, excludeAmbiguous: true });
    expect(password).toHaveLength(32);
    expect(password).toMatch(/[A-Z]/);
    expect(password).toMatch(/[a-z]/);
    expect(password).toMatch(/[0-9]/);
    expect(password).toMatch(/[!@#$%^&*()-_=+\[\]{}:,.?]/);
    expect(password).not.toMatch(/[Il1O0|`'\"]/);
  });

  it("rejects invalid configurations", () => {
    expect(() => generatePassword({ length: 7, uppercase: true, lowercase: false, digits: false, symbols: false, excludeAmbiguous: false })).toThrow();
    expect(() => generatePassword({ length: 10, uppercase: false, lowercase: false, digits: false, symbols: false, excludeAmbiguous: false })).toThrow();
  });
});
