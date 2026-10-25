import type { QuickUnlockConfig } from "@/lib/crypto";

type PrfExtensionInputs = AuthenticationExtensionsClientInputs & {
  prf: { eval: { first: BufferSource } };
};

type PrfExtensionOutputs = AuthenticationExtensionsClientOutputs & {
  prf?: { enabled?: boolean; results?: { first?: ArrayBuffer } };
};

function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

function asBufferSource(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function decodeBase64Url(value: string): Uint8Array {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  return Uint8Array.from(atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=")), (char) => char.charCodeAt(0));
}

function decodeBase64(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

function prfSecret(credential: Credential | null): Uint8Array {
  if (!(credential instanceof PublicKeyCredential)) throw new Error("The device did not return a passkey.");
  const extensions = credential.getClientExtensionResults() as PrfExtensionOutputs;
  const result = extensions.prf?.results?.first;
  if (!result || result.byteLength !== 32) throw new Error("This browser or device does not support passkey PRF unlock.");
  return new Uint8Array(result);
}

export async function registerDeviceUnlock(): Promise<{ credentialId: string; prfSalt: string; secret: Uint8Array }> {
  if (!window.isSecureContext || !navigator.credentials?.create || !window.PublicKeyCredential) {
    throw new Error("Device unlock requires a browser with WebAuthn on localhost or HTTPS.");
  }
  const prfSaltBytes = randomBytes(32);
  const options: PublicKeyCredentialCreationOptions & { extensions: PrfExtensionInputs } = {
    challenge: asBufferSource(randomBytes(32)),
    rp: { name: "Secure Vault" },
    user: {
      id: asBufferSource(randomBytes(16)),
      name: "secure-vault-local",
      displayName: "Secure Vault",
    },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      userVerification: "required",
      residentKey: "discouraged",
    },
    timeout: 60_000,
    attestation: "none",
    extensions: { prf: { eval: { first: asBufferSource(prfSaltBytes) } } },
  };
  const credential = await navigator.credentials.create({ publicKey: options });
  if (!(credential instanceof PublicKeyCredential)) throw new Error("Device credential setup was canceled.");
  return {
    credentialId: encodeBase64Url(new Uint8Array(credential.rawId)),
    prfSalt: btoa(String.fromCharCode(...prfSaltBytes)),
    secret: prfSecret(credential),
  };
}

export async function getDeviceUnlockSecret(config: QuickUnlockConfig): Promise<Uint8Array> {
  if (!window.isSecureContext || !navigator.credentials?.get || !window.PublicKeyCredential) {
    throw new Error("Device unlock requires a browser with WebAuthn on localhost or HTTPS.");
  }
  if (!config.credentialId || !config.prfSalt) throw new Error("Device unlock is not configured correctly.");
  const options: PublicKeyCredentialRequestOptions & { extensions: PrfExtensionInputs } = {
    challenge: asBufferSource(randomBytes(32)),
    allowCredentials: [{ type: "public-key", id: asBufferSource(decodeBase64Url(config.credentialId)) }],
    userVerification: "required",
    timeout: 60_000,
    extensions: { prf: { eval: { first: asBufferSource(decodeBase64(config.prfSalt)) } } },
  };
  const credential = await navigator.credentials.get({ publicKey: options });
  return prfSecret(credential);
}
