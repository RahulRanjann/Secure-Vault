import { OAuth2Client } from "google-auth-library";
import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { timingSafeEqual } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";

const SCOPE = "https://www.googleapis.com/auth/drive.appdata";
const TOKEN_PATH = path.join(process.env.LOCALAPPDATA ?? process.cwd(), "SecureVault", "google-token.enc");

function oauthClient() {
  const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI } = process.env;
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GOOGLE_REDIRECT_URI) throw new Error("Google Drive is not configured.");
  return new OAuth2Client(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI);
}

function tokenSecret(): Buffer {
  const secret = process.env.APP_TOKEN_ENCRYPTION_KEY;
  if (!secret) throw new Error("Google token storage is not configured.");
  const key = Buffer.from(secret, "base64");
  if (key.byteLength !== 32) throw new Error("Token encryption key must decode to 32 bytes.");
  return key;
}

export async function getAuthorizationUrl(state: string) {
  return oauthClient().generateAuthUrl({ access_type: "offline", prompt: "consent", scope: [SCOPE], state });
}

export function isValidOAuthState(received: string | null, expected: string | undefined): boolean {
  if (!received || !expected) return false;
  const actualBytes = Buffer.from(received);
  const expectedBytes = Buffer.from(expected);
  return actualBytes.byteLength === expectedBytes.byteLength && timingSafeEqual(actualBytes, expectedBytes);
}

export async function exchangeCode(code: string) {
  const { tokens } = await oauthClient().getToken(code);
  if (!tokens.refresh_token) throw new Error("Google did not provide offline access; reconnect and grant access.");
  const key = tokenSecret();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(tokens), "utf8"), cipher.final()]);
  const record = { iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), data: encrypted.toString("base64") };
  await mkdir(path.dirname(TOKEN_PATH), { recursive: true });
  await writeFile(TOKEN_PATH, JSON.stringify(record), { mode: 0o600 });
}

async function loadTokens(): Promise<Record<string, unknown>> {
  const record = JSON.parse(await readFile(TOKEN_PATH, "utf8")) as { iv: string; tag: string; data: string };
  const decipher = createDecipheriv("aes-256-gcm", tokenSecret(), Buffer.from(record.iv, "base64"));
  decipher.setAuthTag(Buffer.from(record.tag, "base64"));
  const clear = Buffer.concat([decipher.update(Buffer.from(record.data, "base64")), decipher.final()]).toString("utf8");
  return JSON.parse(clear) as Record<string, unknown>;
}

export async function getDriveClient() {
  const client = oauthClient();
  const tokens = await loadTokens();
  client.setCredentials(tokens);
  return client;
}

export async function disconnectDrive() {
  try {
    const tokens = await loadTokens();
    if (typeof tokens.refresh_token === "string") await oauthClient().revokeToken(tokens.refresh_token).catch(() => undefined);
  } catch {
    // A missing or unreadable token is already disconnected from this app.
  }
  const { unlink } = await import("node:fs/promises");
  await unlink(TOKEN_PATH).catch(() => undefined);
}

export async function driveIsConnected() {
  try {
    await readFile(TOKEN_PATH);
    return true;
  } catch {
    return false;
  }
}

export { SCOPE };