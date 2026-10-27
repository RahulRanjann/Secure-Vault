import { OAuth2Client } from "google-auth-library";
import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { database } from "@/lib/database";

const SCOPE = "https://www.googleapis.com/auth/drive.appdata";
const SESSION_DAYS = 30;

function oauthClient() {
  const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI, APP_BASE_URL } = process.env;
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GOOGLE_REDIRECT_URI || !APP_BASE_URL) throw new Error("Google OAuth is not configured.");
  const expectedRedirect = new URL("/api/drive/callback", APP_BASE_URL).toString();
  if (GOOGLE_REDIRECT_URI !== expectedRedirect) throw new Error("Google OAuth redirect URI must match APP_BASE_URL.");
  return new OAuth2Client(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI);
}

function tokenSecret(): Buffer {
  const secret = process.env.APP_TOKEN_ENCRYPTION_KEY;
  if (!secret) throw new Error("Drive token encryption is not configured.");
  const key = Buffer.from(secret, "base64");
  if (key.byteLength !== 32) throw new Error("Token encryption key must decode to 32 bytes.");
  return key;
}

function encryptToken(token: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", tokenSecret(), iv);
  const ciphertext = Buffer.concat([cipher.update(token, "utf8"), cipher.final()]);
  return { iv: iv.toString("base64"), authTag: cipher.getAuthTag().toString("base64"), ciphertext: ciphertext.toString("base64") };
}

function decryptToken(record: { iv: string; auth_tag: string; ciphertext: string }): string {
  const decipher = createDecipheriv("aes-256-gcm", tokenSecret(), Buffer.from(record.iv, "base64"));
  decipher.setAuthTag(Buffer.from(record.auth_tag, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(record.ciphertext, "base64")), decipher.final()]).toString("utf8");
}

function sessionHash(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export type SessionUser = { id: string; email: string; name: string };

export async function getAuthorizationUrl(state: string, nonce: string) {
  return oauthClient().generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    include_granted_scopes: true,
    scope: ["openid", "email", "profile", SCOPE],
    state,
    nonce,
  });
}

export function getAppBaseUrl(): string {
  const value = process.env.APP_BASE_URL;
  if (!value) throw new Error("APP_BASE_URL is not configured.");
  const url = new URL(value);
  if (url.username || url.password || url.pathname !== "/" || url.search || url.hash) throw new Error("APP_BASE_URL must be an origin without credentials, a path, or query.");
  if (process.env.NODE_ENV === "production" && url.protocol !== "https:") throw new Error("APP_BASE_URL must use HTTPS in production.");
  return url.origin;
}

export function isValidOAuthState(received: string | null, expected: string | undefined): boolean {
  if (!received || !expected) return false;
  const actualBytes = Buffer.from(received);
  const expectedBytes = Buffer.from(expected);
  return actualBytes.byteLength === expectedBytes.byteLength && timingSafeEqual(actualBytes, expectedBytes);
}

export async function exchangeCode(code: string, expectedNonce: string): Promise<{ user: SessionUser; sessionToken: string; sessionExpiresAt: Date }> {
  const client = oauthClient();
  const { tokens } = await client.getToken(code);
  if (!tokens.id_token) throw new Error("Google did not return a verified sign-in identity.");

  const ticket = await new OAuth2Client(process.env.GOOGLE_CLIENT_ID).verifyIdToken({
    idToken: tokens.id_token,
    audience: process.env.GOOGLE_CLIENT_ID,
  });
  const identity = ticket.getPayload();
  if (!identity?.sub || identity.nonce !== expectedNonce || !identity.email || identity.email_verified !== true) {
    throw new Error("Google account must have a verified email address.");
  }

  const db = database();
  const userId = randomUUID();
  const rows = await db`
    INSERT INTO app_users (id, google_subject, email, display_name)
    VALUES (${userId}::uuid, ${identity.sub}, ${identity.email}, ${identity.name ?? identity.email})
    ON CONFLICT (google_subject) DO UPDATE SET
      email = EXCLUDED.email,
      display_name = EXCLUDED.display_name
    RETURNING id, email, display_name
  `;
  const row = rows[0] as { id: string; email: string; display_name: string } | undefined;
  if (!row) throw new Error("Google account could not be created.");

  if (tokens.refresh_token) {
    const encrypted = encryptToken(tokens.refresh_token);
    await db`
      INSERT INTO google_drive_tokens (user_id, iv, auth_tag, ciphertext)
      VALUES (${row.id}::uuid, ${encrypted.iv}, ${encrypted.authTag}, ${encrypted.ciphertext})
      ON CONFLICT (user_id) DO UPDATE SET
        iv = EXCLUDED.iv,
        auth_tag = EXCLUDED.auth_tag,
        ciphertext = EXCLUDED.ciphertext,
        updated_at = NOW()
    `;
  }
  const driveTokens = await db`SELECT user_id FROM google_drive_tokens WHERE user_id = ${row.id}::uuid LIMIT 1`;
  if (!driveTokens.length) throw new Error("Google Drive access was not granted. Sign in again and approve Drive app-data access.");

  const sessionToken = randomBytes(32).toString("base64url");
  const sessionExpiresAt = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000);
  await db`DELETE FROM app_sessions WHERE expires_at <= NOW()`;
  await db`
    INSERT INTO app_sessions (token_hash, user_id, expires_at)
    VALUES (${sessionHash(sessionToken)}, ${row.id}::uuid, ${sessionExpiresAt.toISOString()}::timestamptz)
  `;
  return {
    user: { id: row.id, email: row.email, name: row.display_name },
    sessionToken,
    sessionExpiresAt,
  };
}

export async function getSessionUser(sessionToken: string | undefined): Promise<SessionUser | null> {
  if (!sessionToken) return null;
  const rows = await database()`
    SELECT u.id, u.email, u.display_name
    FROM app_sessions s
    JOIN app_users u ON u.id = s.user_id
    WHERE s.token_hash = ${sessionHash(sessionToken)}
      AND s.expires_at > NOW()
    LIMIT 1
  `;
  const row = rows[0] as { id: string; email: string; display_name: string } | undefined;
  return row ? { id: row.id, email: row.email, name: row.display_name } : null;
}

export async function deleteSession(sessionToken: string | undefined): Promise<void> {
  if (!sessionToken) return;
  await database()`DELETE FROM app_sessions WHERE token_hash = ${sessionHash(sessionToken)}`;
}

export async function getDriveClient(userId: string) {
  const rows = await database()`
    SELECT iv, auth_tag, ciphertext
    FROM google_drive_tokens
    WHERE user_id = ${userId}::uuid
    LIMIT 1
  `;
  const row = rows[0] as { iv: string; auth_tag: string; ciphertext: string } | undefined;
  if (!row) throw new Error("Google Drive is not connected for this account.");
  const client = oauthClient();
  client.setCredentials({ refresh_token: decryptToken(row) });
  return client;
}

export async function driveIsConnected(userId: string): Promise<boolean> {
  const rows = await database()`
    SELECT user_id FROM google_drive_tokens WHERE user_id = ${userId}::uuid LIMIT 1
  `;
  return rows.length > 0;
}

export async function disconnectDrive(userId: string): Promise<void> {
  const rows = await database()`
    SELECT iv, auth_tag, ciphertext FROM google_drive_tokens WHERE user_id = ${userId}::uuid LIMIT 1
  `;
  const row = rows[0] as { iv: string; auth_tag: string; ciphertext: string } | undefined;
  if (row) {
    try {
      await oauthClient().revokeToken(decryptToken(row));
    } catch {
      // Local token removal still disconnects this account if Google's revoke endpoint is unavailable.
    }
  }
  await database()`DELETE FROM google_drive_tokens WHERE user_id = ${userId}::uuid`;
}

export { SCOPE };
