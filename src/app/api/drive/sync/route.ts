import { NextRequest, NextResponse } from "next/server";
import { DriveSyncError, syncVault } from "@/lib/drive";
import { parseEnvelope } from "@/lib/crypto";
import { requireSameOrigin, safeError } from "@/lib/http-security";
import { getSessionUser } from "@/lib/oauth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const denied = request.headers.get("sec-fetch-site") === "cross-site"
    ? safeError("Cross-site sync requests are not allowed.", 403)
    : null;
  if (denied) return denied;
  try {
    const user = await getSessionUser(request.cookies.get("sv_session")?.value);
    if (!user) return safeError("Sign in with Google before syncing.", 401);
    const result = await syncVault(user.id);
    return NextResponse.json(result, { headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    if (error instanceof DriveSyncError) return safeError(error.message, 502);
    return safeError("Google Drive sync failed. Reconnect if authorization was revoked.", 502);
  }
}

export async function POST(request: NextRequest) {
  const denied = requireSameOrigin(request);
  if (denied) return denied;
  try {
    const user = await getSessionUser(request.cookies.get("sv_session")?.value);
    if (!user) return safeError("Sign in with Google before syncing.", 401);
    const length = Number(request.headers.get("content-length") ?? 0);
    if (length > 1_600_000) return safeError("Encrypted vault exceeds the size limit.", 413);
    const body = await request.text();
    if (new TextEncoder().encode(body).byteLength > 1_600_000) return safeError("Encrypted vault exceeds the size limit.", 413);
    const input: unknown = JSON.parse(body);
    if (!input || typeof input !== "object" || !("envelope" in input)) return safeError("Invalid sync request.");
    const content = JSON.stringify(parseEnvelope((input as { envelope: unknown }).envelope));
    const version = "version" in input && typeof (input as { version?: unknown }).version === "string" ? (input as { version: string }).version : undefined;
    const result = await syncVault(user.id, content, version);
    return NextResponse.json(result, { headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    if (error instanceof DriveSyncError) return safeError(error.message, 502);
    if (error instanceof Error && error.message === "Drive vault changed during upload. No local data was overwritten.") {
      return safeError(error.message, 409);
    }
    return safeError("Google Drive sync failed. Resolve conflicts or reconnect and retry.", 502);
  }
}