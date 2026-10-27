import { NextRequest, NextResponse } from "next/server";
import { disconnectDrive, getSessionUser } from "@/lib/oauth";
import { requireSameOrigin, safeError } from "@/lib/http-security";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  const denied = requireSameOrigin(request);
  if (denied) return denied;
  try {
    const user = await getSessionUser(request.cookies.get("sv_session")?.value);
    if (!user) return safeError("Sign in to disconnect Google Drive.", 401);
    await disconnectDrive(user.id);
    return NextResponse.json({ disconnected: true }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return safeError("Google Drive could not be disconnected.", 503);
  }
}