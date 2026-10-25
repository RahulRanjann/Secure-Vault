import { randomBytes } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { getAuthorizationUrl } from "@/lib/oauth";
import { requireLocalhost, safeError } from "@/lib/http-security";

export const runtime = "nodejs";

export async function GET(request: NextRequest) {
  const denied = requireLocalhost(request);
  if (denied) return denied;
  const state = randomBytes(32).toString("base64url");
  try {
    const response = NextResponse.redirect(await getAuthorizationUrl(state));
    response.cookies.set("sv_oauth_state", state, {
      httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/api/drive/callback", maxAge: 300,
    });
    response.headers.set("Cache-Control", "no-store");
    response.headers.set("Referrer-Policy", "no-referrer");
    return response;
  } catch {
    return safeError("Google Drive is not configured. Add the OAuth settings and restart the app.", 503);
  }
}