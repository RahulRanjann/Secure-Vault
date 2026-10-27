import { randomBytes } from "node:crypto";
import { NextResponse } from "next/server";
import { getAuthorizationUrl } from "@/lib/oauth";
import { safeError } from "@/lib/http-security";

export const runtime = "nodejs";

export async function GET() {
  const state = randomBytes(32).toString("base64url");
  const nonce = randomBytes(32).toString("base64url");
  try {
    const response = NextResponse.redirect(await getAuthorizationUrl(state, nonce));
    response.cookies.set("sv_oauth_state", state, {
      httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/api/drive/callback", maxAge: 300,
    });
    response.cookies.set("sv_oauth_nonce", nonce, {
      httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/api/drive/callback", maxAge: 300,
    });
    response.headers.set("Cache-Control", "no-store");
    response.headers.set("Referrer-Policy", "no-referrer");
    return response;
  } catch {
    return safeError("Google Drive is not configured. Add the OAuth settings and restart the app.", 503);
  }
}