import { NextRequest, NextResponse } from "next/server";
import { exchangeCode, getAppBaseUrl, isValidOAuthState } from "@/lib/oauth";

export const runtime = "nodejs";

export async function GET(request: NextRequest) {
  const state = request.nextUrl.searchParams.get("state");
  const expected = request.cookies.get("sv_oauth_state")?.value;
  const expectedNonce = request.cookies.get("sv_oauth_nonce")?.value;
  let baseUrl: string;
  try {
    baseUrl = getAppBaseUrl();
  } catch {
    return NextResponse.json({ error: "Authentication is not configured." }, { status: 503 });
  }
  const response = NextResponse.redirect(new URL("/", baseUrl));
  response.cookies.set("sv_oauth_state", "", { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/api/drive/callback", maxAge: 0 });
  response.cookies.set("sv_oauth_nonce", "", { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/api/drive/callback", maxAge: 0 });
  response.headers.set("Cache-Control", "no-store");
  response.headers.set("Referrer-Policy", "no-referrer");
  if (!isValidOAuthState(state, expected) || !expectedNonce) {
    response.cookies.set("sv_drive_result", "state_error", { httpOnly: false, sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/", maxAge: 60 });
    return response;
  }
  const code = request.nextUrl.searchParams.get("code");
  if (!code) {
    response.cookies.set("sv_drive_result", "denied", { sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/", maxAge: 60 });
    return response;
  }
  try {
    const { sessionToken, sessionExpiresAt } = await exchangeCode(code, expectedNonce);
    response.cookies.set("sv_session", sessionToken, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      path: "/",
      expires: sessionExpiresAt,
    });
    response.cookies.set("sv_drive_result", "connected", { sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/", maxAge: 60 });
  } catch {
    response.cookies.set("sv_drive_result", "error", { sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/", maxAge: 60 });
  }
  return response;
}