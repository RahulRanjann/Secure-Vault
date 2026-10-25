import { NextRequest, NextResponse } from "next/server";
import { exchangeCode, isValidOAuthState } from "@/lib/oauth";
import { requireLocalhost } from "@/lib/http-security";

export const runtime = "nodejs";

export async function GET(request: NextRequest) {
  const denied = requireLocalhost(request);
  if (denied) return denied;
  const state = request.nextUrl.searchParams.get("state");
  const expected = request.cookies.get("sv_oauth_state")?.value;
  const response = NextResponse.redirect(new URL("/", request.url));
  response.cookies.set("sv_oauth_state", "", { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/api/drive/callback", maxAge: 0 });
  response.headers.set("Cache-Control", "no-store");
  response.headers.set("Referrer-Policy", "no-referrer");
  if (!isValidOAuthState(state, expected)) {
    response.cookies.set("sv_drive_result", "state_error", { httpOnly: false, sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/", maxAge: 60 });
    return response;
  }
  const code = request.nextUrl.searchParams.get("code");
  if (!code) {
    response.cookies.set("sv_drive_result", "denied", { sameSite: "lax", path: "/", maxAge: 60 });
    return response;
  }
  try {
    await exchangeCode(code);
    response.cookies.set("sv_drive_result", "connected", { sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/", maxAge: 60 });
  } catch {
    response.cookies.set("sv_drive_result", "error", { sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/", maxAge: 60 });
  }
  return response;
}