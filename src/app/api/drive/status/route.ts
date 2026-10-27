import { NextRequest, NextResponse } from "next/server";
import { driveIsConnected, getSessionUser } from "@/lib/oauth";
import { safeError } from "@/lib/http-security";

export const runtime = "nodejs";

export async function GET(request: NextRequest) {
  try {
    const user = await getSessionUser(request.cookies.get("sv_session")?.value);
    return NextResponse.json({
      configured: Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && process.env.GOOGLE_REDIRECT_URI && process.env.APP_TOKEN_ENCRYPTION_KEY && process.env.DATABASE_URL && process.env.APP_BASE_URL),
      authenticated: Boolean(user),
      user,
      connected: user ? await driveIsConnected(user.id) : false,
    }, {
    headers: { "Cache-Control": "no-store" },
    });
  } catch {
    return safeError("Authentication status is unavailable. Check the database configuration.", 503);
  }
}