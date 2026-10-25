import { NextRequest, NextResponse } from "next/server";
import { driveIsConnected } from "@/lib/oauth";
import { requireLocalhost } from "@/lib/http-security";

export const runtime = "nodejs";

export async function GET(request: NextRequest) {
  const denied = requireLocalhost(request);
  if (denied) return denied;
  return NextResponse.json({ configured: Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && process.env.APP_TOKEN_ENCRYPTION_KEY), connected: await driveIsConnected() }, {
    headers: { "Cache-Control": "no-store" },
  });
}