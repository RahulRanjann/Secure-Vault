import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/oauth";
import { safeError } from "@/lib/http-security";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  try {
    const user = await getSessionUser(request.cookies.get("sv_session")?.value);
    return NextResponse.json({ authenticated: Boolean(user), user }, {
      headers: { "Cache-Control": "no-store" },
    });
  } catch {
    return safeError("Sign-in status is unavailable. Check the database configuration.", 503);
  }
}
