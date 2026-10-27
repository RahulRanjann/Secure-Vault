import { NextRequest, NextResponse } from "next/server";
import { deleteSession } from "@/lib/oauth";
import { requireSameOrigin, safeError } from "@/lib/http-security";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  const denied = requireSameOrigin(request);
  if (denied) return denied;
  try {
    await deleteSession(request.cookies.get("sv_session")?.value);
    const response = NextResponse.json({ signedOut: true }, { headers: { "Cache-Control": "no-store" } });
    response.cookies.set("sv_session", "", {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      path: "/",
      maxAge: 0,
    });
    return response;
  } catch {
    return safeError("Could not sign out. Try again.", 503);
  }
}
