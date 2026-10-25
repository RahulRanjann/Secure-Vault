import { NextRequest, NextResponse } from "next/server";
import { disconnectDrive } from "@/lib/oauth";
import { requireSameOrigin } from "@/lib/http-security";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  const denied = requireSameOrigin(request);
  if (denied) return denied;
  await disconnectDrive();
  return NextResponse.json({ disconnected: true }, { headers: { "Cache-Control": "no-store" } });
}