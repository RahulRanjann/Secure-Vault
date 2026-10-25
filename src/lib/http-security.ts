import { NextRequest, NextResponse } from "next/server";

export function requireLocalhost(request: NextRequest): NextResponse | null {
  const host = request.headers.get("host")?.split(":")[0]?.toLowerCase();
  if (host !== "localhost" && host !== "127.0.0.1") return NextResponse.json({ error: "Local access only." }, { status: 403 });
  return null;
}

export function requireSameOrigin(request: NextRequest): NextResponse | null {
  const origin = request.headers.get("origin");
  const host = request.headers.get("host");
  if (!origin || !host || new URL(origin).host !== host) return NextResponse.json({ error: "Request origin rejected." }, { status: 403 });
  return requireLocalhost(request);
}

export function safeError(message: string, status = 400) {
  return NextResponse.json({ error: message }, { status, headers: { "Cache-Control": "no-store" } });
}