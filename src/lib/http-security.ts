import { NextRequest, NextResponse } from "next/server";

export function requireSameOrigin(request: NextRequest): NextResponse | null {
  const origin = request.headers.get("origin");
  const configuredOrigin = process.env.APP_BASE_URL;
  if (process.env.NODE_ENV === "production" && !configuredOrigin) {
    return NextResponse.json({ error: "Application origin is not configured." }, { status: 503 });
  }
  try {
    const expectedOrigin = configuredOrigin ? new URL(configuredOrigin).origin : request.nextUrl.origin;
    if (!origin || new URL(origin).origin !== expectedOrigin) {
      return NextResponse.json({ error: "Request origin rejected." }, { status: 403 });
    }
  } catch {
    return NextResponse.json({ error: "Request origin rejected." }, { status: 403 });
  }
  return null;
}

export function safeError(message: string, status = 400) {
  return NextResponse.json({ error: message }, { status, headers: { "Cache-Control": "no-store" } });
}