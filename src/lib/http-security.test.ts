import { afterEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { requireSameOrigin } from "@/lib/http-security";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("same-origin request protection", () => {
  it("accepts the configured application origin", () => {
    vi.stubEnv("APP_BASE_URL", "https://vault.example");
    vi.stubEnv("NODE_ENV", "production");
    const request = new NextRequest("https://vault.example/api/drive/sync", {
      headers: { origin: "https://vault.example" },
    });

    expect(requireSameOrigin(request)).toBeNull();
  });

  it("rejects a different origin", () => {
    vi.stubEnv("APP_BASE_URL", "https://vault.example");
    vi.stubEnv("NODE_ENV", "production");
    const request = new NextRequest("https://vault.example/api/drive/sync", {
      headers: { origin: "https://attacker.example" },
    });

    expect(requireSameOrigin(request)?.status).toBe(403);
  });

  it("fails closed in production when the canonical origin is missing", () => {
    vi.stubEnv("APP_BASE_URL", "");
    vi.stubEnv("NODE_ENV", "production");
    const request = new NextRequest("https://vault.example/api/drive/sync", {
      headers: { origin: "https://vault.example" },
    });

    expect(requireSameOrigin(request)?.status).toBe(503);
  });
});
