import { describe, expect, it } from "vitest";
import { driveResponseError, mergeDriveHeaders } from "@/lib/drive";

describe("Google Drive API errors", () => {
  it("replaces headers case-insensitively for multipart upload", () => {
    const headers = mergeDriveHeaders(
      new Headers({ Authorization: "Bearer local-token", "Content-Type": "application/json" }),
      { "Content-Type": "multipart/related; boundary=secure-vault" },
    );

    expect(headers.get("authorization")).toBe("Bearer local-token");
    expect(headers.get("content-type")).toBe("multipart/related; boundary=secure-vault");
  });

  it("preserves useful HTTP 400 details while redacting credentials and emails", async () => {
    const response = new Response(JSON.stringify({
      error: {
        code: 400,
        message: "Invalid parent for rahul@example.com with token ya29.secret-value",
        errors: [{ reason: "invalidParent" }],
      },
    }), { status: 400, headers: { "Content-Type": "application/json" } });

    const error = await driveResponseError(response, "create the encrypted vault");

    expect(error.message).toContain("invalidParent");
    expect(error.message).toContain("[redacted]");
    expect(error.message).not.toContain("rahul@example.com");
    expect(error.message).not.toContain("ya29.secret-value");
  });

  it("explains when the Drive API is disabled", async () => {
    const response = new Response(JSON.stringify({
      error: {
        status: "SERVICE_DISABLED",
        errors: [{ reason: "accessNotConfigured" }],
      },
    }), { status: 403, headers: { "Content-Type": "application/json" } });

    await expect(driveResponseError(response, "create the encrypted vault"))
      .resolves.toMatchObject({ message: expect.stringContaining("Google Drive API is not enabled") });
  });
});
