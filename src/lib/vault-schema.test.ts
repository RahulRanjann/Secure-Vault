import { describe, expect, it } from "vitest";
import { credentialSchema } from "@/lib/vault-schema";

const legacyCredential = {
  id: "3c02cb34-49bd-4119-b5ab-0cdbe6e974b5",
  title: "Email",
  url: "",
  username: "person@example.invalid",
  password: "encrypted-secret",
  notes: "",
  category: "",
  favorite: false,
  createdAt: "2025-01-01T00:00:00.000Z",
  updatedAt: "2025-01-01T00:00:00.000Z",
};

describe("credential schema", () => {
  it("treats existing credentials as logins", () => {
    expect(credentialSchema.parse(legacyCredential).type).toBe("login");
  });

  it.each(["phone-lock", "app-lock"] as const)("accepts the %s item type", (type) => {
    expect(credentialSchema.parse({ ...legacyCredential, type }).type).toBe(type);
  });

  it("accepts pattern lock methods", () => {
    expect(credentialSchema.parse({ ...legacyCredential, type: "phone-lock", lockMethod: "pattern" }).lockMethod).toBe("pattern");
    expect(credentialSchema.parse({ ...legacyCredential, type: "app-lock", lockMethod: "pattern" }).lockMethod).toBe("pattern");
  });

  it("rejects unsupported item types", () => {
    expect(credentialSchema.safeParse({ ...legacyCredential, type: "other" }).success).toBe(false);
  });
});
