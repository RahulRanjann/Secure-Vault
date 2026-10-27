import { expect, test } from "@playwright/test";

test("create vault, configure quick unlock, reload, and verify master-password fallback", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.route("**/api/drive/status", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({
      configured: true,
      authenticated: true,
      user: { id: "f7a4a7e7-f8c7-4c94-bec3-7f19e2a4049d", email: "test@example.invalid", name: "Test User" },
      connected: true,
    }),
  }));
  await page.goto("/");
  await expect(page.locator("body")).toHaveJSProperty("scrollWidth", 390);
  await expect(page.getByRole("heading", { name: "Create your vault" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Create your vault" })).toBeInViewport();
  await page.getByLabel("Master password", { exact: true }).fill("a long local test passphrase 456");
  await page.getByLabel("Confirm master password").fill("a long local test passphrase 456");
  await page.getByRole("button", { name: "Create private vault" }).click();
  await expect(page.getByRole("heading", { name: "Save your recovery key" })).toBeVisible();
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: "Continue to my vault" }).click();
  await page.getByRole("button", { name: "Security settings" }).click();
  await page.getByLabel("New app PIN").fill("12345678");
  await page.getByLabel("Confirm app PIN").fill("12345678");
  await page.getByRole("button", { name: "Enable App PIN" }).click();
  await expect(page.getByText("App PIN enabled", { exact: true })).toBeVisible();
  await page.getByRole("dialog").getByRole("button", { name: "Close" }).click();
  await page.getByRole("button", { name: "Add item" }).first().click();
  await page.getByLabel("Service name *").fill("Sample service");
  await page.getByLabel("Website URL").fill("https://example.invalid");
  await page.getByLabel("Username or email").fill("user@example.invalid");
  await page.getByLabel("Password *").fill("never-a-real-password");
  await page.getByRole("button", { name: "Save securely" }).click();
  await expect(page.getByRole("button", { name: /^S Sample service/ })).toBeVisible();
  await expect(page.locator("body")).toHaveJSProperty("scrollWidth", 390);
  await page.getByRole("button", { name: "Close details" }).click();
  await page.getByRole("button", { name: "Add item" }).click();
  await page.getByLabel("Item type").selectOption("phone-lock");
  await page.getByLabel("Lock method").selectOption("pattern");
  await page.getByLabel("Phone or device name *").fill("Personal phone");
  await page.getByRole("button", { name: "Pattern point 1" }).click();
  await page.getByRole("button", { name: "Pattern point 2" }).click();
  await page.getByRole("button", { name: "Pattern point 3" }).click();
  await page.getByRole("button", { name: "Save securely" }).click();
  await expect(page.getByRole("button", { name: /^P Personal phone/ })).toBeVisible();
  await page.getByRole("button", { name: "Reveal secret" }).click();
  await expect(page.getByRole("button", { name: "Pattern point 3, sequence 3" })).toBeVisible();
  await page.getByRole("button", { name: "Close details" }).click();
  await page.getByRole("button", { name: "Add item" }).click();
  await page.getByLabel("Item type").selectOption("app-lock");
  await page.getByLabel("Lock method").selectOption("pattern");
  await page.getByLabel("App name *").fill("Banking app");
  for (const point of [1, 2, 3, 4]) {
    await page.getByRole("button", { name: `Pattern point ${point}` }).click();
  }
  await page.getByRole("button", { name: "Save securely" }).click();
  await expect(page.getByRole("dialog").getByText("Draw a pattern using exactly 3 or 6 different points.", { exact: true })).toBeVisible();
  for (const point of [5, 6]) {
    await page.getByRole("button", { name: `Pattern point ${point}` }).click();
  }
  await page.getByRole("button", { name: "Save securely" }).click();
  await expect(page.getByRole("button", { name: /^B Banking app/ })).toBeVisible();
  await page.getByRole("button", { name: "Reveal secret" }).click();
  await expect(page.getByRole("button", { name: "Pattern point 6, sequence 6" })).toBeVisible();
  await page.getByRole("button", { name: "Close details" }).click();
  await page.getByPlaceholder("Search your vault…").fill("Sample");
  await expect(page.getByRole("button", { name: /^S Sample service/ })).toBeVisible();
  const persisted = await page.evaluate(() => localStorage.getItem("secure-vault.encrypted.v1.f7a4a7e7-f8c7-4c94-bec3-7f19e2a4049d"));
  expect(persisted).not.toContain("never-a-real-password");
  expect(persisted).not.toContain("0.1.2.3");
  expect(persisted).not.toContain("0.1.2.3.4.5");
  await page.reload();
  await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
  await page.getByLabel("App PIN").fill("12345678");
  await page.getByRole("button", { name: "Unlock with App PIN" }).click();
  await expect(page.getByRole("button", { name: /^S Sample service/ })).toBeVisible();
  await page.getByRole("button", { name: /Lock vault/ }).click();
  await page.getByRole("button", { name: "Use master password instead" }).click();
  await page.getByLabel("Master password", { exact: true }).fill("a long local test passphrase 456");
  await page.getByRole("button", { name: "Unlock vault" }).click();
  await expect(page.getByRole("button", { name: /^S Sample service/ })).toBeVisible();
});

test("requires Google sign-in before showing a vault", async ({ page }) => {
  await page.route("**/api/drive/status", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ configured: true, authenticated: false, user: null, connected: false }),
  }));
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Sign in to Secure Vault" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Continue with Google" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Create your vault" })).toHaveCount(0);
});
