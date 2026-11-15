import { test, expect } from "@playwright/test";
import { createServer } from "node:http";
import { once } from "node:events";
import { readFile } from "node:fs/promises";

async function login(
  page,
  username = "browser-owner",
  password = "isolated-browser-password",
) {
  await page.goto("/");
  await page.getByLabel("Username", { exact: true }).fill(username);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Workspace overview", exact: true }),
  ).toBeVisible();
}
async function navigate(page, name) {
  const menu = page.getByRole("button", {
    name: "Open navigation",
    exact: true,
  });
  if (await menu.isVisible()) await menu.click();
  await page
    .getByRole("navigation", { name: "Main navigation" })
    .getByRole("button", { name, exact: true })
    .click();
}

test("model replay, file download/recovery, website checks and audit work together", async ({
  page,
}) => {
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/");
  await page.screenshot({
    path: "/tmp/securestream-v2-login.png",
    fullPage: true,
  });
  await login(page);
  await expect(page.getByText("Connected", { exact: true })).toBeVisible();
  await expect(page.getByText("XGBClassifier", { exact: true })).toBeVisible();
  await page.screenshot({
    path: "/tmp/securestream-v2-overview.png",
    fullPage: true,
  });
  await navigate(page, "Network events");
  await page
    .getByRole("button", { name: "Test a record", exact: true })
    .click();
  const inspector = page.getByRole("dialog");
  await inspector.getByRole("button", { name: "Load sample record" }).click();
  await inspector.getByRole("button", { name: "Run model prediction" }).click();
  await expect(inspector.getByText(/Event #\d+/)).toBeVisible();
  await inspector.getByRole("button", { name: "Close", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("saved event #");
  await expect(
    page.getByRole("cell", { name: "Model replay", exact: true }),
  ).toBeVisible();
  const exportPending = page.waitForEvent("download");
  await page.getByRole("button", { name: "CSV", exact: true }).click();
  const exported = await exportPending;
  expect(await readFile(await exported.path(), "utf8")).toContain(
    "model-replay",
  );
  await navigate(page, "Files");
  const original = Buffer.from(
    "Owned browser fixture — restore these exact bytes.\n",
  );
  await page.getByLabel("Upload sample file").setInputFiles({
    name: "browser-fixture.txt",
    mimeType: "text/plain",
    buffer: original,
  });
  await expect(page.getByRole("status")).toContainText(
    "Uploaded browser-fixture.txt",
  );
  await page.getByRole("button", { name: "Encrypt", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("original removed");
  await page.getByRole("button", { name: "Restore", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("File restored");
  const preview = page.getByRole("button", {
    name: "Preview browser-fixture.txt",
    exact: true,
  });
  await preview.click();
  await expect(page.getByRole("dialog")).toContainText(
    original.toString().trim(),
  );
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await expect(preview).toBeFocused();
  const downloadPending = page.waitForEvent("download");
  await page
    .getByRole("button", { name: "Download browser-fixture.txt", exact: true })
    .click();
  expect(await readFile(await (await downloadPending).path())).toEqual(
    original,
  );
  const fixture = createServer((req, res) => {
    res.writeHead(200, {
      "Content-Type": "text/html",
      "X-Content-Type-Options": "nosniff",
    });
    res.end(
      "<html><title>Owned test target</title><body>Browser verification fixture</body></html>",
    );
  });
  fixture.listen(0, "127.0.0.1");
  await once(fixture, "listening");
  try {
    await navigate(page, "Website checks");
    await page.getByLabel("Website URLs or hostnames").fill("127.0.0.1");
    await page.getByLabel("I own or have permission to assess these sites").check();
    await page.getByRole("button", {name: "Save approved websites"}).click();
    await expect(page.getByRole("status")).toContainText("Approved websites updated");
    await page
      .getByLabel("Target URL")
      .fill(`http://127.0.0.1:${fixture.address().port}`);
    await page.getByLabel("I am authorized to check this target").check();
    await page.getByRole("button", { name: "Run website check" }).click();
    await expect(page.getByRole("status")).toContainText("saved", {
      timeout: 35000,
    });
    await expect(
      page.getByRole("heading", { name: "Website findings", exact: true }),
    ).toBeVisible();
    await navigate(page, "Audit history");
    await expect(
      page.getByText("Stored audit chain verified", { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("cell", { name: "decrypt file", exact: true }),
    ).toBeVisible();
  } finally {
    await new Promise((resolve) => fixture.close(resolve));
  }
  expect(errors).toEqual([]);
});

test("administrators can give a member a login, edit access and reset passwords", async ({
  page,
}) => {
  await login(page);
  await navigate(page, "Users");
  await expect(
    page.getByRole("button", { name: "Delete browser-owner", exact: true }),
  ).toBeDisabled();
  await page.getByRole("button", { name: "Add user", exact: true }).click();
  let dialog = page.getByRole("dialog");
  await dialog.getByLabel("Full name").fill("Browser Member");
  await dialog.getByLabel("Username", { exact: true }).fill("e2e-member");
  await dialog.getByLabel("Initial password").fill("initial-member-password");
  await dialog
    .getByRole("button", { name: "Create account", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Account ready", exact: true }),
  ).toBeVisible();
  await expect(page.getByRole("dialog")).toContainText("e2e-member");
  await page.getByRole("button", { name: "Close dialog", exact: true }).click();
  await page.screenshot({
    path: "/tmp/securestream-v2-users.png",
    fullPage: true,
  });
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await login(page, "e2e-member", "initial-member-password");
  await expect(
    page
      .getByRole("navigation")
      .getByRole("button", { name: "Users", exact: true }),
  ).toHaveCount(0);
  await expect(
    page
      .getByRole("navigation")
      .getByRole("button", { name: "Audit history", exact: true }),
  ).toHaveCount(0);
  const memberToken = await page.evaluate(() =>
    sessionStorage.getItem("securestream-token"),
  );
  await page
    .getByRole("button", { name: "Account settings", exact: true })
    .click();
  dialog = page.getByRole("dialog");
  await dialog.getByLabel("Current password").fill("initial-member-password");
  await dialog
    .getByLabel("New password", { exact: true })
    .fill("changed-member-password");
  await dialog
    .getByRole("button", { name: "Update password", exact: true })
    .click();
  await expect(page.getByRole("status")).toContainText("Password changed");
  expect(
    (
      await page.request.get("/api/auth/me", {
        headers: { Authorization: `Bearer ${memberToken}` },
      })
    ).status(),
  ).toBe(401);
  const changedToken = await page.evaluate(() =>
    sessionStorage.getItem("securestream-token"),
  );
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await login(page);
  await navigate(page, "Users");
  const memberRow = page.getByRole("row").filter({
    has: page.getByRole("cell", { name: "e2e-member", exact: true }),
  });
  await memberRow.getByRole("button", { name: "Edit", exact: true }).click();
  dialog = page.getByRole("dialog");
  await dialog.getByLabel("Full name").fill("Updated Browser Member");
  await dialog.getByLabel("Access level").selectOption("admin");
  await dialog
    .getByLabel("New password (optional)")
    .fill("reset-member-password");
  await dialog
    .getByRole("button", { name: "Save changes", exact: true })
    .click();
  await expect(memberRow).toContainText("Updated Browser Member");
  await expect(memberRow).toContainText("Administrator");
  expect(
    (
      await page.request.get("/api/auth/me", {
        headers: { Authorization: `Bearer ${changedToken}` },
      })
    ).status(),
  ).toBe(401);
  const assigned = await page.request.post("/api/auth/login", {
    form: { username: "e2e-member", password: "reset-member-password" },
  });
  expect(assigned.ok()).toBe(true);
  expect((await assigned.json()).role).toBe("admin");
  await memberRow
    .getByRole("button", { name: "Delete e2e-member", exact: true })
    .click();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Remove account", exact: true })
    .click();
  await expect(memberRow).toHaveCount(0);
});

test("rule editing, file inspection, model metrics and bulk file actions are available", async ({
  page,
}) => {
  test.setTimeout(90000);
  await login(page);
  await navigate(page, "Rules");
  await page.getByRole("button", { name: "Add rule", exact: true }).click();
  let dialog = page.getByRole("dialog");
  await dialog.getByLabel("Rule name").fill("Browser review rule");
  await dialog.getByLabel("Pattern value").fill("192.0.2.1");
  await dialog.getByRole("button", { name: "Save rule", exact: true }).click();
  const rule = page.getByRole("row").filter({ hasText: "Browser review rule" });
  await rule
    .getByRole("button", { name: "Edit Browser review rule", exact: true })
    .click();
  await page.getByRole("dialog").getByLabel("Threshold (optional)").fill("250");
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Save rule", exact: true })
    .click();
  await expect(rule).toContainText("250");
  const enabled = rule.getByRole("switch");
  await enabled.click();
  await expect(enabled).toHaveAttribute("aria-checked", "false");
  await rule
    .getByRole("button", { name: "Delete Browser review rule", exact: true })
    .click();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Delete rule", exact: true })
    .click();
  await expect(rule).toHaveCount(0);
  await navigate(page, "File scanner");
  const eicar = Buffer.from(
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
  );
  await page.getByLabel("File to inspect").setInputFiles({
    name: "eicar-test.txt",
    mimeType: "text/plain",
    buffer: eicar,
  });
  await page
    .getByRole("button", { name: "Run file inspection", exact: true })
    .click();
  await expect(page.getByRole("status")).toContainText("saved", {
    timeout: 35000,
  });
  await expect(
    page.getByText("EICAR antivirus test signature detected.", { exact: true }),
  ).toBeVisible();
  await navigate(page, "Model performance");
  await expect(
    page.getByRole("cell", { name: "R2L", exact: true }),
  ).toBeVisible();
  await expect(page.getByText("XGBClassifier", { exact: true })).toBeVisible();
  await page.screenshot({
    path: "/tmp/securestream-v2-model.png",
    fullPage: true,
  });
  await navigate(page, "Files");
  for (const name of ["bulk-a.txt", "bulk-b.txt"]) {
    await page.getByLabel("Upload sample file").setInputFiles({
      name,
      mimeType: "text/plain",
      buffer: Buffer.from(name),
    });
    await expect(page.getByRole("status")).toContainText("Uploaded " + name);
  }
  for (const name of ["bulk-a.txt", "bulk-b.txt"])
    await page.getByLabel("Select " + name, { exact: true }).check();
  await page
    .getByRole("button", { name: "Encrypt selected", exact: true })
    .click();
  await expect(page.getByRole("status")).toContainText("2 files encrypted");
  await page.getByRole("button", { name: /^Encrypted backups/ }).click();
  for (const name of ["bulk-a.txt.enc", "bulk-b.txt.enc"])
    await page.getByLabel("Select " + name, { exact: true }).check();
  await page
    .getByRole("button", { name: "Restore selected", exact: true })
    .click();
  await expect(page.getByRole("status")).toContainText("2 files restored");
});

test("mobile navigation exposes every restored screen without horizontal page overflow", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await login(page);
  for (const name of [
    "Network events",
    "Website checks",
    "Files",
    "File scanner",
    "Model performance",
    "Users",
    "Rules",
    "Audit history",
    "Overview",
  ]) {
    await navigate(page, name);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
  }
  await page.screenshot({
    path: "/tmp/securestream-v2-mobile.png",
    fullPage: true,
  });
});

test("separate customer sessions see only their own workspace files and accounts", async ({
  page,
  browser,
}) => {
  await login(page);
  const otherContext = await browser.newContext();
  const other = await otherContext.newPage();
  try {
    await login(other, "other-customer", "isolated-other-password");
    await expect(other.getByRole("banner")).toContainText(
      "Other customer workspace",
    );
    await navigate(other, "Files");
    await other.getByLabel("Upload sample file").setInputFiles({
      name: "other-customer-private.txt",
      mimeType: "text/plain",
      buffer: Buffer.from("private customer sample"),
    });
    await expect(other.getByRole("status")).toContainText(
      "Uploaded other-customer-private.txt",
    );
    await expect(
      other.getByRole("row").filter({ hasText: "other-customer-private.txt" }),
    ).toBeVisible();
    await navigate(page, "Files");
    await expect(
      page.getByRole("row").filter({ hasText: "other-customer-private.txt" }),
    ).toHaveCount(0);
    await navigate(other, "Users");
    await expect(
      other.getByRole("cell", { name: "other-customer", exact: true }),
    ).toBeVisible();
    await expect(
      other.getByRole("cell", { name: "browser-owner", exact: true }),
    ).toHaveCount(0);
  } finally {
    await otherContext.close();
  }
});
