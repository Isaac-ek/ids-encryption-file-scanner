import { test, expect } from "@playwright/test";
import { createServer } from "node:http";
import { once } from "node:events";

async function login(page) {
  await page.goto("/");
  await page.getByLabel("Username", { exact: true }).fill("browser-owner");
  await page
    .getByLabel("Password", { exact: true })
    .fill("isolated-browser-password");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Intrusion events" }),
  ).toBeVisible();
}

test("model replay, file recovery, scoped website results and audit work together", async ({
  page,
}) => {
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await login(page);
  await expect(page.getByText("Connected", { exact: true })).toBeVisible();
  await expect(page.getByText("XGBClassifier", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Load sample record" }).click();
  await expect(page.getByLabel("Connection features (JSON)")).not.toHaveValue(
    "",
  );
  await page.getByRole("button", { name: "Run model prediction" }).click();
  await expect(page.getByRole("status")).toContainText("saved event #");
  await expect(
    page.getByRole("cell", { name: "model-replay", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Files", exact: true }).click();
  const original = Buffer.from(
    "Owned browser fixture — restore these exact bytes.\n",
  );
  await page
    .getByLabel("Upload sample file")
    .setInputFiles({
      name: "browser-fixture.txt",
      mimeType: "text/plain",
      buffer: original,
    });
  await expect(page.getByRole("status")).toContainText(
    "Uploaded browser-fixture.txt",
  );
  await page.getByRole("button", { name: "Encrypt", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("original removed");
  await expect(
    page.getByText("No original files", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Restore", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("File restored");
  const preview = page.getByRole("button", { name: "Preview", exact: true });
  await preview.click();
  await expect(page.getByRole("dialog")).toContainText(
    original.toString().trim(),
  );
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await expect(preview).toBeFocused();
  const token = await page.evaluate(() =>
    sessionStorage.getItem("securestream-token"),
  );
  const recovered = await page.request.get(
    "/api/encryption/download?type=sensitive&filename=browser-fixture.txt",
    { headers: { Authorization: `Bearer ${token}` } },
  );
  expect(await recovered.body()).toEqual(original);

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
    await page
      .getByRole("button", { name: "Website checks", exact: true })
      .click();
    await page
      .getByLabel("Target URL")
      .fill(`http://127.0.0.1:${fixture.address().port}`);
    await page.getByLabel("I am authorized to check this target").check();
    await page.getByRole("button", { name: "Run website check" }).click();
    await expect(page.getByRole("status")).toContainText("saved");
    await expect(
      page.getByRole("heading", { name: /Results · check/ }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Audit", exact: true }).click();
    await expect(
      page.getByText("Stored audit chain verified", { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("cell", { name: "decrypt_file", exact: true }),
    ).toBeVisible();
    await page.screenshot({
      path: "/tmp/securestream-desktop.png",
      fullPage: true,
    });
  } finally {
    await new Promise((resolve) => fixture.close(resolve));
  }
  expect(errors).toEqual([]);
});

test("mobile navigation remains usable without horizontal overflow", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await login(page);
  for (const section of ["Website checks", "Files", "Audit", "Events"]) {
    await page.getByRole("button", { name: section, exact: true }).click();
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
  }
  await page.screenshot({
    path: "/tmp/securestream-mobile.png",
    fullPage: true,
  });
});
