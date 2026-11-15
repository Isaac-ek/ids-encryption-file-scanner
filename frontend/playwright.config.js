import { defineConfig } from "@playwright/test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const data = mkdtempSync(path.join(tmpdir(), "securestream-browser-"));
const python = process.env.PYTHON_BIN || path.join(root, ".venv/bin/python");
export default defineConfig({
  testDir: "./e2e",
  workers: 1,
  timeout: 45000,
  use: {
    baseURL: "http://127.0.0.1:8184",
    channel: process.env.PLAYWRIGHT_CHROMIUM_CHANNEL || undefined,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
  },
  webServer: {
    command: `"${python}" scripts/create_admin.py && "${python}" -m uvicorn api.main:app --host 127.0.0.1 --port 8184`,
    cwd: root,
    url: "http://127.0.0.1:8184/api/health",
    reuseExistingServer: false,
    env: {
      SECURITY_DATA_DIR: data,
      DATABASE_URL: `sqlite:///${data}/browser.db`,
      JWT_SECRET: "isolated-browser-signing-secret-not-for-production-12345",
      WORKER_TOKEN: "isolated-browser-worker-secret-not-for-production-12345",
      BOOTSTRAP_USERNAME: "browser-owner",
      BOOTSTRAP_PASSWORD: "isolated-browser-password",
      SCAN_ALLOWED_HOSTS: "127.0.0.1",
      SCAN_ALLOW_LOCALHOST: "true",
    },
  },
});
