import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./e2e",
  workers: 1,
  globalSetup: "./e2e/setup.ts",
  use: {
    baseURL: process.env.VULNRADAR_TEST_URL || "http://127.0.0.1:8000",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    headless: true,
    storageState: "test-results/auth/state.json",
    launchOptions: {
      executablePath: process.env.CHROMIUM_PATH || undefined,
      args: ["--no-sandbox"],
    },
  },
});
