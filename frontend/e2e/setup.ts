import { request, type FullConfig } from "@playwright/test";
import { mkdir } from "node:fs/promises";
export default async function setup(config: FullConfig) {
  const client = await request.newContext({
    baseURL: config.projects[0].use.baseURL,
  });
  const response = await client.post("/api/auth/login", {
    headers: { "X-VulnRadar-Client": "web" },
    data: { access_key: "v4-test-only-" + "a".repeat(29) + "b" },
  });
  if (!response.ok())
    throw new Error(
      "Test-only authentication failed; start scripts/start_test_server.py, never use an operational database",
    );
  await mkdir("test-results/auth", { recursive: true });
  await client.storageState({ path: "test-results/auth/state.json" });
  await client.dispose();
}
