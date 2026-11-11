// Real browser captures, restricted to the disposable mock-OSV entrypoint.
import { chromium, request } from "playwright";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const baseURL = process.env.VULNRADAR_TEST_URL;
if (!baseURL || !["127.0.0.1", "localhost"].includes(new URL(baseURL).hostname))
  throw new Error("Use a loopback server launched by scripts/start_test_server.py --mock-osv");
const legacy = process.argv.includes("--baseline");
const prepare = process.argv.includes("--prepare");
const client = await request.newContext({ baseURL });
const health = await client.get("/api/health");
if (health.headers()["x-vulnradar-test-fixture"] !== "mock-osv")
  throw new Error("Capture refused: this is not the disposable mock-OSV fixture server");
const headers = { "X-VulnRadar-Client": "web" };
if (!legacy) {
  const login = await client.post("/api/auth/login", { headers, data: { access_key: "v4-test-only-" + "a".repeat(29) + "b" } });
  if (!login.ok()) throw new Error("Disposable authentication failed");
}
const roots = await (await client.get("/api/directories")).json();
const listing = await (await client.get("/api/directories?path=" + encodeURIComponent(roots.directories[0].path))).json();
const folder = listing.directories.find(item => item.name === "sample-app");
if (!folder) throw new Error("Disposable sample-app fixture is missing");
if (/Users[\\/](?!Public[\\/])/i.test(folder.path))
  throw new Error("Capture refused: set TEMP/TMP to a neutral fixture directory");
const projects = await (await client.get("/api/projects")).json();
if (!projects.some(item => item.path === folder.path)) {
  const created = await client.post("/api/projects", { headers, data: { name: "Aplicação de validação (fixture)", path: folder.path } });
  if (!created.ok()) throw new Error("Disposable project creation failed");
}
if (prepare) {
  await client.dispose();
  console.log("Neutral disposable project prepared; no operational data accessed");
  process.exit(0);
}
const routes = [["/", "dashboard"], ["/priorities", "priorities"], ["/feed", "feed"], ["/search", "search"], ["/technologies", "technologies"], ["/exploration", "exploration"], ["/projects", "projects"], ["/sca", "sca"], ["/sast", "sast"], ["/inventory", "inventory"], ["/oci", "oci"], ["/watchlist", "watchlist"], ["/alerts", "alerts"], ["/triage", "triage"], ["/reports", "reports"], ["/sources", "sources"], ["/history", "history"] , ["/settings", "settings"]];
const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ baseURL, storageState: await client.storageState(), timezoneId: "America/Sao_Paulo", locale: "pt-BR", colorScheme: "dark" });
try {
  const page = await context.newPage();
  const output = resolve(process.env.VULNRADAR_SCREENSHOT_DIR || "../docs/screenshots/readme");
  const manifest = [];
  const widths = legacy ? [1920, 1440, 1366, 1024, 768, 390] : [1440, 390];
  for (const width of widths) {
    await page.setViewportSize({ width, height: width < 600 ? 844 : 960 });
    const targets = legacy ? routes : [["/", "overview"], ["/projects", "projects"], ["/triage", "remediation"]];
    await mkdir(resolve(output, String(width)), { recursive: true });
    for (const [route, name] of targets) {
      await page.goto(route);
      await page.locator("main h1").first().waitFor();
      await page.waitForFunction(() => document.querySelectorAll('[role="status"][aria-label="Carregando dados"]').length === 0);
      await page.screenshot({ path: resolve(output, String(width), name + ".png"), fullPage: legacy });
      manifest.push({ route, width, image: `${width}/${name}.png`, viewportCapture: !legacy });
    }
  }
  if (!legacy) {
    await page.setViewportSize({ width: 1440, height: 960 });
    await page.goto("/triage");
    const buttons = page.locator("button[data-row-action]");
    await buttons.first().click();
    await page.getByRole("dialog").waitFor();
    await page.getByRole("tab", { name: "Evidência", exact: true }).click();
    await page.screenshot({ path: resolve(output, "1440/investigation.png") });
    manifest.push({ route: "/triage", state: "finding drawer", width: 1440, image: "1440/investigation.png" });
    await page.keyboard.press("Escape");
    await page.getByRole("button", { name: "Sair", exact: true }).click();
    await page.getByRole("heading", { name: "Entrar no VulnRadar" }).waitFor();
    await page.screenshot({ path: resolve(output, "1440/access.png") });
    manifest.push({ route: "/", state: "login with empty credential field", width: 1440, image: "1440/access.png" });
  }
  await writeFile(resolve(output, "capture-manifest.json"), JSON.stringify({ fixture: "Disposable mock OSV, no operational database", source: legacy ? "79eff96 baseline exported for capture" : "main security review", captures: manifest }, null, 2) + "\n");
  console.log(`Captured ${manifest.length} images from a neutral disposable workspace`);
} finally {
  await browser.close();
  await client.dispose();
}
