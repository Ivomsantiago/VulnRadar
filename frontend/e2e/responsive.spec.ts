import { test, expect } from "@playwright/test";
const routes = [
  ["/", "radar"],
  ["/exposure", "application-exposure"],
  ["/priorities", "priorities"],
  ["/feed", "feed"],
  ["/search", "search"],
  ["/technologies", "technologies"],
  ["/exploration", "exploration"],
  ["/projects", "projects"],
  ["/sca", "sca"],
  ["/sast", "sast"],
  ["/inventory", "inventory"],
  ["/oci", "oci"],
  ["/watchlist", "watchlist"],
  ["/alerts", "alerts"],
  ["/triage", "triage"],
  ["/reports", "reports"],
  ["/sources", "sources"],
  ["/history", "history"],
  ["/settings", "settings"],
];
for (const width of [1920, 1440, 1366, 1024, 768, 390])
  test(`all routes at ${width}px: layout, navigation and screenshots`, async ({
    page,
  }) => {
    test.setTimeout(180000);
    await page.setViewportSize({ width, height: width < 600 ? 844 : 1000 });
    const failures: string[] = [];
    page.on("response", (response) => {
      if (
        new URL(response.url()).pathname.startsWith("/api/") &&
        response.status() >= 400
      )
        failures.push(
          `${response.status()} ${new URL(response.url()).pathname}`,
        );
    });
    for (const [path, name] of routes) {
      await page.goto(path);
      await expect(page.locator("main h1").first()).toBeVisible();
      await expect(
        page.getByRole("status", { name: "Carregando dados" }),
      ).toHaveCount(0, { timeout: 15000 });
      const metrics = await page.evaluate(() => ({
        viewport: innerWidth,
        document: document.documentElement.scrollWidth,
      }));
      expect(
        metrics.document,
        `${path} overflow at ${width}`,
      ).toBeLessThanOrEqual(metrics.viewport + 1);
      expect(failures, `API failures at ${path}`).toEqual([]);
      await page.screenshot({
        path: `../docs/screenshots/radar/${width}/${name}.png`,
        fullPage: true,
      });
    }
    if (width < 900) {
      await page.getByRole("button", { name: "Alternar navegação" }).click();
      await expect(
        page.getByRole("navigation", { name: "Navegação principal" }),
      ).toBeVisible();
      await page
        .getByRole("link", { name: "Visão geral", exact: true })
        .click();
      await expect(page.locator(".nav-backdrop")).toHaveCount(0);
    }
    await page.goto("/feed");
    await page.getByRole("button", { name: /Filtros avançados/ }).click();
    const box = await page.getByRole("dialog").boundingBox();
    expect(box?.x).toBeGreaterThanOrEqual(0);
    expect(box!.width).toBeLessThanOrEqual(width);
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).toHaveCount(0);
  });
