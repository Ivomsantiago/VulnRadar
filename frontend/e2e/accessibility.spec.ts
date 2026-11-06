import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
const routes = [
  "/",
  "/feed",
  "/search",
  "/technologies",
  "/projects",
  "/priorities",
  "/inventory",
  "/oci",
  "/reports",
  "/watchlist",
  "/alerts",
  "/history",
  "/settings",
];
test("WCAG automated checks across operational pages and native drawers", async ({
  page,
}) => {
  test.setTimeout(180000);
  await page.setViewportSize({ width: 1440, height: 1000 });
  for (const path of routes) {
    await page.goto(path);
    await expect(page.locator("main h1").first()).toBeVisible();
    await expect(
      page.getByRole("status", { name: "Carregando dados" }),
    ).toHaveCount(0);
    const report = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
      .analyze();
    expect(
      report.violations.map((v) => ({
        id: v.id,
        description: v.description,
        nodes: v.nodes.map((n) => n.target),
      })),
      path,
    ).toEqual([]);
  }
  await page.goto("/feed");
  await page.getByRole("button", { name: /Filtros avançados/ }).click();
  let report = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(report.violations).toEqual([]);
  await page.keyboard.press("Escape");
  await page.setViewportSize({ width: 390, height: 844 });
  await page.keyboard.press("Control+k");
  await expect(
    page.getByRole("dialog", { name: "Busca universal" }),
  ).toBeVisible();
  report = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(report.violations).toEqual([]);
  await page.keyboard.press("Escape");
  await page.goto("/settings");
  await page.getByLabel("Tema visual").selectOption("light");
  await page
    .getByRole("button", { name: "Salvar preferências", exact: true })
    .click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  report = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(report.violations).toEqual([]);
  for (const path of ["/search", "/watchlist", "/oci", "/reports"]) {
    await page.goto(path);
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    const lightReport = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
      .analyze();
    expect(lightReport.violations, path + " light theme").toEqual([]);
  }
  await page.goto("/settings");
  await page.getByLabel("Tema visual").selectOption("dark");
  await page
    .getByRole("button", { name: "Salvar preferências", exact: true })
    .click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
});
