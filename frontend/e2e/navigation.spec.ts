import { test, expect } from "@playwright/test";

test("navigation, advanced filters, favorites, watchlist persistence and universal search", async ({
  page,
}) => {
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Visão geral", exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Eventos conectados")).toBeVisible();
  await expect(
    page.getByRole("heading", {
      name: "Exposição das aplicações",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Threat Intelligence global" }),
  ).toBeVisible();
  await page
    .getByRole("link", {
      name: "Inteligência de vulnerabilidades",
      exact: true,
    })
    .click();
  await page
    .getByRole("button", { name: "Filtros avançados", exact: false })
    .click();
  await page.getByLabel("Filtrar severidade").selectOption("CRITICAL");
  await page
    .getByRole("button", { name: "Ver resultados", exact: true })
    .click();
  await expect(page).toHaveURL(/severity=CRITICAL/);
  await page.getByLabel("Pesquisar vulnerabilidades").fill("CVE-");
  await expect(page).toHaveURL(/q=CVE-/);
  await page
    .getByRole("button", { name: "Salvar filtro", exact: true })
    .click();
  await page.getByLabel("Nome do filtro").fill("e2e-critical");
  await page.getByRole("button", { name: "Salvar", exact: true }).click();
  await page.reload();
  await expect(
    page
      .getByLabel("Filtros favoritos")
      .getByRole("option", { name: "e2e-critical" }),
  ).toHaveCount(1);
  await page
    .getByRole("link", { name: "Monitoramento e alertas", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Adicionar pacote", exact: true })
    .click();
  await page
    .getByLabel("Pacote", { exact: true })
    .fill("vulnradar-e2e-fixture");
  await page.getByLabel("Versão opcional").fill("1.0.0");
  await page.getByRole("button", { name: "Salvar", exact: true }).click();
  await expect(
    page.getByText("vulnradar-e2e-fixture", { exact: true }),
  ).toBeVisible();
  await page.reload();
  await expect(
    page.getByText("vulnradar-e2e-fixture", { exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Remover vulnradar-e2e-fixture" })
    .click();
  await expect(
    page.getByText("vulnradar-e2e-fixture", { exact: true }),
  ).toHaveCount(0);
  await page.keyboard.press("Control+k");
  await expect(
    page.getByRole("dialog", { name: "Busca universal" }),
  ).toBeVisible();
  await page.getByLabel("Pesquisar no VulnRadar").fill("not-a-known-component");
  await expect(
    page.getByRole("heading", { name: "Nenhum resultado na base coletada" }),
  ).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  const response = await page.request.get("/api/export?format=json");
  expect(response.status()).toBe(200);
  expect(Array.isArray(await response.json())).toBeTruthy();
});

test("advisory details, missing fixes, tabs and triage using isolated browser mocks", async ({
  page,
}) => {
  const item = {
    id: "CVE-2099-FIXTURE",
    title: "Fixture de teste isolada",
    description: "Dados simulados apenas neste teste.",
    severity: "HIGH",
    cvss: 8.0,
    epss: 0.01,
    kev: false,
    published: "2099-01-01",
    triage: "new",
  };
  await page.route("**/api/vulnerabilities**", async (route) => {
    const url = new URL(route.request().url());
    if (route.request().method() === "PATCH") {
      await route.fulfill({ json: { ...item, triage: "investigating" } });
      return;
    }
    if (url.pathname === "/api/vulnerabilities") {
      await route.fulfill({
        json: { items: [item], total: 1, page: 1, page_size: 25 },
      });
      return;
    }
    await route.fulfill({
      json: {
        vulnerability: item,
        priority: {
          classification: "Monitoramento",
          reasons: ["Fixture de teste"],
        },
        aliases: [item.id],
        advisories: [],
        history: [],
        related_projects: [],
        evidence: [
          {
            source: "osv",
            packages: [
              {
                ecosystem: "npm",
                package: "fixture-only",
                ranges: [],
                fixed: [],
              },
            ],
            references: [{ url: "https://osv.dev" }],
          },
        ],
      },
    });
  });
  await page.goto("/feed");
  await page.getByRole("button", { name: item.id, exact: true }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.getByRole("tab", { name: "Componentes afetados" }).click();
  await expect(page.getByText("fixture-only", { exact: true })).toBeVisible();
  await expect(
    page.getByText("Versões corrigidas: Não informadas pela fonte"),
  ).toBeVisible();
  await page.getByRole("tab", { name: "Resumo", exact: true }).click();
  await page.getByLabel("Justificativa").fill("Justificativa somente de teste");
  await page.getByRole("button", { name: "Salvar triagem" }).click();
  await expect(page.getByRole("status")).toHaveText("Triagem registrada.");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
});
