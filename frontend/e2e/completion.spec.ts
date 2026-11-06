import { test, expect } from "@playwright/test";

test("eight journeys, CPE product lookup, runtime monitoring and server PDF", async ({
  page,
}) => {
  await page.goto("/");
  await expect(
    page
      .getByRole("navigation", { name: "Navegação principal" })
      .getByRole("link"),
  ).toHaveCount(8);
  await page
    .getByRole("link", {
      name: "Inteligência de vulnerabilidades",
      exact: true,
    })
    .click();
  await page
    .getByRole("link", { name: "Busca de versões", exact: true })
    .click();
  await page
    .getByLabel("Fornecedor CPE", { exact: true })
    .fill("fixture_vendor");
  await page.getByLabel("Produto CPE", { exact: true }).fill("fixture_runtime");
  await page.getByLabel("Versão do produto", { exact: true }).fill("1.5");
  await page
    .getByRole("button", { name: "Consultar produtos", exact: true })
    .click();
  await expect(
    page.getByText("Correspondência de versão", { exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Monitorar esta versão", exact: true })
    .click();
  await expect(page.getByRole("status")).toHaveText(
    "Produto e versão adicionados ao monitoramento NVD.",
  );
  await page
    .getByRole("link", { name: "Monitoramento e alertas", exact: true })
    .click();
  await expect(
    page.getByRole("cell", {
      name: "fixture_vendor / fixture_runtime",
      exact: true,
    }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Verificar produto", exact: true })
    .click();
  await expect(page.getByRole("status")).toContainText("1 correspondências");
  await page.reload();
  await expect(
    page.getByRole("cell", {
      name: "fixture_vendor / fixture_runtime",
      exact: true,
    }),
  ).toBeVisible();
  await page
    .getByRole("button", {
      name: "Remover produto fixture_runtime",
      exact: true,
    })
    .click();
  await expect(
    page.getByRole("cell", {
      name: "fixture_vendor / fixture_runtime",
      exact: true,
    }),
  ).toHaveCount(0);
  await page
    .getByRole("link", { name: "Relatórios", exact: true })
    .first()
    .click();
  await expect(
    page.getByRole("heading", {
      name: "Evolução da exposição e remediação",
      exact: true,
    }),
  ).toBeVisible();
  const pdf = await page.request.get("/api/reports/findings?format=pdf");
  expect(pdf.status()).toBe(200);
  expect(pdf.headers()["content-type"]).toBe("application/pdf");
  expect((await pdf.body()).subarray(0, 8).toString()).toBe("%PDF-1.4");
  await expect(
    page.getByRole("link", { name: "PDF do histórico", exact: true }),
  ).toBeVisible();
  // Existing routes continue to work after sidebar consolidation.
  for (const path of [
    "/sca",
    "/sast",
    "/exploration",
    "/sources",
    "/repositories",
    "/findings",
  ]) {
    await page.goto(path);
    await expect(page.locator("main h1")).toBeVisible();
  }
  await page.goto("/vulnerabilities?severity=HIGH");
  await expect(page).toHaveURL(/\/feed\?severity=HIGH/);
});

test("OCI remains usable when optional scanners are absent", async ({
  page,
}) => {
  await page.route("**/api/engines", (route) =>
    route.fulfill({
      json: {
        osv: "reachable",
        semgrep: true,
        trivy: false,
        grype: false,
        oci_registries: ["docker.io"],
      },
    }),
  );
  await page.goto("/oci");
  await expect(
    page.getByText(/Instale Trivy ou Grype no servidor/),
  ).toBeVisible();
  await page.goto("/projects");
  await expect(
    page.getByRole("heading", { name: "Repositórios e análises", exact: true }),
  ).toBeVisible();
});

test("OCI real: Trivy and Grype scan remote layers and persist evidence", async ({
  page,
}) => {
  test.skip(
    process.env.VULNRADAR_OCI_LIVE_TESTS !== "1",
    "Live OCI opt-in requires installed scanners and network",
  );
  test.setTimeout(360000);
  const roots = await (await page.request.get("/api/directories")).json();
  const root = roots.directories[0]?.path;
  expect(root).toMatch(/vulnradar-.*browser-/);
  const folders = await (
    await page.request.get("/api/directories?path=" + encodeURIComponent(root))
  ).json();
  const path = folders.directories.find(
    (d: { name: string }) => d.name === "sample-app",
  ).path;
  let projects = await (await page.request.get("/api/projects")).json();
  if (!projects.length) {
    const created = await page.request.post("/api/projects", {
      headers: { "X-VulnRadar-Client": "web" },
      data: { name: "Disposable OCI validation", path },
    });
    expect(created.status()).toBe(201);
    projects = [await created.json()];
  }
  for (const engine of ["trivy", "grype"]) {
    await page.goto("/oci");
    await page
      .getByLabel("Projeto", { exact: true })
      .selectOption(String(projects[0].id));
    await page.getByLabel("Mecanismo", { exact: true }).selectOption(engine);
    await page
      .getByLabel("Referência da imagem", { exact: true })
      .fill("alpine:3.22.0");
    await page
      .getByRole("button", { name: "Analisar imagem", exact: true })
      .click();
    const dialog = page.getByRole("dialog", { name: /Análise #/ });
    await expect(dialog.getByText("Concluído", { exact: true })).toBeVisible({
      timeout: 180000,
    });
    await expect(dialog.getByText(/Digest:.*sha256:/)).toBeVisible();
    await dialog.getByRole("tab", { name: /^OCI/ }).click();
    await expect(dialog.locator("tbody tr").first()).toBeVisible();
    await dialog.locator("tbody tr button").first().click();
    const finding = page.getByRole("dialog", { name: /Investigar achado/ });
    await finding.getByRole("tab", { name: "Evidência", exact: true }).click();
    await expect(
      finding.getByRole("heading", { name: engine.toUpperCase(), exact: true }),
    ).toBeVisible();
    await page.screenshot({
      path: `../docs/screenshots/v3/1440/oci-real-${engine}.png`,
      fullPage: true,
    });
    await page.keyboard.press("Escape");
    await page.keyboard.press("Escape");
  }
  const findings = await (
    await page.request.get("/api/findings?kind=oci&status=")
  ).json();
  expect(findings.total).toBeGreaterThan(0);
});
