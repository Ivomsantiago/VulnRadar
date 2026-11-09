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

test("retired OCI preserves investigation routes without scanner controls", async ({
  page,
}) => {
  await page.goto("/oci");
  await expect(
    page.getByRole("heading", { name: "Análises OCI anteriores" }),
  ).toBeVisible();
  await expect(
    page.getByRole("link", { name: "Consultar pacote e versão" }),
  ).toHaveAttribute("href", "/search");
  await expect(
    page.getByRole("button", { name: "Analisar imagem" }),
  ).toHaveCount(0);
  const response = await page.request.post("/api/projects/1/oci", {
    headers: { "X-VulnRadar-Client": "web" },
    data: { image: "alpine:3.22", engine: "trivy" },
  });
  expect(response.status()).toBe(410);
});

test("index quality is visible separately from application exposure", async ({
  page,
}) => {
  const response = await page.request.get("/api/intelligence/quality");
  expect(response.status()).toBe(200);
  const quality = await response.json();
  expect(typeof quality.total).toBe("number");
  expect(Object.keys(quality.missing)).toContain("epss");
  await page.goto("/sources");
  await expect(
    page.getByRole("heading", { name: "Qualidade do índice coletado" }),
  ).toBeVisible();
  await expect(page.getByText("Sem EPSS", { exact: true })).toBeVisible();
  await expect(page.getByText(quality.scope, { exact: true })).toBeVisible();
  await page.goto("/settings");
  await expect(page.getByText("Trivy OCI", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Grype OCI", { exact: true })).toHaveCount(0);
});
