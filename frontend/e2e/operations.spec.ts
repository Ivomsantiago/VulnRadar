import { test, expect } from "@playwright/test";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
test.use({ timezoneId: "America/Sao_Paulo" });
test("repository wizard, SCA and local Semgrep, evidence, remediation and exports", async ({
  page,
}) => {
  test.setTimeout(120000);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/projects");
  const existing = (
    (await (await page.request.get("/api/projects")).json()) as {
      id: number;
      name: string;
      path: string;
    }[]
  ).find((p) => p.path.endsWith("/sample-app"));
  if (existing) {
    await page
      .locator(".project-card")
      .filter({
        has: page.getByRole("heading", { name: existing.name, exact: true }),
      })
      .getByRole("button", { name: "Preparar análise" })
      .click();
  } else {
    await page
      .getByRole("button", { name: "Cadastrar repositório", exact: true })
      .click();
    await page
      .getByLabel("Nome do projeto")
      .fill("V2 validation project " + Date.now());
    await page
      .getByRole("button", { name: "Selecionar pasta", exact: true })
      .click();
    await page.getByRole("button", { name: /repositories/ }).click();
    await page.getByRole("button", { name: "sample-app", exact: true }).click();
    await page.getByRole("button", { name: "Selecionar esta pasta" }).click();
    await page.getByRole("button", { name: "Validar e continuar" }).click();
  }
  await expect(page.getByText("Linguagens: Python")).toBeVisible();
  await page.getByRole("radio", { name: /Análise combinada/ }).check();
  await page.getByRole("button", { name: "Verificar pré-requisitos" }).click();
  await expect(
    page.getByText("Caminho autorizado", { exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Executar análise", exact: true })
    .click();
  await expect(page.getByRole("dialog", { name: /Análise #/ })).toBeVisible();
  await expect(
    page.getByRole("dialog").getByText("Concluído", { exact: true }),
  ).toBeVisible({ timeout: 90000 });
  await page.getByRole("tab", { name: /SCA/ }).click();
  await expect(
    page
      .getByRole("dialog")
      .getByRole("cell")
      .filter({ hasText: /^lodash/ })
      .first(),
  ).toBeVisible();
  await page.getByRole("tab", { name: /SAST/ }).click();
  await expect(
    page
      .getByRole("dialog")
      .getByRole("button", { name: /python-subprocess-shell/ }),
  ).toBeVisible();
  await page.screenshot({
    path: "../docs/screenshots/v3/1440/scan-results.png",
    fullPage: true,
  });
  await page
    .getByRole("dialog")
    .getByRole("button", { name: /python-subprocess-shell/ })
    .click();
  const finding = page.getByRole("dialog", { name: /Investigar achado/ });
  await expect(finding.getByText(/unsafe\.py/).first()).toBeVisible();
  await finding.getByRole("tab", { name: "Evidência", exact: true }).click();
  await expect(
    finding.getByText("Evidência preservada da ferramenta"),
  ).toBeVisible();
  await page.screenshot({
    path: "../docs/screenshots/v3/1440/finding-evidence.png",
    fullPage: true,
  });
  await finding.getByRole("tab", { name: "Resumo", exact: true }).click();
  await finding.getByLabel("Estado da remediação").selectOption("planned");
  await finding
    .getByLabel("Justificativa")
    .fill("Validation: correção de fixture planejada");
  await finding.getByRole("button", { name: "Registrar decisão" }).click();
  await expect(finding.getByRole("status")).toHaveText("Triagem registrada.");
  await page.keyboard.press("Escape");
  await page.getByRole("tab", { name: "Resumo", exact: true }).click();
  const sarif = page.getByRole("link", { name: "SARIF", exact: true });
  const response = await page.request.get((await sarif.getAttribute("href"))!, {
    maxRetries: 1,
  });
  expect(response.status()).toBe(200);
  expect((await response.json()).runs[0].results.length).toBeGreaterThan(0);
  await page.keyboard.press("Escape");
  await page.goto("/");
  await expect(page.getByText("Evidências dos scans").first()).toBeVisible();
  await page.goto("/inventory");
  await expect(
    page.getByRole("link", { name: "lodash", exact: true }),
  ).toBeVisible();
});

test("remediation ownership and false-positive decision persist; reports filter and print", async ({
  page,
}) => {
  await page.goto("/priorities");
  const response = await page.request.get("/api/findings?status=");
  const data = await response.json();
  expect(data.items.length).toBeGreaterThan(0);
  const finding = data.items[0];
  await page.goto(
    "/priorities?project_id=" +
      finding.project_id +
      "&status=" +
      finding.status,
  );
  await page
    .getByRole("button", {
      name: finding.vulnerability_id || finding.rule_id,
      exact: true,
    })
    .first()
    .click();
  const dialog = page.getByRole("dialog", { name: /Investigar achado/ });
  await dialog
    .getByLabel("Estado da remediação")
    .selectOption("false_positive");
  await dialog
    .getByLabel("Responsável", { exact: true })
    .fill("AppSec validation");
  await dialog
    .getByLabel("Prazo / SLA", { exact: true })
    .fill("2027-01-15T12:30");
  await dialog
    .getByLabel("Plano de correção")
    .fill("False positive documented with fixture evidence");
  await dialog
    .getByLabel("Justificativa", { exact: true })
    .fill("Fixture code is not used by an operational application");
  await dialog.getByRole("button", { name: "Registrar decisão" }).click();
  await expect(dialog.getByRole("status")).toHaveText("Triagem registrada.");
  await page.keyboard.press("Escape");
  const updated = await (
    await page.request.get("/api/findings/" + finding.id)
  ).json();
  expect(updated.status).toBe("false_positive");
  expect(updated.owner).toBe("AppSec validation");
  expect(updated.due_at).toMatch(/^2027-01-15T15:30:00/);
  await page.goto(
    "/priorities?project_id=" + finding.project_id + "&status=false_positive",
  );
  await page
    .getByRole("button", {
      name: finding.vulnerability_id || finding.rule_id,
      exact: true,
    })
    .first()
    .click();
  await expect(
    page.getByRole("dialog").getByLabel("Prazo / SLA", { exact: true }),
  ).toHaveValue("2027-01-15T12:30");
  await page.keyboard.press("Escape");
  await page.goto("/reports");
  await page
    .getByLabel("Remediação", { exact: true })
    .selectOption("false_positive");
  await expect(
    page.getByRole("cell", { name: "AppSec validation" }),
  ).toBeVisible();
  const csv = await page.request.get(
    "/api/reports/findings?format=csv&status=false_positive",
  );
  expect(csv.status()).toBe(200);
  expect(await csv.text()).toContain("AppSec validation");
  await page.emulateMedia({ media: "print" });
  const pdf = await page.pdf({ format: "A4", printBackground: true });
  expect(pdf.length).toBeGreaterThan(1000);
});

test("fix and reanalyse a disposable repository; resolved findings reopen on recurrence", async ({
  page,
}) => {
  test.setTimeout(120000);
  const project = (await (await page.request.get("/api/projects")).json()).find(
    (p: { path: string }) => p.path.endsWith("/sample-app"),
  );
  expect(project.path).toMatch(/vulnradar-.*browser-/);
  const source = join(project.path, "unsafe.py");
  const manifest = join(project.path, "package-lock.json");
  const originalSource = await readFile(source, "utf8");
  const originalManifest = await readFile(manifest, "utf8");
  const headers = { "X-VulnRadar-Client": "web" };
  const findings = await (
    await page.request.get(`/api/findings?project_id=${project.id}&status=`)
  ).json();
  for (const finding of findings.items) {
    await page.request.patch(`/api/findings/${finding.id}/triage`, {
      headers,
      data: {
        status: "planned",
        reason: "Disposable fixture: validate repair and recurrence",
      },
    });
  }
  const reanalyse = async () => {
    const response = await page.request.post(
      `/api/projects/${project.id}/scans/combined`,
      { headers },
    );
    expect(response.status()).toBe(202);
    const scan = await response.json();
    await page.goto(`/projects?scan=${scan.id}`);
    const dialog = page.getByRole("dialog", { name: /Análise #/ });
    await expect(dialog.getByText("Concluído", { exact: true })).toBeVisible({
      timeout: 90000,
    });
    await dialog.getByRole("tab", { name: "Comparação", exact: true }).click();
    await expect(dialog.getByText("Reabertos", { exact: true })).toBeVisible();
    return await (await page.request.get(`/api/scans/${scan.id}`)).json();
  };
  try {
    await writeFile(
      source,
      'import subprocess\nsubprocess.run(["fixture-never-executed"], shell=False)\n',
    );
    const lock = JSON.parse(originalManifest);
    lock.packages["node_modules/lodash"].version = "99.0.0";
    await writeFile(manifest, JSON.stringify(lock));
    const repaired = await reanalyse();
    expect(repaired.result.comparison.resolved).toBe(2);
    await writeFile(source, originalSource);
    await writeFile(manifest, originalManifest);
    const recurrent = await reanalyse();
    expect(recurrent.result.comparison.reopened).toBe(2);
    expect(recurrent.result.comparison.new).toBe(0);
  } finally {
    await writeFile(source, originalSource);
    await writeFile(manifest, originalManifest);
  }
});
