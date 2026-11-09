import { test, expect } from "@playwright/test";

test("VEX requires exact version and explicit reviewed remediation", async ({
  page,
}) => {
  const projects = await (await page.request.get("/api/projects")).json();
  const project = projects.find((item: { path: string }) =>
    item.path.replaceAll("\\", "/").endsWith("/sample-app"),
  );
  expect(project).toBeDefined();
  const rows = await (
    await page.request.get(
      `/api/findings?project_id=${project.id}&kind=sca&status=`,
    )
  ).json();
  const finding = rows.items.find(
    (item: { package: string }) => item.package === "lodash",
  );
  expect(finding).toBeDefined();
  await page.goto(`/priorities?project_id=${project.id}&q=lodash&status=`);
  await page
    .locator(".findings-table")
    .getByRole("button", { name: finding.vulnerability_id, exact: true })
    .first()
    .click();
  const dialog = page.getByRole("dialog", {
    name: `Investigar achado #${finding.id}`,
  });
  await dialog
    .getByText("Declaração VEX de não afetação", { exact: true })
    .click();
  const document = {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": "urn:test:e2e-vex",
    author: "Fixture reviewer",
    version: 1,
    timestamp: new Date(Date.now() - 60000).toISOString(),
    statements: [
      {
        vulnerability: { name: finding.vulnerability_id },
        products: [{ "@id": `pkg:npm/lodash@${finding.version}` }],
        status: "not_affected",
        justification: "vulnerable_code_not_in_execute_path",
        impact_statement:
          "Fictional reviewed statement for isolated tests only",
      },
    ],
  };
  await dialog
    .getByLabel("Arquivo VEX")
    .setInputFiles({
      name: "fixture.vex.json",
      mimeType: "application/json",
      buffer: Buffer.from(JSON.stringify(document)),
    });
  await dialog
    .getByLabel("Aplicar “não aplicável” à triagem desta versão")
    .check();
  await dialog
    .getByLabel("Justificativa da decisão", { exact: true })
    .fill("Reviewed fixture assertion; not a production conclusion");
  await dialog
    .getByRole("button", { name: "Registrar VEX", exact: true })
    .click();
  await expect(
    dialog.getByText(
      "Declaração registrada. A identidade do revisor foi incluída na auditoria.",
    ),
  ).toBeVisible();
  const exported = await page.request.get(
    `/api/findings/${finding.id}/vex?format=openvex`,
  );
  expect(exported.status()).toBe(200);
  expect((await exported.json()).statements[0].status).toBe("not_affected");
});
