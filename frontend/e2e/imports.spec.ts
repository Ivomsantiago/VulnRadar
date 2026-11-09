import { test, expect } from "@playwright/test";

test("imports SARIF as partial evidence and keeps investigation available", async ({
  page,
}) => {
  const directories = await (await page.request.get("/api/directories")).json();
  const folder = await (
    await page.request.get(
      "/api/directories?path=" +
        encodeURIComponent(directories.directories[0].path),
    )
  ).json();
  const path = folder.directories.find(
    (item: { name: string }) => item.name === "sample-app",
  ).path;
  const projects = await (await page.request.get("/api/projects")).json();
  let project = projects.find((item: { path: string }) => item.path === path);
  if (!project)
    project = await (
      await page.request.post("/api/projects", {
        headers: { "X-VulnRadar-Client": "web" },
        data: { name: "SARIF test project", path },
      })
    ).json();
  await page.goto("/projects");
  await page
    .getByText("Importar análise SARIF externa", { exact: true })
    .click();
  await page
    .getByLabel("Projeto da análise externa")
    .selectOption(String(project.id));
  const document = {
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "Datadog test fixture" } },
        results: [
          {
            ruleId: "test-rule",
            level: "error",
            message: { text: "Fictional SARIF test result" },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "api/server.py" },
                  region: { startLine: 5 },
                },
              },
            ],
          },
        ],
      },
    ],
  };
  await page
    .getByLabel("Arquivo SARIF")
    .setInputFiles({
      name: "fixture.sarif",
      mimeType: "application/json",
      buffer: Buffer.from(JSON.stringify(document)),
    });
  await page
    .getByRole("button", { name: "Importar SARIF", exact: true })
    .click();
  const dialog = page.getByRole("dialog", { name: /Análise #/ });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText(/SARIF importado/)).toBeVisible();
  await dialog.getByRole("tab", { name: /^SAST/ }).click();
  await expect(
    dialog
      .getByRole("button", { name: /sarif:Datadog_test_fixture:test-rule/ })
      .first(),
  ).toBeVisible();
});
