import { test, expect } from "@playwright/test";
test("collect 24h and one month, prioritize critical/high and keep investigation queue", async ({
  page,
}) => {
  test.setTimeout(90000);
  await page.goto("/");
  await expect(
    page.getByRole("heading", {
      name: "Radar de vulnerabilidades",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Últimas 24h", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByLabel("Severidade no radar")).toHaveValue("urgent");
  await page
    .getByRole("button", { name: "Buscar vulnerabilidades", exact: true })
    .click();
  await expect(
    page.getByText("Período consultado nas fontes", { exact: true }),
  ).toBeVisible({ timeout: 30000 });
  await expect(
    page.getByRole("button", { name: "CVE-2099-PRODUCT-FIXTURE", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "CVE-2099-RADAR-MONTH", exact: true }),
  ).toHaveCount(0);
  const day = await (await page.request.get("/api/radar?period=24h")).json();
  expect(day.items.map((item: { id: string }) => item.id)).not.toContain(
    "CVE-2099-RADAR-MONTH",
  );
  await page.getByRole("button", { name: "1 mês", exact: true }).click();
  await expect(page).toHaveURL(/period=30d/);
  await page
    .getByRole("button", { name: "Buscar vulnerabilidades", exact: true })
    .click();
  await expect
    .poll(
      async () =>
        (await (await page.request.get("/api/radar/collections")).json())[0]
          .status,
      { timeout: 30000 },
    )
    .toBe("success");
  await expect(
    page.getByRole("button", { name: "CVE-2099-RADAR-MONTH", exact: true }),
  ).toBeVisible();
  const monthly = await (
    await page.request.get("/api/radar?period=30d")
  ).json();
  expect(monthly.items[0].severity).toBe("CRITICAL");
  expect(
    monthly.items.find(
      (item: { id: string }) => item.id === "CVE-2099-RADAR-MONTH",
    ).severity,
  ).toBe("HIGH");
  await page
    .getByRole("checkbox", {
      name: "Selecionar CVE-2099-RADAR-MONTH",
      exact: true,
    })
    .check();
  await page
    .getByRole("button", { name: "Adicionar à investigação", exact: true })
    .click();
  await expect(
    page.getByText(/adicionada à fila de investigação/),
  ).toBeVisible();
  await page.getByLabel("Estado no radar").selectOption("queued");
  await expect(
    page.getByRole("button", { name: "CVE-2099-RADAR-MONTH", exact: true }),
  ).toBeVisible();
  await page.reload();
  await expect(
    page.getByRole("button", { name: "CVE-2099-RADAR-MONTH", exact: true }),
  ).toBeVisible();
  const href = await page
    .getByRole("link", { name: "CSV", exact: true })
    .getAttribute("href");
  const csv = await page.request.get(href!);
  expect(csv.status()).toBe(200);
  expect(await csv.text()).toContain("CVE-2099-RADAR-MONTH");
  expect(await csv.text()).not.toContain("CVE-2099-PRODUCT-FIXTURE");
  await page.getByLabel("Estado no radar").selectOption("all");
  await page.getByRole("button", { name: "Últimas 24h", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "CVE-2099-RADAR-MONTH", exact: true }),
  ).toHaveCount(0);
  await page.getByLabel("Considerar data de").selectOption("modified");
  await expect(
    page.getByRole("button", { name: "CVE-2099-RADAR-MONTH", exact: true }),
  ).toBeVisible();
  await page.screenshot({
    path: "../docs/screenshots/radar/1440/investigation-workflow.png",
    fullPage: true,
  });
});
