import { test, expect } from "@playwright/test";
test.use({ storageState: { cookies: [], origins: [] } });

test("personal key login, workspace access and logout revocation", async ({
  page,
}) => {
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Entrar no VulnRadar" }),
  ).toBeVisible();
  expect((await page.request.get("/api/projects")).status()).toBe(401);
  await page
    .getByLabel("Chave pessoal")
    .fill("v4-test-only-" + "a".repeat(29) + "b");
  await page.getByRole("button", { name: "Entrar", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Visão geral", exact: true }),
  ).toBeVisible();
  expect((await page.request.get("/api/projects")).status()).toBe(200);
  expect(
    await page.evaluate(() =>
      Object.keys(localStorage).filter((key) =>
        /token|session|access-key/.test(key),
      ),
    ),
  ).toEqual([]);
  await page.evaluate(() =>
    localStorage.setItem(
      "vr-private-test-preference",
      "test-only-private-filter",
    ),
  );
  await page.getByRole("button", { name: "Sair", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Entrar no VulnRadar" }),
  ).toBeVisible();
  expect((await page.request.get("/api/projects")).status()).toBe(401);
  expect(
    await page.evaluate(() =>
      localStorage.getItem("vr-private-test-preference"),
    ),
  ).toBeNull();
});
