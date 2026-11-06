// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "./api";
afterEach(() => vi.unstubAllGlobals());
describe("API client", () => {
  it("sends explicit mutation header and JSON body", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValue(
        new Response(JSON.stringify({ id: 1 }), { status: 201 }),
      );
    vi.stubGlobal("fetch", fetch);
    expect(await api("/watchlist", "POST", { package: "test" })).toEqual({
      id: 1,
    });
    expect(fetch.mock.calls[0][1].headers["X-VulnRadar-Client"]).toBe("web");
    expect(fetch.mock.calls[0][1].body).toBe('{"package":"test"}');
  });
  it("preserves explicit incomplete-query errors", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response(JSON.stringify({ detail: "Consulta incompleta" }), {
            status: 502,
          }),
        ),
    );
    await expect(api("/search/package", "POST", {})).rejects.toThrow(
      "Consulta incompleta",
    );
  });
  it("handles deletion without attempting JSON parse", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(null, { status: 204 })),
    );
    expect(await api("/watchlist/1", "DELETE")).toBeUndefined();
  });
});
