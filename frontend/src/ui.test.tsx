// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent, cleanup } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { useState } from "react";
import { Kpi, Pagination, Tabs } from "./ui";
import { Badge } from "./shared";
import { Table } from "./base";
afterEach(cleanup);
it("navigates dense evidence rows by keyboard without losing context", () => {
  const open = vi.fn();
  render(<Table label="Evidence"><tbody><tr><td><button data-row-action onClick={() => open(1)}>CVE one</button></td></tr><tr><td><button data-row-action onClick={() => open(2)}>CVE two</button></td></tr></tbody></Table>);
  const table = screen.getByRole("table", { name: "Evidence" });
  table.focus(); fireEvent.keyDown(table, { key: "j" });
  expect(document.activeElement).toBe(screen.getByRole("button", { name: "CVE one" }));
  fireEvent.keyDown(document.activeElement!, { key: "j" });
  expect(document.activeElement).toBe(screen.getByRole("button", { name: "CVE two" }));
  fireEvent.keyDown(document.activeElement!, { key: "Escape" });
  expect(document.activeElement).toBe(table);
  fireEvent.keyDown(table, { key: "Enter" });
  expect(open).toHaveBeenCalledWith(2);
});
describe("operational semantics", () => {
  it("does not substitute a global count when project exposure is unknown", () => {
    render(
      <BrowserRouter>
        <Kpi
          label="Vulnerabilidades relevantes"
          value={null}
          context="Projetos monitorados"
          state="no_projects"
          to="/projects"
        />
      </BrowserRouter>,
    );
    expect(screen.getByText("—")).toBeDefined();
    expect(screen.getByText("Sem projetos")).toBeDefined();
    expect(screen.queryByText("0")).toBeNull();
  });
  it("keeps unknown severity distinct from low severity", () => {
    render(<Badge value="UNKNOWN" />);
    expect(screen.getByText("Não informada")).toBeDefined();
    expect(screen.queryByText("Baixa")).toBeNull();
  });
  it("supports keyboard tab navigation and panel association", () => {
    function Example() {
      const [value, setValue] = useState("summary");
      return (
        <Tabs
          value={value}
          onChange={setValue}
          items={[
            { id: "summary", label: "Resumo", content: <p>Contexto</p> },
            {
              id: "evidence",
              label: "Evidência",
              content: <p>Arquivo e linha</p>,
            },
          ]}
        />
      );
    }
    render(<Example />);
    const summary = screen.getByRole("tab", { name: "Resumo" });
    summary.focus();
    fireEvent.keyDown(summary, { key: "ArrowRight" });
    expect(
      screen
        .getByRole("tab", { name: "Evidência" })
        .getAttribute("aria-selected"),
    ).toBe("true");
    expect(screen.getByRole("tabpanel").textContent).toBe("Arquivo e linha");
    expect(document.activeElement).toBe(
      screen.getByRole("tab", { name: "Evidência" }),
    );
  });
  it("prevents navigation beyond known server-side pages", () => {
    const change = vi.fn();
    render(<Pagination page={1} total={0} size={25} onChange={change} />);
    expect(
      (
        screen.getByRole("button", {
          name: "Página anterior",
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(
      (
        screen.getByRole("button", {
          name: "Próxima página",
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(change).not.toHaveBeenCalled();
  });
});
