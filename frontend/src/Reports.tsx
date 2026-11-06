import { useState } from "react";
import { Link } from "react-router-dom";
import { Download, Printer } from "lucide-react";
import { type Project } from "./api";
import { Header, Empty, ErrorBox, Badge, useData } from "./shared";
import { Skeleton } from "./ui";
type Report = {
  total: number;
  exported: number;
  truncated: boolean;
  scope: string;
  coverage: Record<string, number>;
  items: {
    id: number;
    project: string;
    project_id: number;
    kind: string;
    component: string | null;
    vulnerability: string | null;
    rule: string | null;
    severity: string;
    status: string;
    owner: string | null;
    overdue: boolean;
    due_at: string | null;
  }[];
};
export function Reports() {
  const [filters, setFilters] = useState<Record<string, string>>({});
  const query = new URLSearchParams(
    Object.entries(filters)
      .filter(([, v]) => v)
      .map(([key, value]) => [
        key,
        key === "since" || key === "until"
          ? new Date(value).toISOString()
          : value,
      ]),
  );
  const projects = useData<Project[]>("projects", "/projects");
  const report = useData<Report>("report", "/reports/findings?" + query);
  return (
    <>
      <Header
        eyebrow="GESTÃO / RELATÓRIOS"
        title="Relatórios de exposição"
        description="Achados, responsabilidades e cobertura usando um único conjunto filtrado."
        action={
          <button onClick={() => window.print()}>
            <Printer size={15} />
            Imprimir / Salvar PDF
          </button>
        }
      />
      <section className="panel padded report-filters">
        <div className="form-grid">
          {[
            ["project_id", "Repositório"],
            ["severity", "Severidade"],
            ["status", "Remediação"],
            ["kind", "Tipo de análise"],
            ["technology", "Tecnologia"],
            ["since", "Primeira observação desde"],
            ["until", "Primeira observação até"],
          ].map(([key, label]) => (
            <label key={key}>
              {label}
              {["project_id", "severity", "status", "kind"].includes(key) ? (
                <select
                  aria-label={label}
                  value={filters[key] || ""}
                  onChange={(e) =>
                    setFilters({ ...filters, [key]: e.target.value })
                  }
                >
                  <option value="">Todos</option>
                  {(key === "project_id"
                    ? (projects.data || []).map((p) => [String(p.id), p.name])
                    : (key === "severity"
                        ? ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
                        : key === "kind"
                          ? ["sca", "sast"]
                          : [
                              "new",
                              "pending",
                              "investigating",
                              "applicable",
                              "not_applicable",
                              "planned",
                              "remediating",
                              "mitigated",
                              "resolved",
                              "false_positive",
                              "accepted",
                            ]
                      ).map((s) => [s, s])
                  ).map(([value, text]) => (
                    <option key={value} value={value}>
                      {text}
                    </option>
                  ))}
                </select>
              ) : (
                <input
                  aria-label={label}
                  type={
                    key === "since" || key === "until"
                      ? "datetime-local"
                      : "text"
                  }
                  value={filters[key] || ""}
                  onChange={(e) =>
                    setFilters({ ...filters, [key]: e.target.value })
                  }
                />
              )}
            </label>
          ))}
        </div>
      </section>
      <ErrorBox error={report.error} />
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>{report.data?.total ?? "—"} achados no conjunto</h2>
            <p>
              Prazo vencido é calculado sobre achados ainda abertos; estado de
              remediação atual.
            </p>
          </div>
          <div className="button-row">
            <a
              className="button"
              href={"/api/reports/findings?" + query + "&format=csv"}
              download
            >
              <Download size={14} />
              CSV
            </a>
            <a
              className="button"
              href={"/api/reports/findings?" + query}
              download="vulnradar-report.json"
            >
              JSON
            </a>
          </div>
        </div>
        {report.isPending ? (
          <Skeleton />
        ) : report.data?.items.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Projeto / achado</th>
                  <th>Componente</th>
                  <th>Severidade</th>
                  <th>Estado</th>
                  <th>Responsável</th>
                  <th>SLA</th>
                </tr>
              </thead>
              <tbody>
                {report.data.items.map((f) => (
                  <tr key={f.id}>
                    <td>
                      <Link to={"/priorities?project_id=" + f.project_id}>
                        {f.project}
                      </Link>
                      <small className="table-sub">
                        {f.vulnerability || f.rule}
                      </small>
                    </td>
                    <td>{f.component || "SAST"}</td>
                    <td>
                      <Badge value={f.severity} />
                    </td>
                    <td>
                      <Badge value={f.status} />
                    </td>
                    <td>{f.owner || "Não atribuído"}</td>
                    <td>
                      {f.overdue
                        ? "Vencido"
                        : f.due_at
                          ? "No prazo"
                          : "Sem prazo"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="Nenhum achado neste conjunto" />
        )}
        <div className="panel-note">
          {report.data?.scope}
          {report.data?.truncated &&
            " Exportação limitada a 5000 achados; refine os filtros."}
        </div>
      </section>
      <section className="panel padded">
        <h2>Cobertura das análises no período</h2>
        <div className="button-row">
          {Object.entries(report.data?.coverage || {}).map(([state, count]) => (
            <span key={state}>
              <Badge value={state} /> {count} execuções
            </span>
          ))}
        </div>
        <p className="field-hint">
          SARIF e CycloneDX continuam disponíveis por execução em Repositórios →
          Investigar. Cobertura parcial não representa resultado limpo.
        </p>
      </section>
    </>
  );
}
