import { useState } from "react";
import { Link } from "react-router-dom";
import { Download, Printer } from "lucide-react";
import { type Project } from "./api";
import { Header, Empty, ErrorBox, Badge, useData } from "./shared";
import { Pagination, Skeleton } from "./ui";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";
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
  const [page, setPage] = useState(1);
  const setFilter = (key: string, value: string) => {
    setFilters({ ...filters, [key]: value });
    setPage(1);
  };
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
            ["change", "Mudança observada"],
            ["technology", "Tecnologia"],
            ["since", "Período desde"],
            ["until", "Período até"],
          ].map(([key, label]) => (
            <label key={key}>
              {label}
              {["project_id", "severity", "status", "kind", "change"].includes(
                key,
              ) ? (
                <select
                  aria-label={label}
                  value={filters[key] || ""}
                  onChange={(e) => setFilter(key, e.target.value)}
                >
                  <option value="">Todos</option>
                  {(key === "project_id"
                    ? (projects.data || []).map((p) => [String(p.id), p.name])
                    : (key === "severity"
                        ? ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
                        : key === "kind"
                          ? ["sca", "sast", "oci"]
                          : key === "change"
                            ? ["new", "resolved", "reopened"]
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
                  onChange={(e) => setFilter(key, e.target.value)}
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
              href={"/api/reports/findings?" + query + "&format=pdf"}
              download
            >
              PDF
            </a>
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
                {report.data.items
                  .slice((page - 1) * 25, page * 25)
                  .map((f) => (
                    <tr key={f.id}>
                      <td>
                        <Link
                          to={
                            "/priorities?project_id=" +
                            f.project_id +
                            "&finding=" +
                            f.id +
                            "&status=" +
                            f.status
                          }
                        >
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
        <Pagination
          page={page}
          total={report.data?.exported || 0}
          size={25}
          onChange={setPage}
        />
      </section>
      <ExposureHistory filters={filters} />
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

function ExposureHistory({ filters }: { filters: Record<string, string> }) {
  const [days, setDays] = useState("30");
  const query = new URLSearchParams(
    Object.entries(filters).filter(
      ([key, value]) =>
        value &&
        ["project_id", "severity", "status", "kind", "technology"].includes(
          key,
        ),
    ),
  );
  query.set("days", days);
  type Point = {
    date: string;
    open: number | null;
    closed: number | null;
    new: number;
    resolved: number;
    reopened: number;
    overdue: number | null;
  };
  const data = useData<{
    items: Point[];
    recorded_from: string | null;
    scope: string;
    truncated: boolean;
  }>("exposure-history", "/reports/exposure?" + query);
  return (
    <section className="panel padded">
      <div className="panel-heading">
        <div>
          <h2>Evolução da exposição e remediação</h2>
          <p>
            Estados registrados por dia UTC; os filtros de projeto, severidade,
            estado, mecanismo e tecnologia também se aplicam a este histórico.
          </p>
        </div>
        <select
          aria-label="Período do histórico"
          value={days}
          onChange={(e) => setDays(e.target.value)}
        >
          {[7, 30, 90, 366].map((value) => (
            <option key={value} value={value}>
              {value} dias
            </option>
          ))}
        </select>
      </div>
      <ErrorBox error={data.error} />
      {data.isPending ? (
        <Skeleton />
      ) : (
        <>
          {data.data &&
          data.data.items.filter((p) => p.open !== null).length > 1 ? (
            <div
              className="chart-wrap"
              role="img"
              aria-label="Série temporal de achados abertos e encerrados"
              style={{ height: 250 }}
            >
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={data.data.items}>
                  <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
                  <XAxis
                    dataKey="date"
                    tick={{ fill: "var(--text-secondary)", fontSize: 11 }}
                    minTickGap={40}
                  />
                  <YAxis
                    allowDecimals={false}
                    tick={{ fill: "var(--text-secondary)", fontSize: 11 }}
                  />
                  <Tooltip />
                  <Line
                    name="Abertos"
                    dataKey="open"
                    stroke="var(--accent)"
                    dot={false}
                    connectNulls={false}
                  />
                  <Line
                    name="Encerrados"
                    dataKey="closed"
                    stroke="var(--success)"
                    dot={false}
                    connectNulls={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <p className="notice">
              A evolução gráfica aparece após dois dias com estados registrados.
              O primeiro dia e os períodos desconhecidos estão discriminados na
              tabela.
            </p>
          )}
          <div
            className="table-scroll report-history-table"
            tabIndex={0}
            role="region"
            aria-label="Histórico de exposição por dia"
          >
            <table>
              <thead>
                <tr>
                  <th>Data UTC</th>
                  <th>Abertos</th>
                  <th>Encerrados</th>
                  <th>Novos</th>
                  <th>Resoluções</th>
                  <th>Reaberturas</th>
                  <th>SLA vencido</th>
                </tr>
              </thead>
              <tbody>
                {[...(data.data?.items || [])].reverse().map((p) => (
                  <tr key={p.date}>
                    <td>{p.date}</td>
                    <td>{p.open ?? "Desconhecido"}</td>
                    <td>{p.closed ?? "Desconhecido"}</td>
                    <td>{p.new ?? "Desconhecido"}</td>
                    <td>{p.resolved ?? "Desconhecido"}</td>
                    <td>{p.reopened ?? "Desconhecido"}</td>
                    <td>{p.overdue ?? "Desconhecido"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="field-hint">
            {data.data?.scope}
            {data.data?.truncated &&
              " Limite de eventos atingido; exposição marcada como desconhecida."}
          </p>
          <div className="button-row">
            {["json", "csv", "pdf"].map((format) => (
              <a
                className="button"
                key={format}
                href={"/api/reports/exposure?" + query + "&format=" + format}
                download
              >
                {format.toUpperCase()} do histórico
              </a>
            ))}
          </div>
        </>
      )}
    </section>
  );
}
