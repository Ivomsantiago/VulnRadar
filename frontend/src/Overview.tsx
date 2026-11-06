import { NavLink } from "react-router-dom";
import {
  ShieldAlert,
  FolderGit2,
  Eye,
  RefreshCw,
  ChevronRight,
  Activity,
  AlertTriangle,
} from "lucide-react";
import {
  AreaChart,
  Area,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { type Source, type Dashboard } from "./api";
import {
  formatDate,
  severityLabel,
  useData,
  Empty,
  ErrorBox,
  Badge,
  Header,
} from "./shared";

export function Overview() {
  const { data, isPending, error } = useData<Dashboard>(
    "dashboard",
    "/dashboard",
  );
  const sources = useData<Source[]>("sources", "/sources");
  return (
    <>
      <Header
        eyebrow="SECURITY INTELLIGENCE"
        title="Visão geral"
        description="Sua superfície de software, sob uma perspectiva de segurança."
        action={
          <NavLink className="button secondary" to="/sources">
            <RefreshCw size={15} />
            Atualizar fontes
          </NavLink>
        }
      />
      <ErrorBox error={error} />
      <div className="notice">
        <span className="live-dot" />
        Base operacional <span>·</span>{" "}
        {data?.coverage || "Aguardando informações do backend"}
      </div>
      <div className="metrics">
        {[
          {
            label: "Vulnerabilidades",
            value: data?.total,
            to: "/feed",
            icon: ShieldAlert,
          },
          {
            label: "Críticas",
            value: data?.severities.CRITICAL || 0,
            to: "/feed?severity=CRITICAL",
            icon: AlertTriangle,
          },
          {
            label: "Altas",
            value: data?.severities.HIGH || 0,
            to: "/feed?severity=HIGH",
            icon: ShieldAlert,
          },
          {
            label: "Exploração conhecida",
            value: data?.kev,
            to: "/exploration",
            icon: Activity,
          },
        ].map((m, i) => (
          <NavLink className={`metric m${i}`} to={m.to} key={m.label}>
            <div>
              {m.label}
              <m.icon size={18} />
            </div>
            <strong>{isPending ? "—" : (m.value ?? 0)}</strong>
            <small>
              {i === 3 ? "Catálogo CISA KEV" : "Registros na base coletada"}
              <ChevronRight size={14} />
            </small>
          </NavLink>
        ))}
      </div>
      <div className="chart-grid">
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Publicações recentes</h2>
              <p>Volume coletado por data de publicação</p>
            </div>
            <span className="chip">Últimos 30 dias</span>
          </div>
          {data?.trend.length ? (
            <div className="chart">
              <ResponsiveContainer width="100%" height={245}>
                <AreaChart data={data.trend}>
                  <CartesianGrid stroke="#202c3b" vertical={false} />
                  <XAxis
                    dataKey="date"
                    tick={{ fill: "#8797ad", fontSize: 11 }}
                  />
                  <YAxis
                    tick={{ fill: "#8797ad", fontSize: 11 }}
                    allowDecimals={false}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "#131d2b",
                      border: "1px solid #2a384a",
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="count"
                    name="Publicações"
                    stroke="#40b9d4"
                    fill="#173342"
                    strokeWidth={2}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <Empty title="Seu radar está pronto para coletar">
              Sincronize uma fonte para acompanhar publicações reais. Nenhum
              dado demonstrativo é utilizado.
            </Empty>
          )}
        </section>
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Distribuição por severidade</h2>
              <p>Classificação informada pelas fontes</p>
            </div>
          </div>
          <div className="severity-list">
            {["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].map((s) => (
              <NavLink to={"/feed?severity=" + s} key={s}>
                <span className={`severity-dot ${s.toLowerCase()}`} />
                <span>{severityLabel[s]}</span>
                <div className="bar">
                  <i
                    style={{
                      width: `${data?.total ? (100 * (data.severities[s] || 0)) / data.total : 0}%`,
                    }}
                  />
                </div>
                <b>{data?.severities[s] || 0}</b>
              </NavLink>
            ))}
          </div>
          <div className="panel-note">
            CVSS mede severidade. EPSS estima probabilidade. KEV registra
            exploração conhecida.
          </div>
        </section>
      </div>
      <div className="chart-grid">
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Fontes de inteligência</h2>
              <p>Saúde e cobertura das integrações</p>
            </div>
            <NavLink to="/sources">
              Gerenciar <ChevronRight size={14} />
            </NavLink>
          </div>
          {sources.data?.map((s) => (
            <div className="source-row" key={s.id}>
              <span className="source-logo">
                {s.id.slice(0, 2).toUpperCase()}
              </span>
              <div>
                <strong>{s.id.toUpperCase()}</strong>
                <small>
                  {s.last_run
                    ? formatDate(s.last_run)
                    : "Ainda não sincronizada"}
                </small>
              </div>
              <Badge value={s.status} />
            </div>
          ))}
        </section>
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Seu espaço de investigação</h2>
              <p>Conecte inteligência ao seu software</p>
            </div>
          </div>
          {[
            {
              label: "Tecnologias na watchlist",
              value: data?.watchlist,
              to: "/watchlist",
              icon: Eye,
            },
            {
              label: "Repositórios cadastrados",
              value: data?.projects,
              to: "/projects",
              icon: FolderGit2,
            },
            {
              label: "Análises registradas",
              value: data?.scans,
              to: "/projects",
              icon: ShieldAlert,
            },
          ].map((x) => (
            <NavLink className="workspace-link" to={x.to} key={x.label}>
              <x.icon size={19} />
              <span>{x.label}</span>
              <b>{x.value || 0}</b>
              <ChevronRight size={15} />
            </NavLink>
          ))}
          <div className="panel-note">
            Comece adicionando um pacote à watchlist ou consultando sua versão
            no OSV.
          </div>
        </section>
      </div>
    </>
  );
}
