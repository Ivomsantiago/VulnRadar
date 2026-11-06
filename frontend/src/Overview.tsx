import { useState } from "react";
import { Link } from "react-router-dom";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  Activity,
  ArrowRight,
  Globe2,
  ShieldCheck,
  FolderGit2,
  RefreshCw,
  ArrowUpRight,
} from "lucide-react";
import {
  type Activity as Event,
  type Dashboard,
  type Exposure,
  type Finding,
  type Page,
  type Source,
} from "./api";
import { Header, Empty, ErrorBox, useData, formatDate, Badge } from "./shared";
import { Kpi, Skeleton } from "./ui";
import { FindingsTable, FindingDetails } from "./Findings";

function Distribution({
  title,
  description,
  data,
  missing = 0,
}: {
  title: string;
  description: string;
  data?: { label: string; count: number }[];
  missing?: number;
}) {
  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>{title}</h2>
          <p>{description}</p>
        </div>
      </div>
      {data?.some((x) => x.count) ? (
        <div className="chart small">
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={data}>
              <CartesianGrid stroke="var(--border)" vertical={false} />
              <XAxis
                dataKey="label"
                tick={{ fill: "var(--text-muted)", fontSize: 10 }}
              />
              <YAxis
                allowDecimals={false}
                tick={{ fill: "var(--text-muted)", fontSize: 10 }}
              />
              <Tooltip
                contentStyle={{
                  background: "var(--surface-raised)",
                  border: "1px solid var(--border)",
                }}
              />
              <Bar
                isAnimationActive={false}
                dataKey="count"
                name="Registros"
                fill="var(--accent)"
                radius={[3, 3, 0, 0]}
              />
            </BarChart>
          </ResponsiveContainer>
        </div>
      ) : (
        <Empty title="Sem métricas suficientes" />
      )}
      <div className="panel-note">
        {missing.toLocaleString("pt-BR")} registros sem esta métrica; não são
        classificados como pontuação zero.
      </div>
    </section>
  );
}
export function Overview() {
  const [days, setDays] = useState(30);
  const [selected, setSelected] = useState<number | null>(null);
  const global = useData<Dashboard>("dashboard", "/dashboard?days=" + days);
  const exposure = useData<Exposure>("exposure", "/exposure");
  const priorities = useData<Page<Finding>>(
    "findings",
    "/findings?status=open&page_size=5",
  );
  const activity = useData<Event[]>("activity", "/activity");
  const sources = useData<Source[]>("sources", "/sources");
  const technologies = useData<{
    items: { ecosystem: string; package: string; vulnerabilities: number }[];
  }>("technologies", "/technologies?page_size=5");
  const history = useData<{ date: string; new: number; resolved: number }[]>(
    "finding-trend",
    "/finding-trend?days=" + days,
  );
  const severitySeries: Record<string, string | number>[] = [];
  for (const item of global.data?.severity_trend || []) {
    let row = severitySeries.find((r) => r.date === item.date);
    if (!row) {
      row = { date: item.date };
      severitySeries.push(row);
    }
    row[item.severity] = item.count;
  }
  const e = exposure.data;
  const g = global.data;
  const waiting = !e || e.state === "no_projects" || e.state === "not_scanned";
  return (
    <>
      <Header
        eyebrow="APPLICATION SECURITY / OVERVIEW"
        title="Visão geral"
        description="Priorize o que afeta suas aplicações. Investigue com contexto."
        action={
          <Link className="button primary" to="/projects">
            <FolderGit2 size={16} />
            Analisar repositório
          </Link>
        }
      />
      <ErrorBox error={exposure.error || global.error} />
      <div className="section-title">
        <div>
          <ShieldCheck size={17} />
          <h2>Exposição das aplicações</h2>
          <span className="chip">{e?.projects ?? 0} projetos monitorados</span>
        </div>
        <Link to="/priorities">
          Central de prioridades <ArrowRight size={14} />
        </Link>
      </div>
      <div className="metrics">
        {[
          {
            label: "Vulnerabilidades relevantes",
            value: e?.relevant_vulnerabilities,
            to: "/priorities?kind=sca",
            context: "Correspondências nos projetos",
          },
          {
            label: "Críticas e altas abertas",
            value: e?.open_high_critical,
            to: "/priorities?severity=HIGH_CRITICAL",
            context: "Achados SCA + SAST em aberto",
          },
          {
            label: "Exploração conhecida",
            value: e?.kev,
            to: "/priorities?priority=immediate",
            context: "KEV relacionado aos ativos",
          },
          {
            label: "Novas relevantes / 24h",
            value: e?.new_24h,
            to: "/priorities?new_hours=24",
            context: "Primeira observação no período",
          },
        ].map((k, index) => (
          <Kpi
            key={k.label}
            label={k.label}
            value={
              waiting ||
              (index !== 1 && !e?.sca_scanned) ||
              (e?.state === "partial" && !k.value)
                ? null
                : (k.value ?? 0)
            }
            context={k.context}
            to={k.to}
            state={
              index !== 1 && e && !e.sca_scanned && e.state !== "no_projects"
                ? "Aguardando SCA"
                : e?.state || "Carregando"
            }
            tone={index === 1 ? "attention" : "default"}
          />
        ))}
      </div>
      {waiting && (
        <div className="onboarding-banner">
          <span className="onboarding-icon">
            <FolderGit2 size={25} />
          </span>
          <div>
            <h3>
              {e?.state === "no_projects"
                ? "Coloque suas aplicações no radar"
                : "Seu próximo passo é uma análise"}
            </h3>
            <p>
              Cadastre um repositório autorizado e execute SCA ou SAST para
              gerar evidências de exposição. As CVEs globais não substituem
              esses dados.
            </p>
          </div>
          <Link className="button secondary" to="/projects">
            Começar <ArrowRight size={14} />
          </Link>
        </div>
      )}
      {e?.state === "partial" && (
        <div className="notice">
          Há análises incompletas, interrompidas ou com falha. Os números
          representam apenas as evidências disponíveis; campos sem evidência
          aparecem como “—”. <Link to="/projects">Revisar cobertura</Link>
        </div>
      )}
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Vulnerabilidades que exigem atenção</h2>
            <p>
              Fila priorizada por exploração conhecida e severidade dos achados
            </p>
          </div>
          <Link to="/priorities">
            Ver fila completa <ArrowUpRight size={14} />
          </Link>
        </div>
        <ErrorBox error={priorities.error} />
        {priorities.isPending ? (
          <Skeleton rows={3} />
        ) : priorities.data?.items.length ? (
          <FindingsTable items={priorities.data.items} open={setSelected} />
        ) : (
          <Empty title="Nenhum achado aberto registrado">
            Os achados aparecerão após analisar os projetos. Uma fila vazia não
            comprova segurança.
          </Empty>
        )}
      </section>
      <div className="section-title global-title">
        <div>
          <Globe2 size={17} />
          <h2>Threat Intelligence global</h2>
          <span className="chip">Base pública coletada</span>
        </div>
        <Link to="/feed">
          Investigar no feed <ArrowRight size={14} />
        </Link>
      </div>
      <div className="global-strip">
        {[
          {
            label: "Vulnerabilidades coletadas",
            value: g?.total,
            path: "/feed",
          },
          {
            label: "Críticas",
            value: g?.severities.CRITICAL || 0,
            path: "/feed?severity=CRITICAL",
          },
          {
            label: "Altas",
            value: g?.severities.HIGH || 0,
            path: "/feed?severity=HIGH",
          },
          {
            label: "Publicadas / 24h",
            value: g?.new_24h || 0,
            path:
              "/feed?published_after=" +
              new Date(Date.now() - 86400000).toISOString().slice(0, 10),
          },
          { label: "Catálogo KEV", value: g?.kev, path: "/exploration" },
        ].map((k) => (
          <Link to={k.path} key={k.label}>
            <small>{k.label}</small>
            <strong>{g ? (k.value ?? 0).toLocaleString("pt-BR") : "—"}</strong>
          </Link>
        ))}
      </div>
      <div className="coverage-caption">
        {g?.coverage} Publicação global não implica que um projeto esteja
        afetado.
      </div>
      <div className="section-title">
        <div>
          <Activity size={17} />
          <h2>Contexto e evolução</h2>
        </div>
        <div className="segmented" aria-label="Período dos gráficos">
          {[7, 30, 60, 90].map((d) => (
            <button
              key={d}
              className={days === d ? "active" : ""}
              aria-pressed={days === d}
              onClick={() => setDays(d)}
            >
              {d} dias
            </button>
          ))}
        </div>
      </div>
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Novas publicações por severidade</h2>
            <p>
              Distribuição das divulgações coletadas no período de {days} dias
            </p>
          </div>
        </div>
        {severitySeries.length ? (
          <div className="chart">
            <ResponsiveContainer width="100%" height={190}>
              <BarChart data={severitySeries}>
                <CartesianGrid stroke="var(--border)" vertical={false} />
                <XAxis
                  dataKey="date"
                  tick={{ fill: "var(--text-muted)", fontSize: 10 }}
                />
                <YAxis
                  allowDecimals={false}
                  tick={{ fill: "var(--text-muted)", fontSize: 10 }}
                />
                <Tooltip
                  contentStyle={{
                    background: "var(--surface-raised)",
                    border: "1px solid var(--border)",
                  }}
                />
                <Legend />
                {[
                  ["CRITICAL", "Crítica", "var(--danger)"],
                  ["HIGH", "Alta", "var(--warning)"],
                  ["MEDIUM", "Média", "var(--accent)"],
                  ["LOW", "Baixa", "var(--success)"],
                  ["UNKNOWN", "Não informada", "var(--text-muted)"],
                ].map(([key, label, color]) => (
                  <Bar
                    isAnimationActive={false}
                    key={key}
                    dataKey={key}
                    name={label}
                    fill={color}
                    stackId="severity"
                  />
                ))}
              </BarChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <Empty title="Sem divulgações coletadas neste período" />
        )}
      </section>
      <div className="chart-grid equal">
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Publicações por dia</h2>
              <p>
                Data de divulgação, somente registros coletados · {days} dias
              </p>
            </div>
          </div>
          {global.isPending ? (
            <Skeleton />
          ) : g?.trend.length ? (
            <div className="chart">
              <ResponsiveContainer width="100%" height={215}>
                <AreaChart data={g.trend}>
                  <CartesianGrid stroke="var(--border)" vertical={false} />
                  <XAxis
                    dataKey="date"
                    tick={{ fill: "var(--text-muted)", fontSize: 10 }}
                  />
                  <YAxis
                    allowDecimals={false}
                    tick={{ fill: "var(--text-muted)", fontSize: 10 }}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "var(--surface-raised)",
                      border: "1px solid var(--border)",
                    }}
                  />
                  <Area
                    isAnimationActive={false}
                    dataKey="count"
                    name="Publicações"
                    stroke="var(--accent)"
                    fill="var(--accent-muted)"
                    strokeWidth={2}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <Empty title="Sem publicações coletadas no período">
              Sincronize as fontes para acompanhar divulgações reais.
            </Empty>
          )}
        </section>
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Entrada e resolução de achados</h2>
              <p>Primeiras observações e eventos de resolução · {days} dias</p>
            </div>
          </div>
          {history.data?.length ? (
            <div className="chart">
              <ResponsiveContainer width="100%" height={215}>
                <BarChart data={history.data}>
                  <CartesianGrid stroke="var(--border)" vertical={false} />
                  <XAxis
                    dataKey="date"
                    tick={{ fill: "var(--text-muted)", fontSize: 10 }}
                  />
                  <YAxis
                    allowDecimals={false}
                    tick={{ fill: "var(--text-muted)", fontSize: 10 }}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "var(--surface-raised)",
                      border: "1px solid var(--border)",
                    }}
                  />
                  <Legend />
                  <Bar
                    isAnimationActive={false}
                    dataKey="new"
                    name="Novos"
                    fill="var(--accent)"
                  />
                  <Bar
                    isAnimationActive={false}
                    dataKey="resolved"
                    name="Resolvidos"
                    fill="var(--success)"
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <Empty title="Sem histórico de achados no período" />
          )}
        </section>
        <Distribution
          title="Distribuição de CVSS"
          description="Severidade técnica · base global coletada"
          data={g?.cvss_distribution}
          missing={g?.cvss_missing}
        />
        <Distribution
          title="Distribuição de EPSS"
          description="Estimativa de exploração · não é probabilidade de comprometimento"
          data={g?.epss_distribution}
          missing={g?.epss_missing}
        />
      </div>
      <div className="chart-grid equal">
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Tecnologias mais citadas</h2>
              <p>
                Contagem de vulnerabilidades distintas por identidade de pacote
              </p>
            </div>
            <Link to="/technologies">
              Explorar <ArrowRight size={13} />
            </Link>
          </div>
          {technologies.data?.items.length ? (
            technologies.data.items.map((t) => (
              <Link
                className="rank-row"
                key={t.ecosystem + t.package}
                to={
                  "/feed?package=" +
                  encodeURIComponent(t.package) +
                  "&ecosystem=" +
                  encodeURIComponent(t.ecosystem)
                }
              >
                <span className="eco-label">{t.ecosystem}</span>
                <b>{t.package}</b>
                <span className="rank-track" aria-hidden="true">
                  <i
                    style={{
                      width: `${(100 * t.vulnerabilities) / Math.max(1, ...(technologies.data?.items || []).map((x) => x.vulnerabilities))}%`,
                    }}
                  />
                </span>
                <span>{t.vulnerabilities}</span>
                <ArrowRight size={13} />
              </Link>
            ))
          ) : (
            <Empty title="Nenhum pacote identificado na coleta" />
          )}
        </section>
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Saúde das fontes</h2>
              <p>Estado individual de coleta e consulta</p>
            </div>
            <Link to="/sources">
              <RefreshCw size={13} />
              Gerenciar
            </Link>
          </div>
          {sources.data?.map((s) => (
            <div className="source-row" key={s.id}>
              <span className="source-logo">
                {s.id.slice(0, 2).toUpperCase()}
              </span>
              <div>
                <strong>{s.id.toUpperCase()}</strong>
                <small>
                  {s.last_success
                    ? "Sucesso " + formatDate(s.last_success)
                    : "Sem sincronização bem-sucedida registrada"}
                </small>
              </div>
              <Badge value={s.health || s.status} />
            </div>
          ))}
        </section>
      </div>
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Atividade recente</h2>
            <p>Eventos reais de inteligência, análises e decisões</p>
          </div>
          <Link to="/history">
            Histórico completo <ArrowRight size={13} />
          </Link>
        </div>
        {activity.data?.length ? (
          <div className="compact-timeline">
            {activity.data.slice(0, 8).map((event) => (
              <div key={event.id}>
                <span className="timeline-dot" />
                <div>
                  <b>
                    {String(
                      event.data.reason ||
                        (
                          {
                            scan: "Análise finalizada",
                            "vulnerability.new":
                              "Nova vulnerabilidade divulgada",
                            "vulnerability.updated": "Advisory atualizado",
                            "finding.triage": "Decisão de remediação",
                          } as Record<string, string>
                        )[event.kind] ||
                        event.kind,
                    )}
                  </b>
                  <small>
                    {event.subject} ·{" "}
                    {event.kind.startsWith("vulnerability")
                      ? "Inteligência global"
                      : "Evento operacional"}
                  </small>
                </div>
                <time>{formatDate(event.created_at)}</time>
              </div>
            ))}
          </div>
        ) : (
          <Empty title="As próximas atividades aparecerão aqui" />
        )}
      </section>
      {selected && (
        <FindingDetails id={selected} close={() => setSelected(null)} />
      )}
    </>
  );
}
