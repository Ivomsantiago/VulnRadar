import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowDownToLine,
  ArrowUpRight,
  CalendarDays,
  Check,
  LoaderCircle,
  RefreshCw,
  Search,
  ShieldAlert,
  X,
} from "lucide-react";
import { api, type Vulnerability } from "./api";
import { Details } from "./Investigation";
import {
  ErrorBox,
  localDateTime,
  severityLabel,
  statusLabels,
  useData,
} from "./shared";
import { Pagination, Skeleton, useDebounced } from "./ui";

type Intel = Vulnerability & { sources: string[] };
type RadarData = {
  items: Intel[];
  total: number;
  summary: {
    total: number;
    critical: number;
    high: number;
    unknown: number;
    kev: number;
    queued: number;
  };
  window: { since: string; until: string; basis: "published" | "modified" };
  scope: string;
};
type Collection = {
  id: number;
  status: string;
  since: string;
  until: string;
  basis: string;
  completed_at: string | null;
  progress: {
    fetched: number;
    pages: number;
    active_source?: string;
    error?: string;
    sources: Record<
      string,
      { status: string; fetched?: number; pages?: number; error?: string }
    >;
  };
};
const names: Record<string, string> = {
  nvd: "NVD",
  github: "GitHub",
  kev: "CISA KEV",
  epss: "FIRST EPSS",
  osv: "OSV",
  trivy: "Trivy",
  grype: "Grype",
};
const running = (job: Collection) =>
  ["pending", "running"].includes(job.status);
const number = (value: number | undefined) =>
  value === undefined ? "—" : value.toLocaleString("pt-BR");
const shortDate = (value: string | null | undefined) =>
  value
    ? new Date(value).toLocaleString("pt-BR", {
        day: "2-digit",
        month: "short",
        hour: "2-digit",
        minute: "2-digit",
      })
    : "Não informada";

export function RadarPage() {
  const [params, setParams] = useSearchParams();
  const [search, setSearch] = useState(params.get("q") || "");
  const debounced = useDebounced(search);
  const [selected, setSelected] = useState<string[]>([]);
  const [details, setDetails] = useState<string | null>(null);
  const [custom, setCustom] = useState(false);
  const [from, setFrom] = useState(
    localDateTime(new Date(Date.now() - 30 * 86400000).toISOString()),
  );
  const [to, setTo] = useState(localDateTime(new Date().toISOString()));
  const [enrich, setEnrich] = useState(true);
  const [notice, setNotice] = useState("");
  const qc = useQueryClient();
  const period = params.get("period") || "24h";
  const severity = params.get("severity") || "urgent";
  const page = Math.max(1, Number(params.get("page")) || 1);
  const query = params.toString();
  const result = useData<RadarData>("radar", "/radar?" + query);
  const collections = useQuery({
    queryKey: ["radar-collections"],
    queryFn: () => api<Collection[]>("/radar/collections"),
    refetchInterval: (query) =>
      query.state.data?.some(running) ? 1500 : 10000,
  });
  const active = collections.data?.find(running);
  const latest = collections.data?.[0];
  const set = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    value ? next.set(key, value) : next.delete(key);
    if (key !== "page") next.delete("page");
    setParams(next);
  };
  useEffect(() => {
    if (debounced !== (params.get("q") || "")) set("q", debounced);
  }, [debounced]);
  useEffect(() => setSearch(params.get("q") || ""), [params.get("q")]);
  useEffect(() => {
    setSelected([]);
  }, [query]);
  useEffect(() => {
    qc.invalidateQueries({ queryKey: ["radar"] });
  }, [latest?.status, latest?.progress.fetched, latest?.progress.pages]);
  const collect = useMutation({
    mutationFn: () =>
      api<Collection>("/radar/collect", "POST", {
        ...result.data!.window,
        enrich,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["radar-collections"] });
      setNotice("");
    },
  });
  const cancel = useMutation({
    mutationFn: () => api(`/radar/collections/${active!.id}/cancel`, "POST"),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["radar-collections"] }),
  });
  const queue = useMutation({
    mutationFn: () =>
      api<{ updated: number }>("/radar/queue", "POST", {
        identifiers: selected,
      }),
    onSuccess: (data) => {
      setNotice(
        data.updated === 1
          ? "1 vulnerabilidade adicionada à fila de investigação."
          : `${data.updated} vulnerabilidades adicionadas à fila de investigação.`,
      );
      setSelected([]);
      qc.invalidateQueries();
    },
  });
  const choosePeriod = (value: string) => {
    const next = new URLSearchParams(params);
    next.set("period", value);
    next.delete("since");
    next.delete("until");
    next.delete("page");
    setParams(next);
    setCustom(false);
  };
  const items = result.data?.items || [];
  const summary = result.data?.summary;
  const kevAvailable =
    latest?.progress.sources?.kev?.status === "success" ||
    (summary?.kev || 0) > 0;
  const window = result.data?.window;
  return (
    <div className="radar-page">
      <header className="radar-heading">
        <div>
          <span className="radar-eyebrow">
            <span /> INTELIGÊNCIA DE VULNERABILIDADES
          </span>
          <h1>Radar de vulnerabilidades</h1>
          <p>Publicações por período, com críticas e altas primeiro.</p>
        </div>
        <div className="radar-heading-actions">
          <Link to="/sources">
            Fontes e monitoramento <ArrowUpRight size={15} />
          </Link>
          <button
            className="primary radar-collect"
            disabled={
              !!active || collect.isPending || !result.data || !!result.error
            }
            onClick={() => collect.mutate()}
          >
            {active ? (
              <LoaderCircle className="radar-spin" size={17} />
            ) : (
              <RefreshCw size={17} />
            )}
            {active ? "Buscando vulnerabilidades…" : "Buscar vulnerabilidades"}
          </button>
        </div>
      </header>
      <section className="radar-period" aria-label="Período de inteligência">
        <div className="radar-period-top">
          <div>
            <CalendarDays size={17} />
            <b>Período</b>
          </div>
          <div className="radar-period-options">
            {[
              ["24h", "Últimas 24h"],
              ["7d", "7 dias"],
              ["30d", "1 mês"],
              ["90d", "3 meses"],
            ].map(([value, label]) => (
              <button
                key={value}
                aria-pressed={period === value && !custom}
                className={period === value && !custom ? "active" : ""}
                onClick={() => choosePeriod(value)}
              >
                {label}
              </button>
            ))}
            <button
              className={period === "custom" || custom ? "active" : ""}
              aria-expanded={custom}
              onClick={() => setCustom(!custom)}
            >
              Escolher datas
            </button>
          </div>
          <select
            aria-label="Considerar data de"
            value={params.get("basis") || "published"}
            onChange={(e) => set("basis", e.target.value)}
          >
            <option value="published">Publicadas no período</option>
            <option value="modified">Atualizadas no período</option>
          </select>
        </div>
        {custom && (
          <form
            className="radar-custom"
            onSubmit={(e) => {
              e.preventDefault();
              const next = new URLSearchParams(params);
              next.set("period", "custom");
              next.set("since", new Date(from).toISOString());
              next.set("until", new Date(to).toISOString());
              next.delete("page");
              setParams(next);
              setCustom(false);
            }}
          >
            <label>
              Início
              <input
                required
                type="datetime-local"
                value={from}
                max={to}
                onChange={(e) => setFrom(e.target.value)}
              />
            </label>
            <label>
              Fim
              <input
                required
                type="datetime-local"
                value={to}
                min={from}
                max={localDateTime(new Date().toISOString())}
                onChange={(e) => setTo(e.target.value)}
              />
            </label>
            <button className="primary">Aplicar período</button>
          </form>
        )}
        <div className="radar-window">
          <span>
            {window
              ? `${shortDate(window.since)} — ${shortDate(window.until)}`
              : "Carregando período…"}
            {period === "30d" && " · últimos 30 dias"}
            {period === "90d" && " · últimos 90 dias"}
          </span>
          <label>
            <input
              type="checkbox"
              checked={enrich}
              onChange={(e) => setEnrich(e.target.checked)}
            />
            Enriquecer com KEV e EPSS
          </label>
        </div>
      </section>
      <ErrorBox
        error={
          result.error ||
          collections.error ||
          collect.error ||
          cancel.error ||
          queue.error
        }
      />
      {latest && (
        <section className={`radar-collection ${latest.status}`} role="status">
          <div>
            {active ? (
              <LoaderCircle size={17} className="radar-spin" />
            ) : latest.status === "success" ? (
              <Check size={17} />
            ) : (
              <ShieldAlert size={17} />
            )}
            <div>
              <strong>
                {latest.status === "pending"
                  ? "Coleta na fila"
                  : latest.status === "running"
                    ? `Consultando ${names[latest.progress.active_source || ""] || "fontes"}`
                    : latest.status === "success"
                      ? "Período consultado nas fontes"
                      : latest.status === "partial"
                        ? "Coleta parcial — algumas fontes não terminaram"
                        : latest.status === "cancelled"
                          ? "Coleta cancelada"
                          : "Não foi possível concluir a coleta"}
              </strong>
              <p>
                {shortDate(latest.since)} — {shortDate(latest.until)} ·{" "}
                {latest.progress.fetched || 0} registros recebidos ·{" "}
                {latest.progress.pages || 0} páginas salvas.{" "}
                {latest.progress.error}
              </p>
            </div>
          </div>
          <div className="radar-source-progress">
            {Object.entries(latest.progress.sources || {}).map(
              ([key, value]) => (
                <span
                  key={key}
                  title={value.error || `${value.fetched || 0} registros`}
                >
                  <i className={value.status} />
                  {names[key]}
                  {value.status === "running"
                    ? "…"
                    : value.status === "success"
                      ? " ✓"
                      : " incompleto"}
                </span>
              ),
            )}
            {active && (
              <button
                className="icon-button"
                aria-label="Cancelar coleta"
                onClick={() => cancel.mutate()}
                disabled={cancel.isPending}
              >
                <X size={16} />
              </button>
            )}
          </div>
        </section>
      )}
      <section
        className="radar-summary"
        aria-label="Inteligência na base coletada"
      >
        <button
          className={severity === "CRITICAL" ? "chosen" : ""}
          onClick={() => set("severity", "CRITICAL")}
        >
          <span>
            <i className="critical" />
            Críticas
          </span>
          <strong>{number(summary?.critical)}</strong>
          <small>Investigar primeiro</small>
        </button>
        <button
          className={severity === "HIGH" ? "chosen" : ""}
          onClick={() => set("severity", "HIGH")}
        >
          <span>
            <i className="high" />
            Altas
          </span>
          <strong>{number(summary?.high)}</strong>
          <small>Próximas prioridades</small>
        </button>
        <button
          className={params.get("kev") === "true" ? "chosen" : ""}
          disabled={!kevAvailable}
          title={
            kevAvailable
              ? "Filtrar registros no CISA KEV"
              : "Habilite o enriquecimento e consulte o período para atualizar KEV"
          }
          onClick={() => {
            const next = new URLSearchParams(params);
            next.set("kev", "true");
            next.set("severity", "all");
            next.delete("page");
            setParams(next);
          }}
        >
          <span>Exploração conhecida</span>
          <strong>{number(kevAvailable ? summary?.kev : undefined)}</strong>
          <small>
            {kevAvailable
              ? "Registros no CISA KEV"
              : "KEV não consultado no período"}
          </small>
        </button>
        <button
          className={params.get("state") === "queued" ? "chosen" : ""}
          onClick={() => set("state", "queued")}
        >
          <span>Em investigação</span>
          <strong>{number(summary?.queued)}</strong>
          <small>Sua fila neste período</small>
        </button>
      </section>
      <section className="radar-results">
        <div className="radar-results-heading">
          <div>
            <h2>
              {params.get("basis") === "modified"
                ? "Atualizações do período"
                : "Publicações do período"}
              <span>{number(result.data?.total)}</span>
            </h2>
            <p>
              Maior severidade informada pelas fontes. KEV e EPSS ajudam a
              ordenar a investigação.
            </p>
            {!!summary?.unknown && (
              <p>
                {number(summary.unknown)}{" "}
                {summary.unknown === 1
                  ? "publicação ainda sem classificação na fonte."
                  : "publicações ainda sem classificação na fonte."}{" "}
                <button
                  className="radar-text-action"
                  onClick={() => set("severity", "UNKNOWN")}
                >
                  Ver sem classificação
                </button>
              </p>
            )}
          </div>
          <div className="radar-export">
            <a href={"/api/radar?" + query + "&format=csv"} download>
              <ArrowDownToLine size={15} />
              CSV
            </a>
            <a
              href={"/api/radar?" + query + "&export=true"}
              download="radar-periodo.json"
            >
              JSON
            </a>
          </div>
        </div>
        <div className="radar-filters">
          <div className="radar-search">
            <Search size={17} />
            <input
              aria-label="Pesquisar no radar"
              placeholder="Buscar CVE, GHSA, pacote ou descrição…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <select
            aria-label="Severidade no radar"
            value={severity}
            onChange={(e) => set("severity", e.target.value)}
          >
            <option value="urgent">Críticas e altas</option>
            <option value="all">Todas as severidades</option>
            {["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].map((s) => (
              <option key={s} value={s}>
                {severityLabel[s]}
              </option>
            ))}
          </select>
          <select
            aria-label="Estado no radar"
            value={params.get("state") || "all"}
            onChange={(e) => set("state", e.target.value)}
          >
            <option value="all">Todos os estados</option>
            <option value="new">Ainda não investigadas</option>
            <option value="queued">Em investigação</option>
            <option value="resolved">Concluídas</option>
          </select>
          <select
            aria-label="Ordenar radar"
            value={params.get("sort") || "priority"}
            onChange={(e) => set("sort", e.target.value)}
          >
            <option value="priority">Por prioridade</option>
            <option value="newest">Mais recentes</option>
            <option value="epss">Maior EPSS</option>
          </select>
          {params.get("kev") === "true" && (
            <button className="radar-chip" onClick={() => set("kev", "")}>
              Somente KEV <X size={12} />
            </button>
          )}
        </div>
        {!!items.length && (
          <label className="radar-mobile-select">
            <input
              type="checkbox"
              checked={items.every((item) => selected.includes(item.id))}
              onChange={(e) =>
                setSelected(
                  e.target.checked ? items.map((item) => item.id) : [],
                )
              }
            />
            Selecionar publicações da página
          </label>
        )}
        {notice && (
          <p className="radar-notice" role="status">
            {notice}
          </p>
        )}
        {!!selected.length && (
          <div className="radar-selection">
            <span>
              {selected.length}{" "}
              {selected.length === 1 ? "selecionada" : "selecionadas"}
            </span>
            <button
              disabled={queue.isPending}
              className="primary"
              onClick={() => queue.mutate()}
            >
              Adicionar à investigação
            </button>
            <button onClick={() => setSelected([])}>Limpar seleção</button>
          </div>
        )}
        {result.isPending ? (
          <Skeleton rows={6} />
        ) : items.length ? (
          <div className="radar-table-scroll">
            <table>
              <thead>
                <tr>
                  <th className="radar-check">
                    <input
                      type="checkbox"
                      aria-label="Selecionar esta página"
                      checked={
                        items.length > 0 &&
                        items.every((item) => selected.includes(item.id))
                      }
                      onChange={(e) =>
                        setSelected(
                          e.target.checked ? items.map((item) => item.id) : [],
                        )
                      }
                    />
                  </th>
                  <th>Severidade</th>
                  <th>Vulnerabilidade</th>
                  <th>CVSS / EPSS</th>
                  <th>Exploração</th>
                  <th>
                    {params.get("basis") === "modified"
                      ? "Atualizada"
                      : "Publicada"}
                  </th>
                  <th>Estado</th>
                  <th>
                    <span className="sr-only">Investigar</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <tr
                    key={item.id}
                    className={selected.includes(item.id) ? "selected" : ""}
                  >
                    <td className="radar-check">
                      <input
                        type="checkbox"
                        aria-label={`Selecionar ${item.id}`}
                        checked={selected.includes(item.id)}
                        onChange={(e) =>
                          setSelected(
                            e.target.checked
                              ? [...selected, item.id]
                              : selected.filter((value) => value !== item.id),
                          )
                        }
                      />
                    </td>
                    <td>
                      <span
                        className={`radar-severity ${item.severity.toLowerCase()}`}
                      >
                        {severityLabel[item.severity] || "Não informada"}
                      </span>
                    </td>
                    <td className="radar-title-cell">
                      <button onClick={() => setDetails(item.id)}>
                        {item.id}
                        <ArrowUpRight size={13} />
                      </button>
                      <p title={item.title}>{item.title}</p>
                      <div className="radar-providers">
                        {item.sources.map((source) => (
                          <span key={source}>{names[source] || source}</span>
                        ))}
                      </div>
                    </td>
                    <td>
                      <strong className="radar-cvss">{item.cvss ?? "—"}</strong>
                      <small>
                        EPSS{" "}
                        {item.epss === null
                          ? "não informado"
                          : (item.epss * 100).toFixed(2) + "%"}
                      </small>
                    </td>
                    <td>
                      {item.kev ? (
                        <span className="radar-kev">No CISA KEV</span>
                      ) : (
                        <span className="radar-muted">Sem registro KEV</span>
                      )}
                    </td>
                    <td className="radar-date">
                      {shortDate(
                        params.get("basis") === "modified"
                          ? item.modified
                          : item.published,
                      )}
                    </td>
                    <td>
                      <span
                        className={
                          item.triage === "investigating"
                            ? "radar-state investigating"
                            : "radar-state"
                        }
                      >
                        {statusLabels[item.triage] || item.triage}
                      </span>
                    </td>
                    <td>
                      <button
                        className="icon-button"
                        aria-label={`Investigar ${item.id}`}
                        onClick={() => setDetails(item.id)}
                      >
                        <ArrowUpRight size={17} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="radar-empty">
            <Search size={27} />
            <h3>
              {summary?.total
                ? "Nenhuma publicação com estes filtros"
                : "Busque as vulnerabilidades deste período"}
            </h3>
            <p>
              {summary?.total
                ? "Ajuste a severidade ou o estado para ampliar a lista."
                : "Clique em Buscar vulnerabilidades para consultar NVD e GitHub. Os resultados ficam salvos e podem ser organizados aqui."}
            </p>
            {!!summary?.total && (
              <button onClick={() => set("severity", "all")}>
                Ver todas as severidades
              </button>
            )}
            {!summary?.total && (
              <button
                className="primary"
                disabled={!!active || collect.isPending || !!result.error}
                onClick={() => collect.mutate()}
              >
                Buscar nas fontes
              </button>
            )}
          </div>
        )}
        <Pagination
          page={page}
          total={result.data?.total || 0}
          size={25}
          onChange={(value) => set("page", String(value))}
        />
      </section>
      <p className="radar-footnote">
        Inteligência na base coletada · O período filtra a data informada pela
        fonte, não a data em que você abriu a tela. Publicação não confirma
        exposição local.{" "}
        <Link to="/exposure">
          Ver exposição das aplicações <ArrowUpRight size={12} />
        </Link>
      </p>
      {details && <Details id={details} close={() => setDetails(null)} />}
    </div>
  );
}
