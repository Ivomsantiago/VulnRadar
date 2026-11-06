import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Search,
  SlidersHorizontal,
  RefreshCw,
  X,
  Columns3,
  ArrowDownUp,
  Download,
  ShieldCheck,
} from "lucide-react";
import {
  api,
  type Vulnerability,
  type Source,
  type Activity as Event,
} from "./api";
import { Evidence, type SourceEvidence } from "./Evidence";
import {
  Header,
  Empty,
  ErrorBox,
  Badge,
  formatDate,
  severityLabel,
  statusLabels,
  useData,
} from "./shared";
import {
  Modal,
  Pagination,
  Skeleton,
  Tabs,
  useStored,
  useDebounced,
} from "./ui";

const columns = [
  ["component", "Componente"],
  ["severity", "Severidade"],
  ["cvss", "CVSS"],
  ["epss", "EPSS"],
  ["kev", "KEV"],
  ["published", "Publicação"],
  ["triage", "Estado"],
] as const;
function exportSelection(items: Vulnerability[]) {
  const blob = new Blob([JSON.stringify(items, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "vulnradar-selecao.json";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export function VulnerabilityTable({
  items,
  onSelect,
  onSort,
  sort,
}: {
  items: Vulnerability[];
  onSelect: (id: string) => void;
  onSort?: (key: string) => void;
  sort?: string;
}) {
  const [visible, setVisible] = useStored<string[]>(
    "vr-columns",
    columns.map((c) => c[0]),
  );
  const [density, setDensity] = useStored("vr-table-density", "compact");
  const [selected, setSelected] = useState<string[]>([]);
  const [configure, setConfigure] = useState(false);
  useEffect(() => setSelected([]), [items]);
  const show = (name: string) => visible.includes(name);
  return (
    <>
      <div className="table-tools">
        <span className="muted">
          {selected.length
            ? `${selected.length} selecionados nesta página`
            : "Registros deduplicados por aliases explícitos"}
        </span>
        {selected.length > 0 && (
          <button
            onClick={() =>
              exportSelection(items.filter((i) => selected.includes(i.id)))
            }
          >
            <Download size={13} />
            Exportar seleção
          </button>
        )}
        <button
          aria-label="Configurar colunas"
          onClick={() => setConfigure(!configure)}
          aria-expanded={configure}
        >
          <Columns3 size={14} />
          Colunas
        </button>
        <select
          aria-label="Densidade da tabela"
          value={density}
          onChange={(e) => setDensity(e.target.value)}
        >
          <option value="compact">Compacta</option>
          <option value="comfortable">Confortável</option>
        </select>
      </div>
      {configure && (
        <fieldset className="column-options">
          <legend>Colunas visíveis</legend>
          {columns.map(([key, label]) => (
            <label key={key}>
              <input
                type="checkbox"
                checked={show(key)}
                onChange={() =>
                  setVisible(
                    show(key)
                      ? visible.filter((x) => x !== key)
                      : [...visible, key],
                  )
                }
              />
              {label}
            </label>
          ))}
        </fieldset>
      )}
      <div className="vulnerability-cards">
        {items.map((v) => (
          <article key={v.id}>
            <div className="button-row">
              <Badge value={v.severity} />
              <Badge value={v.triage} />
              {v.kev && <Badge value="KEV" />}
            </div>
            <button className="text-button" onClick={() => onSelect(v.id)}>
              {v.id}
            </button>
            <p>{v.title}</p>
            {show("component") && (
              <small>
                {v.components?.map((c) => c.package).join(", ") ||
                  "Pacote não identificado"}
              </small>
            )}
            <div className="card-scores">
              {show("cvss") && (
                <span>
                  CVSS <b>{v.cvss ?? "—"}</b>
                </span>
              )}
              {show("epss") && (
                <span>
                  EPSS{" "}
                  <b>
                    {v.epss == null
                      ? "Não informado"
                      : (v.epss * 100).toFixed(2) + "%"}
                  </b>
                </span>
              )}
            </div>
          </article>
        ))}
      </div>
      <div className={`table-scroll vulnerability-table density-${density}`}>
        <table>
          <thead>
            <tr>
              <th className="checkbox-cell">
                <input
                  type="checkbox"
                  aria-label="Selecionar página"
                  checked={items.length > 0 && selected.length === items.length}
                  onChange={(e) =>
                    setSelected(e.target.checked ? items.map((i) => i.id) : [])
                  }
                />
              </th>
              <th>Identificador / descrição</th>
              {columns
                .filter(([key]) => show(key))
                .map(([key, label]) => (
                  <th key={key}>
                    {onSort && ["cvss", "epss", "published"].includes(key) ? (
                      <button
                        className="sort-button"
                        onClick={() => onSort(key)}
                        aria-label={"Ordenar por " + label}
                      >
                        {label}
                        <ArrowDownUp
                          size={12}
                          className={sort === key ? "accent" : ""}
                        />
                      </button>
                    ) : (
                      label
                    )}
                  </th>
                ))}
            </tr>
          </thead>
          <tbody>
            {items.map((v) => (
              <tr
                key={v.id}
                className={selected.includes(v.id) ? "selected-row" : ""}
              >
                <td className="checkbox-cell">
                  <input
                    type="checkbox"
                    aria-label={"Selecionar " + v.id}
                    checked={selected.includes(v.id)}
                    onChange={(e) =>
                      setSelected(
                        e.target.checked
                          ? [...selected, v.id]
                          : selected.filter((i) => i !== v.id),
                      )
                    }
                  />
                </td>
                <td>
                  <button
                    className="text-button"
                    onClick={() => onSelect(v.id)}
                  >
                    {v.id}
                  </button>
                  <span className="truncate" title={v.title}>
                    {v.title}
                  </span>
                </td>
                {show("component") && (
                  <td>
                    <span className="cell-text">
                      {v.components?.map((c) => c.package).join(", ") ||
                        "Não identificado"}
                    </span>
                    <small className="table-sub">
                      {[...new Set(v.components?.map((c) => c.ecosystem))].join(
                        " · ",
                      )}
                    </small>
                  </td>
                )}
                {show("severity") && (
                  <td>
                    <Badge value={v.severity} />
                  </td>
                )}
                {show("cvss") && <td className="mono">{v.cvss ?? "—"}</td>}
                {show("epss") && (
                  <td className="mono">
                    {v.epss == null ? "—" : (v.epss * 100).toFixed(2) + "%"}
                  </td>
                )}
                {show("kev") && (
                  <td>
                    {v.kev ? (
                      <span
                        className="kev"
                        title="Exploração conhecida no catálogo CISA"
                      >
                        KEV
                      </span>
                    ) : (
                      "—"
                    )}
                  </td>
                )}
                {show("published") && (
                  <td>{v.published?.slice(0, 10) || "Não informada"}</td>
                )}
                {show("triage") && (
                  <td>
                    <Badge value={v.triage} />
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
const filterLabels: Record<string, string> = {
  q: "Busca",
  severity: "Severidade",
  ecosystem: "Ecossistema",
  package: "Pacote",
  source: "Fonte",
  cvss_min: "CVSS mín.",
  cvss_max: "CVSS máx.",
  epss_min: "EPSS mín.",
  epss_max: "EPSS máx.",
  published_after: "Publicada desde",
  published_before: "Publicada até",
  modified_after: "Atualizada desde",
  kev: "KEV",
  triage: "Triagem",
  project_id: "Projeto",
};
export function Feed({ kev = false }: { kev?: boolean }) {
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useState(params.get("q") || "");
  const search = useDebounced(q);
  const [selected, setSelected] = useState<string | null>(null);
  const [advanced, setAdvanced] = useState(false);
  const [favorites, setFavorites] = useStored<
    { name: string; query: string }[]
  >("vr-filter-favorites", []);
  const [favoriteName, setFavoriteName] = useState("");
  const [save, setSave] = useState(false);
  const qc = useQueryClient();
  const sources = useData<Source[]>("sources", "/sources");
  const sync = useMutation({
    mutationFn: () => api("/sync", "POST"),
    onSuccess: () => qc.invalidateQueries(),
  });
  useEffect(() => {
    if (search !== (params.get("q") || "")) {
      const n = new URLSearchParams(params);
      search ? n.set("q", search) : n.delete("q");
      n.delete("page");
      setParams(n);
    }
  }, [search]);
  useEffect(() => {
    setQ(params.get("q") || "");
  }, [params.get("q")]);
  const page = Math.max(1, Number(params.get("page")) || 1);
  const request = new URLSearchParams(params);
  if (kev) request.set("kev", "true");
  const result = useData<{
    items: Vulnerability[];
    total: number;
    page_size: number;
  }>("feed", "/vulnerabilities?" + request);
  const set = (key: string, value: string) => {
    const n = new URLSearchParams(params);
    value ? n.set(key, value) : n.delete(key);
    if (key !== "page") n.delete("page");
    setParams(n);
  };
  const active = [...params.entries()].filter(([key]) => key in filterLabels);
  const lastSuccess = sources.data
    ?.map((s) => s.last_success)
    .filter(Boolean)
    .sort()
    .at(-1);
  const today = new Date().toISOString().slice(0, 10);
  const quick = [
    ["Todas", {}],
    ["Críticas", { severity: "CRITICAL" }],
    ["Altas", { severity: "HIGH" }],
    ["KEV", { kev: "true" }],
    ["Novas", { published_after: today }],
    ["Atualizadas", { modified_after: today }],
  ] as const;
  return (
    <>
      <Header
        eyebrow="VULNERABILITY INTELLIGENCE"
        title={kev ? "Exploração conhecida" : "Vulnerability Intelligence"}
        description={
          kev
            ? "Registros do CISA KEV. Exploração conhecida não confirma aplicabilidade local."
            : "Investigue publicações coletadas. A relação com seus ativos é avaliada pelos scans."
        }
        action={
          <button
            className="secondary"
            disabled={sync.isPending}
            onClick={() => sync.mutate()}
          >
            <RefreshCw size={15} />
            Atualizar fontes
          </button>
        }
      />
      <div className="feed-meta">
        <b>{(result.data?.total || 0).toLocaleString("pt-BR")} resultados</b>
        <span>
          Último sucesso:{" "}
          {lastSuccess ? formatDate(lastSuccess) : "Não registrado"}
        </span>
        <span>
          {sources.data?.filter((s) => s.status === "success").length || 0}{" "}
          fontes com sucesso
        </span>
      </div>
      <div className="toolbar">
        <div className="search-field">
          <Search size={16} />
          <input
            aria-label="Pesquisar vulnerabilidades"
            placeholder="CVE, GHSA, biblioteca ou descrição…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <button className="secondary" onClick={() => setAdvanced(true)}>
          <SlidersHorizontal size={15} />
          Filtros avançados
          {active.length > 0 && <span className="count">{active.length}</span>}
        </button>
        <button onClick={() => setSave(true)}>Salvar filtro</button>
      </div>
      <div className="quick-filters">
        {quick.map(([label, values]) => (
          <button
            key={label}
            className={
              (
                label === "Todas"
                  ? active.length === 0
                  : Object.entries(values).every(
                      ([key, value]) => params.get(key) === value,
                    )
              )
                ? "active"
                : ""
            }
            onClick={() => {
              const n = new URLSearchParams();
              if (q) n.set("q", q);
              Object.entries(values).forEach(([k, v]) => n.set(k, v));
              setParams(n);
            }}
          >
            {label}
          </button>
        ))}
        {favorites.length > 0 && (
          <select
            aria-label="Filtros favoritos"
            value=""
            onChange={(e) => {
              if (e.target.value)
                setParams(new URLSearchParams(e.target.value));
            }}
          >
            <option value="">Filtros salvos…</option>
            {favorites.map((f) => (
              <option key={f.name} value={f.query}>
                {f.name}
              </option>
            ))}
          </select>
        )}
      </div>
      {active.length > 0 && (
        <div className="filter-chips">
          {active.map(([key, value]) => (
            <button
              key={key}
              onClick={() => {
                if (key === "q") setQ("");
                set(key, "");
              }}
              aria-label={"Remover filtro " + filterLabels[key]}
            >
              {filterLabels[key]}:{" "}
              {severityLabel[value] || statusLabels[value] || value}
              <X size={12} />
            </button>
          ))}
          <button
            className="text-button"
            onClick={() => {
              setQ("");
              setParams({});
            }}
          >
            Limpar todos
          </button>
        </div>
      )}
      <ErrorBox error={result.error || sync.error} />
      {sync.isSuccess && (
        <div className="notice" role="status">
          Coleta enfileirada. Os estados individuais serão atualizados no painel
          de fontes.
        </div>
      )}
      <section className="panel">
        {result.isPending ? (
          <Skeleton rows={6} />
        ) : result.data?.items.length ? (
          <VulnerabilityTable
            items={result.data.items}
            onSelect={setSelected}
            sort={params.get("sort") || "published"}
            onSort={(key) => {
              const n = new URLSearchParams(params);
              n.set("sort", key);
              n.set(
                "direction",
                params.get("sort") === key && params.get("direction") !== "asc"
                  ? "asc"
                  : "desc",
              );
              n.delete("page");
              setParams(n);
            }}
          />
        ) : (
          <Empty title="Nenhum registro nesta consulta">
            Revise os filtros ou sincronize uma fonte. Falta de cobertura não é
            comprovação de segurança.
          </Empty>
        )}
        <Pagination
          page={page}
          total={result.data?.total || 0}
          size={result.data?.page_size || 25}
          onChange={(n) => set("page", String(n))}
        />
      </section>
      {advanced && (
        <Modal
          title="Filtros avançados"
          drawer
          onClose={() => setAdvanced(false)}
        >
          <div className="filter-groups">
            {[
              {
                name: "Classificação",
                fields: [
                  ["severity", "Severidade", "severity"],
                  ["cvss_min", "CVSS mínimo", "number"],
                  ["cvss_max", "CVSS máximo", "number"],
                  ["epss_min", "EPSS mínimo (0–1)", "number"],
                  ["epss_max", "EPSS máximo (0–1)", "number"],
                  ["kev", "Exploração conhecida", "kev"],
                ],
              },
              {
                name: "Tecnologia",
                fields: [
                  ["ecosystem", "Ecossistema", "text"],
                  ["package", "Nome exato do pacote", "text"],
                ],
              },
              {
                name: "Temporalidade",
                fields: [
                  ["published_after", "Publicação desde", "date"],
                  ["published_before", "Publicação até", "date"],
                  ["modified_after", "Atualização desde", "date"],
                ],
              },
              {
                name: "Investigação",
                fields: [
                  ["source", "Fonte", "source"],
                  ["triage", "Estado de triagem", "triage"],
                  ["project_id", "ID do projeto relacionado", "number"],
                ],
              },
            ].map((group) => (
              <fieldset key={group.name}>
                <legend>{group.name}</legend>
                {group.fields.map(([name, label, type]) => (
                  <label key={name}>
                    {label}
                    {["severity", "kev", "triage", "source"].includes(type) ? (
                      <select
                        aria-label={
                          name === "severity" ? "Filtrar severidade" : label
                        }
                        value={params.get(name) || ""}
                        onChange={(e) => set(name, e.target.value)}
                      >
                        <option value="">Todas / sem restrição</option>
                        {(type === "severity"
                          ? Object.entries(severityLabel)
                          : type === "kev"
                            ? [
                                ["true", "Presente no KEV"],
                                ["false", "Sem registro KEV coletado"],
                              ]
                            : type === "source"
                              ? ["nvd", "github", "osv", "kev"].map((s) => [
                                  s,
                                  s.toUpperCase(),
                                ])
                              : Object.entries(statusLabels).filter(([k]) =>
                                  [
                                    "new",
                                    "investigating",
                                    "resolved",
                                    "accepted",
                                    "planned",
                                    "not_applicable",
                                  ].includes(k),
                                )
                        ).map(([key, text]) => (
                          <option key={key} value={key}>
                            {text}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <input
                        type={type}
                        min={type === "number" ? 0 : undefined}
                        step={type === "number" ? "0.01" : undefined}
                        value={params.get(name) || ""}
                        onChange={(e) => set(name, e.target.value)}
                      />
                    )}
                  </label>
                ))}
              </fieldset>
            ))}
          </div>
          <div className="modal-actions">
            <button
              onClick={() => {
                setQ("");
                setParams({});
              }}
            >
              Limpar todos
            </button>
            <button className="primary" onClick={() => setAdvanced(false)}>
              Ver resultados
            </button>
          </div>
          <p className="muted">
            Linguagem e produto não são inferidos por palavras-chave; use a
            identidade de pacote quando disponível.
          </p>
        </Modal>
      )}
      {save && (
        <Modal title="Salvar filtro favorito" onClose={() => setSave(false)}>
          <form
            className="stack"
            onSubmit={(e) => {
              e.preventDefault();
              setFavorites(
                [
                  ...favorites.filter((f) => f.name !== favoriteName),
                  { name: favoriteName, query: params.toString() },
                ].slice(-12),
              );
              setSave(false);
              setFavoriteName("");
            }}
          >
            <label>
              Nome do filtro
              <input
                autoFocus
                required
                maxLength={60}
                value={favoriteName}
                onChange={(e) => setFavoriteName(e.target.value)}
                placeholder="Ex.: Críticas do meu ecossistema"
              />
            </label>
            <p className="muted">O favorito fica salvo neste navegador.</p>
            <button className="primary">Salvar</button>
          </form>
        </Modal>
      )}
      {selected && <Details id={selected} close={() => setSelected(null)} />}
    </>
  );
}
export function Details({ id, close }: { id: string; close: () => void }) {
  const qc = useQueryClient();
  const data = useData<{
    vulnerability: Vulnerability;
    priority: { classification: string; reasons: string[] };
    aliases: string[];
    evidence: SourceEvidence[];
    advisories: { id: string; source: string; payload: unknown }[];
    history: Event[];
    related_projects?: {
      finding_id: number;
      project_id: number;
      project_name: string;
      package: string;
      version: string;
      scan_id: number;
      status: string;
    }[];
  }>("detail", "/vulnerabilities/" + encodeURIComponent(id));
  const [tab, setTab] = useState("summary");
  const [status, setStatus] = useState("investigating");
  const [reason, setReason] = useState("");
  const mutation = useMutation({
    mutationFn: () =>
      api(
        "/vulnerabilities/" +
          encodeURIComponent(data.data!.vulnerability.id) +
          "/triage",
        "PATCH",
        { status, reason },
      ),
    onSuccess: () => qc.invalidateQueries(),
  });
  const v = data.data?.vulnerability;
  return (
    <Modal title={"Detalhes da vulnerabilidade"} drawer wide onClose={close}>
      <ErrorBox error={data.error} />
      {data.isPending ? (
        <Skeleton rows={5} />
      ) : (
        data.data &&
        v && (
          <>
            <div className="investigation-title">
              <div className="button-row">
                <Badge value={v.severity} />
                <Badge value={v.triage} />
                {v.kev && <Badge value="KEV" />}
              </div>
              <h1>{v.id}</h1>
              <p>{v.title}</p>
              <span className="muted">{data.data.aliases.join(" · ")}</span>
            </div>
            <Tabs
              value={tab}
              onChange={setTab}
              items={[
                {
                  id: "summary",
                  label: "Resumo",
                  content: (
                    <>
                      <div className="detail-metrics">
                        <span>
                          CVSS<b>{v.cvss ?? "Não informado"}</b>
                        </span>
                        <span>
                          EPSS
                          <b>
                            {v.epss == null
                              ? "Não informado"
                              : (v.epss * 100).toFixed(2) + "%"}
                          </b>
                        </span>
                        <span>
                          KEV
                          <b>
                            {v.kev
                              ? "Exploração conhecida"
                              : "Sem registro coletado"}
                          </b>
                        </span>
                      </div>
                      <p className="description">{v.description}</p>
                      <p className="muted">
                        CWE:{" "}
                        {[
                          ...new Set(
                            (data.data.evidence || []).flatMap(
                              (e) =>
                                JSON.stringify(e.cwes || []).match(
                                  /CWE-\d+/g,
                                ) || [],
                            ),
                          ),
                        ].join(", ") || "Não informado pelas fontes coletadas"}
                      </p>
                      <div className="callout">
                        <ShieldCheck size={18} />
                        <div>
                          <b>{data.data.priority.classification}</b>
                          {data.data.priority.reasons.map((r) => (
                            <p key={r}>{r}</p>
                          ))}
                          <p>
                            Prioridade global preliminar. A aplicabilidade à
                            aplicação depende de evidências locais.
                          </p>
                        </div>
                      </div>
                      <h3>Registrar triagem do advisory</h3>
                      <form
                        className="stack"
                        onSubmit={(e) => {
                          e.preventDefault();
                          mutation.mutate();
                        }}
                      >
                        <label>
                          Estado
                          <select
                            value={status}
                            onChange={(e) => setStatus(e.target.value)}
                          >
                            {[
                              "new",
                              "pending",
                              "investigating",
                              "applicable",
                              "not_applicable",
                              "false_positive",
                              "planned",
                              "remediating",
                              "mitigated",
                              "resolved",
                              "accepted",
                            ].map((s) => (
                              <option key={s} value={s}>
                                {statusLabels[s]}
                              </option>
                            ))}
                          </select>
                        </label>
                        <label>
                          Justificativa
                          <textarea
                            required
                            minLength={3}
                            maxLength={4000}
                            value={reason}
                            onChange={(e) => setReason(e.target.value)}
                          />
                        </label>
                        <button
                          className="primary"
                          disabled={mutation.isPending}
                        >
                          Salvar triagem
                        </button>
                        <ErrorBox error={mutation.error} />
                        {mutation.isSuccess && (
                          <span role="status" className="success-text">
                            Triagem registrada.
                          </span>
                        )}
                      </form>
                    </>
                  ),
                },
                {
                  id: "components",
                  label: "Componentes afetados",
                  content: (
                    <>
                      <Evidence items={data.data.evidence || []} />
                      {!data.data.evidence?.some((e) => e.packages.length) && (
                        <Empty title="Pacotes não informados nesta evidência">
                          Consulte os dados originais por fonte. Um produto CPE
                          não é automaticamente uma biblioteca de pacote.
                        </Empty>
                      )}
                    </>
                  ),
                },
                {
                  id: "exploration",
                  label: "Exploração",
                  content: (
                    <>
                      <div className="callout">
                        <ShieldCheck size={18} />
                        <div>
                          <b>
                            {v.kev
                              ? "Presente no CISA KEV"
                              : "Sem registro KEV coletado"}
                          </b>
                          <p>
                            EPSS estima exploração; CVSS mede severidade.
                            Nenhuma dessas pontuações comprova exploração da sua
                            aplicação.
                          </p>
                        </div>
                      </div>
                      <Evidence
                        items={(data.data.evidence || []).map((e) => ({
                          ...e,
                          packages: [],
                        }))}
                      />
                      <h3>Dados originais das fontes</h3>
                      {data.data.advisories.map((a) => (
                        <details className="source-evidence" key={a.id}>
                          <summary>
                            {a.source.toUpperCase()} · evidência original
                          </summary>
                          <pre className="code-block">
                            {JSON.stringify(a.payload, null, 2)}
                          </pre>
                        </details>
                      ))}
                    </>
                  ),
                },
                {
                  id: "projects",
                  label: "Projetos relacionados",
                  count: data.data.related_projects?.length || 0,
                  content: data.data.related_projects?.length ? (
                    <div className="related-projects">
                      {data.data.related_projects.map((p) => (
                        <Link
                          key={p.finding_id}
                          to={"/priorities?project_id=" + p.project_id}
                          onClick={close}
                        >
                          <b>{p.project_name}</b>
                          <span>
                            {p.package}@{p.version}
                          </span>
                          <Badge value={p.status} />
                          <small>Análise #{p.scan_id}</small>
                        </Link>
                      ))}
                    </div>
                  ) : (
                    <Empty title="Nenhum projeto relacionado observado">
                      Somente correspondências verificadas em análises locais
                      aparecem aqui.
                    </Empty>
                  ),
                },
                {
                  id: "history",
                  label: "Histórico",
                  content: (
                    <>
                      <dl className="detail-list">
                        <dt>Publicação</dt>
                        <dd>{formatDate(v.published)}</dd>
                        <dt>Última atualização da fonte</dt>
                        <dd>{formatDate(v.modified)}</dd>
                      </dl>
                      <div className="timeline">
                        {data.data.history.map((e) => (
                          <div key={e.id}>
                            <span className="timeline-dot" />
                            <div>
                              <b>
                                {e.kind === "triage"
                                  ? "Triagem registrada"
                                  : e.kind}
                              </b>
                              <time>{formatDate(e.created_at)}</time>
                              <p>
                                {String(e.data.reason || e.data.source || "")}
                              </p>
                              {e.data.to != null && (
                                <Badge value={String(e.data.to)} />
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </>
                  ),
                },
              ]}
            />
          </>
        )
      )}
    </Modal>
  );
}
