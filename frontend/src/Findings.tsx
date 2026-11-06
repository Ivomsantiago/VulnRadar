import { Evidence } from "./Evidence";
import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck, Search, ExternalLink, ArrowRight } from "lucide-react";
import { api, type Finding, type Page, type Activity } from "./api";
import {
  Badge,
  Empty,
  ErrorBox,
  Header,
  formatDate,
  statusLabels,
  useData,
} from "./shared";
import { Modal, Pagination, Skeleton, Tabs, useDebounced } from "./ui";
import { Details } from "./Investigation";

export function FindingsTable({
  items,
  open,
}: {
  items: Finding[];
  open: (id: number) => void;
}) {
  return (
    <>
      <div className="finding-cards">
        {items.map((f) => (
          <article key={f.id}>
            <div className="button-row">
              <Badge value={f.severity} />
              <Badge value={f.status} />
              <span className="muted">{f.kind.toUpperCase()}</span>
            </div>
            <button className="text-button" onClick={() => open(f.id)}>
              {f.vulnerability_id || f.rule_id}
            </button>
            <p>{f.project_name}</p>
            <dl>
              <dt>Componente / arquivo</dt>
              <dd>{f.package || f.file}</dd>
              <dt>Versão</dt>
              <dd>{f.version || "Não se aplica"}</dd>
              <dt>Prioridade</dt>
              <dd>{f.priority.classification}</dd>
              <dt>CVSS / EPSS</dt>
              <dd>
                {f.vulnerability?.cvss ?? "—"} /{" "}
                {f.vulnerability?.epss == null
                  ? "Não informado"
                  : (f.vulnerability.epss * 100).toFixed(2) + "%"}
              </dd>
            </dl>
            <button onClick={() => open(f.id)}>
              Investigar achado <ArrowRight size={13} />
            </button>
          </article>
        ))}
      </div>
      <div className="table-scroll findings-table">
        <table>
          <thead>
            <tr>
              <th>Vulnerabilidade / regra</th>
              <th>Componente / arquivo</th>
              <th>Projeto</th>
              <th>Versão</th>
              <th>CVSS / EPSS</th>
              <th>KEV</th>
              <th>Prioridade</th>
              <th>Estado</th>
            </tr>
          </thead>
          <tbody>
            {items.map((f) => (
              <tr key={f.id}>
                <td>
                  <button className="text-button" onClick={() => open(f.id)}>
                    <span
                      className="finding-identifier"
                      title={f.vulnerability_id || f.rule_id || undefined}
                    >
                      {f.vulnerability_id || f.rule_id}
                    </span>
                  </button>
                  <small className="table-sub">
                    {f.kind.toUpperCase()} · <Badge value={f.severity} />
                  </small>
                </td>
                <td>
                  <span className="cell-text">{f.package || f.file}</span>
                  <small className="table-sub">
                    {f.ecosystem || `Linha ${f.line ?? "não informada"}`}
                  </small>
                </td>
                <td>
                  <Link
                    className="cell-text"
                    title={f.project_name}
                    to={"/projects?project=" + f.project_id}
                  >
                    {f.project_name}
                  </Link>
                </td>
                <td className="mono">{f.version || "—"}</td>
                <td>
                  {f.vulnerability?.cvss ?? "—"}
                  <small className="table-sub">
                    {f.vulnerability?.epss == null
                      ? "EPSS não informado"
                      : (f.vulnerability.epss * 100).toFixed(2) + "% EPSS"}
                  </small>
                </td>
                <td>{f.vulnerability?.kev ? <Badge value="KEV" /> : "—"}</td>
                <td>
                  <span
                    className={`priority ${f.priority.classification === "Investigação imediata" ? "urgent" : ""}`}
                  >
                    {f.priority.classification}
                  </span>
                </td>
                <td>
                  <Badge value={f.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
export function FindingDetails({
  id,
  close,
}: {
  id: number;
  close: () => void;
}) {
  const query = useData<Finding>("finding", "/findings/" + id);
  const qc = useQueryClient();
  const [tab, setTab] = useState("summary");
  const [status, setStatus] = useState("investigating");
  const [reason, setReason] = useState("");
  const [vulnerability, setVulnerability] = useState<string | null>(null);
  const mutation = useMutation({
    mutationFn: () =>
      api("/findings/" + id + "/triage", "PATCH", { status, reason }),
    onSuccess: () => {
      qc.invalidateQueries();
      setReason("");
    },
  });
  const finding = query.data;
  const tool = finding?.evidence as
    | {
        extra?: {
          message?: string;
          lines?: string;
          metadata?: { cwe?: string | string[] };
        };
      }
    | undefined;
  return (
    <>
      <Modal title={`Investigar achado #${id}`} drawer wide onClose={close}>
        <ErrorBox error={query.error} />
        {query.isPending ? (
          <Skeleton />
        ) : (
          finding && (
            <>
              <div className="investigation-title">
                <Badge value={finding.severity} />
                <Badge value={finding.kind.toUpperCase()} />
                <Badge value={finding.status} />
                <h1>{finding.vulnerability_id || finding.rule_id}</h1>
                <p>
                  {finding.project_name} <span> / </span>{" "}
                  {finding.package || finding.file}
                </p>
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
                        <div className="context-grid">
                          <div>
                            <small>Versão instalada</small>
                            <strong>
                              {finding.version || "Não se aplica"}
                            </strong>
                          </div>
                          <div>
                            <small>Correção informada</small>
                            <strong>
                              {finding.fixed_versions.length
                                ? finding.fixed_versions.join(", ")
                                : "Não informada"}
                            </strong>
                          </div>
                          <div>
                            <small>Primeira observação</small>
                            <strong>{formatDate(finding.first_seen)}</strong>
                          </div>
                          <div>
                            <small>Última observação</small>
                            <strong>{formatDate(finding.last_seen)}</strong>
                          </div>
                        </div>
                        <div className="callout">
                          <ShieldCheck size={18} />
                          <div>
                            <b>{finding.priority.classification}</b>
                            {finding.priority.reasons.map((r) => (
                              <p key={r}>{r}</p>
                            ))}
                            <p>
                              Correspondência e padrão estático não comprovam
                              alcançabilidade ou exploração.
                            </p>
                          </div>
                        </div>
                        {finding.vulnerability_id && (
                          <button
                            className="secondary"
                            onClick={() =>
                              setVulnerability(finding.vulnerability_id)
                            }
                          >
                            Investigar advisory <ExternalLink size={14} />
                          </button>
                        )}
                        <h3>Próximo passo</h3>
                        <p>
                          Verifique o uso do componente e a exposição da
                          aplicação. Registre evidências antes de decidir pela
                          correção ou aceitação.
                        </p>
                        <form
                          className="stack"
                          onSubmit={(event) => {
                            event.preventDefault();
                            mutation.mutate();
                          }}
                        >
                          <label>
                            Estado da remediação
                            <select
                              value={status}
                              onChange={(e) => setStatus(e.target.value)}
                            >
                              {[
                                "new",
                                "pending",
                                "investigating",
                                "applicable",
                                "planned",
                                "remediating",
                                "resolved",
                                "not_applicable",
                                "false_positive",
                                "accepted",
                                "mitigated",
                              ].map((s) => (
                                <option value={s} key={s}>
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
                              placeholder="Contexto, evidências e ação de remediação"
                            />
                          </label>
                          <button
                            className="primary"
                            disabled={mutation.isPending}
                          >
                            Registrar decisão
                          </button>
                          <ErrorBox error={mutation.error} />
                          {mutation.isSuccess && (
                            <p role="status" className="success-text">
                              Triagem registrada.
                            </p>
                          )}
                        </form>
                      </>
                    ),
                  },
                  {
                    id: "evidence",
                    label: "Evidência",
                    content: (
                      <>
                        <dl className="detail-list">
                          <dt>Arquivo</dt>
                          <dd className="mono">
                            {finding.file || "Não informado"}
                          </dd>
                          <dt>Linha</dt>
                          <dd>{finding.line ?? "Não se aplica"}</dd>
                          <dt>Execução</dt>
                          <dd>
                            <Link to={"/projects?scan=" + finding.scan_id}>
                              #{finding.scan_id} <ArrowRight size={12} />
                            </Link>
                          </dd>
                        </dl>
                        <h3>Evidência preservada da ferramenta</h3>
                        {finding.kind === "sast" && (
                          <>
                            <p>
                              {tool?.extra?.message ||
                                "Consulte a regra e investigue o uso desta API."}
                            </p>
                            {tool?.extra?.metadata?.cwe && (
                              <p className="muted">
                                CWE:{" "}
                                {Array.isArray(tool.extra.metadata.cwe)
                                  ? tool.extra.metadata.cwe.join(", ")
                                  : tool.extra.metadata.cwe}
                              </p>
                            )}
                            <pre className="code-block">
                              {tool?.extra?.lines ||
                                "Trecho não disponível nesta execução; consulte o arquivo e linha registrados."}
                            </pre>
                          </>
                        )}
                        {finding.source_evidence && (
                          <Evidence items={[finding.source_evidence]} />
                        )}
                        <details className="source-evidence">
                          <summary>Dados originais para auditoria</summary>
                          <pre className="code-block">
                            {JSON.stringify(finding.evidence, null, 2)}
                          </pre>
                        </details>
                      </>
                    ),
                  },
                  {
                    id: "history",
                    label: "Histórico",
                    content: (
                      <div className="timeline">
                        {finding.history?.length ? (
                          finding.history.map((e) => (
                            <div key={e.id}>
                              <span className="timeline-dot" />
                              <div>
                                <b>
                                  {e.kind === "finding.triage"
                                    ? "Decisão de triagem"
                                    : e.kind}
                                </b>
                                <time>{formatDate(e.created_at)}</time>
                                <p>
                                  {String(e.data.reason || "Evento de análise")}
                                </p>
                                {e.data.to != null && (
                                  <Badge value={String(e.data.to)} />
                                )}
                              </div>
                            </div>
                          ))
                        ) : (
                          <Empty title="Nenhuma decisão registrada">
                            O histórico de observações foi preservado nos scans
                            relacionados.
                          </Empty>
                        )}
                      </div>
                    ),
                  },
                ]}
              />
            </>
          )
        )}
      </Modal>
      {vulnerability && (
        <Details id={vulnerability} close={() => setVulnerability(null)} />
      )}
    </>
  );
}
export function FindingsPage({
  kind,
  remediation = false,
}: {
  kind?: "sca" | "sast";
  remediation?: boolean;
}) {
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useState(params.get("q") || "");
  const search = useDebounced(q);
  const [selected, setSelected] = useState<number | null>(null);
  const page = Math.max(1, Number(params.get("page")) || 1);
  const status = params.get("status") || "open";
  const request = new URLSearchParams(params);
  request.set("q", search);
  request.set("status", status);
  if (kind) request.set("kind", kind);
  const data = useData<Page<Finding>>("findings", "/findings?" + request);
  const set = (key: string, value: string) => {
    const n = new URLSearchParams(params);
    value ? n.set(key, value) : n.delete(key);
    if (key !== "page") n.delete("page");
    setParams(n);
  };
  const queues = [
    ["open", "Abertos"],
    ["new", "Novos"],
    ["pending", "Pendentes"],
    ["investigating", "Em análise"],
    ["planned", "Planejados"],
    ["remediating", "Em remediação"],
    ["resolved", "Resolvidos"],
    ["not_applicable", "Não aplicáveis"],
    ["accepted", "Risco aceito"],
  ];
  return (
    <>
      <Header
        eyebrow={kind ? "APPLICATION SECURITY" : "GESTÃO OPERACIONAL"}
        title={
          kind
            ? kind === "sca"
              ? "Análises SCA"
              : "Análises SAST"
            : remediation
              ? "Triagem e remediação"
              : "Central de prioridades"
        }
        description="O que afeta seus projetos, com evidências para decidir o próximo passo."
        action={
          <Link className="button secondary" to="/projects">
            Executar análise <ArrowRight size={14} />
          </Link>
        }
      />
      <div className="scope-banner">
        <ShieldCheck size={16} />
        <span>Exposição das aplicações</span>
        <p>
          Somente achados de análises locais. Advisories globais ficam no feed
          de inteligência.
        </p>
      </div>
      <div className="queue-tabs" aria-label="Filas de remediação">
        {queues.map(([key, label]) => (
          <button
            key={key}
            className={status === key ? "active" : ""}
            onClick={() => set("status", key)}
          >
            {label}
          </button>
        ))}
      </div>
      <div className="toolbar">
        <div className="search-field">
          <Search size={16} />
          <input
            aria-label="Pesquisar achados"
            placeholder="Vulnerabilidade, componente ou projeto…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <select
          aria-label="Prioridade"
          value={params.get("priority") || ""}
          onChange={(e) => set("priority", e.target.value)}
        >
          <option value="">Todas as prioridades</option>
          <option value="immediate">Investigação imediata (KEV)</option>
        </select>
        <span className="muted">{data.data?.total ?? 0} achados</span>
      </div>
      <ErrorBox error={data.error} />
      <section className="panel">
        {data.isPending ? (
          <Skeleton />
        ) : data.data?.items.length ? (
          <FindingsTable items={data.data.items} open={setSelected} />
        ) : (
          <Empty title="Nenhum achado nesta fila">
            Cadastre um projeto e execute uma análise, ou ajuste os filtros. A
            ausência de achados não comprova segurança.
          </Empty>
        )}
        <Pagination
          page={page}
          total={data.data?.total || 0}
          size={data.data?.page_size || 25}
          onChange={(n) => set("page", String(n))}
        />
      </section>
      {selected && (
        <FindingDetails id={selected} close={() => setSelected(null)} />
      )}
    </>
  );
}
