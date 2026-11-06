import { Evidence, type SourceEvidence } from "./Evidence";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQueryClient, useMutation } from "@tanstack/react-query";
import { Search, ChevronLeft, ChevronRight, X } from "lucide-react";
import { api, type Vulnerability, type Activity as Event } from "./api";
import {
  formatDate,
  severityLabel,
  useData,
  Empty,
  ErrorBox,
  Badge,
  Header,
  ExportButtons,
} from "./shared";

export function VulnerabilityTable({
  items,
  onSelect,
}: {
  items: Vulnerability[];
  onSelect: (id: string) => void;
}) {
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Identificador / descrição</th>
            <th>Severidade</th>
            <th>CVSS</th>
            <th>EPSS</th>
            <th>KEV</th>
            <th>Publicação</th>
            <th>Triagem</th>
          </tr>
        </thead>
        <tbody>
          {items.map((v) => (
            <tr key={v.id}>
              <td>
                <button className="text-button" onClick={() => onSelect(v.id)}>
                  {v.id}
                </button>
                <span className="truncate">{v.title}</span>
              </td>
              <td>
                <Badge value={v.severity} />
              </td>
              <td>{v.cvss ?? "—"}</td>
              <td>{v.epss === null ? "—" : (v.epss * 100).toFixed(2) + "%"}</td>
              <td>{v.kev ? <span className="kev">Confirmada</span> : "—"}</td>
              <td>{v.published?.slice(0, 10) || "—"}</td>
              <td>{v.triage}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Feed({ kev = false }: { kev?: boolean }) {
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useState(params.get("q") || "");
  const [selection, setSelection] = useState<string | null>(null);
  const severity = params.get("severity") || "";
  const page = Number(params.get("page") || 1);
  useEffect(() => {
    const timer = setTimeout(() => {
      if (q !== (params.get("q") || "")) {
        const next = new URLSearchParams(params);
        next.set("q", q);
        next.delete("page");
        setParams(next);
      }
    }, 300);
    return () => clearTimeout(timer);
  }, [q, params, setParams]);
  const path =
    "/vulnerabilities?" + params.toString() + (kev ? "&kev=true" : "");
  const { data, error, isPending } = useData<{
    items: Vulnerability[];
    total: number;
    page_size: number;
  }>("feed", path);
  return (
    <>
      <Header
        eyebrow="MONITORAMENTO"
        title={kev ? "Exploração conhecida" : "Feed de vulnerabilidades"}
        description={
          kev
            ? "Vulnerabilidades presentes no catálogo CISA KEV."
            : "Investigue advisories, identifique contexto e acompanhe a triagem."
        }
        action={<ExportButtons />}
      />
      <div className="filters">
        <div className="search-field">
          <Search size={17} />
          <input
            aria-label="Pesquisar vulnerabilidades"
            placeholder="CVE, GHSA, descrição…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <select
          aria-label="Filtrar severidade"
          value={severity}
          onChange={(e) => {
            const next = new URLSearchParams(params);
            next.set("severity", e.target.value);
            next.delete("page");
            setParams(next);
          }}
        >
          <option value="">Todas as severidades</option>
          {Object.entries(severityLabel).map(([key, label]) => (
            <option key={key} value={key}>
              {label}
            </option>
          ))}
        </select>
        <span className="muted">{data?.total ?? 0} registros</span>
      </div>
      <details className="advanced-filters">
        <summary>Filtros avançados</summary>
        <div className="package-form">
          {[
            ["ecosystem", "Ecossistema", "text"],
            ["source", "Fonte", "text"],
            ["cvss_min", "CVSS mínimo", "number"],
            ["epss_min", "EPSS mínimo (0 a 1)", "number"],
            ["published_after", "Publicado desde", "date"],
            ["triage", "Estado de triagem", "text"],
          ].map(([name, label, type]) => (
            <label key={name}>
              {label}
              <input
                type={type}
                step={type === "number" ? "0.01" : undefined}
                min={type === "number" ? 0 : undefined}
                max={
                  name === "cvss_min" ? 10 : name === "epss_min" ? 1 : undefined
                }
                value={params.get(name) || ""}
                onChange={(e) => {
                  const n = new URLSearchParams(params);
                  if (e.target.value) n.set(name, e.target.value);
                  else n.delete(name);
                  n.delete("page");
                  setParams(n);
                }}
              />
            </label>
          ))}
        </div>
      </details>
      <ErrorBox error={error} />
      <section className="panel">
        {isPending ? (
          <div className="skeleton">Carregando registros…</div>
        ) : data?.items.length ? (
          <VulnerabilityTable items={data.items} onSelect={setSelection} />
        ) : (
          <Empty title="Nenhuma vulnerabilidade nesta consulta">
            Revise os filtros ou sincronize as fontes. A ausência de registros
            não comprova segurança.
          </Empty>
        )}
        <div className="pagination">
          <span>Página {page}</span>
          <button
            aria-label="Página anterior"
            disabled={page <= 1}
            onClick={() => {
              const n = new URLSearchParams(params);
              n.set("page", String(page - 1));
              setParams(n);
            }}
          >
            <ChevronLeft size={16} />
          </button>
          <button
            aria-label="Próxima página"
            disabled={!data || page * data.page_size >= data.total}
            onClick={() => {
              const n = new URLSearchParams(params);
              n.set("page", String(page + 1));
              setParams(n);
            }}
          >
            <ChevronRight size={16} />
          </button>
        </div>
      </section>
      {selection && <Details id={selection} close={() => setSelection(null)} />}
    </>
  );
}

export function Details({ id, close }: { id: string; close: () => void }) {
  const qc = useQueryClient();
  const { data, error } = useData<{
    evidence: SourceEvidence[];
    vulnerability: Vulnerability;
    priority: { classification: string; reasons: string[] };
    aliases: string[];
    advisories: {
      id: string;
      source: string;
      payload: Record<string, unknown>;
    }[];
    history: Event[];
  }>("detail", "/vulnerabilities/" + encodeURIComponent(id));
  const [status, setStatus] = useState("investigating");
  const [reason, setReason] = useState("");
  const mutation = useMutation({
    mutationFn: () =>
      api(
        "/vulnerabilities/" +
          encodeURIComponent(data!.vulnerability.id) +
          "/triage",
        "PATCH",
        { status, reason },
      ),
    onSuccess: () => qc.invalidateQueries(),
  });
  useEffect(() => {
    const old = document.activeElement as HTMLElement;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") close();
      if (e.key === "Tab") {
        const dialog = document.querySelector(
          '[aria-label="Detalhes da vulnerabilidade"]',
        );
        const elements = dialog?.querySelectorAll<HTMLElement>(
          "button:not(:disabled),a[href],input,textarea,select,summary",
        );
        if (elements?.length) {
          const first = elements[0],
            last = elements[elements.length - 1];
          if (e.shiftKey && document.activeElement === first) {
            e.preventDefault();
            last.focus();
          } else if (!e.shiftKey && document.activeElement === last) {
            e.preventDefault();
            first.focus();
          }
        }
      }
    };
    document.addEventListener("keydown", handler);
    document.getElementById("close-details")?.focus();
    return () => {
      document.removeEventListener("keydown", handler);
      old?.focus();
    };
  }, [close]);
  return (
    <div className="overlay" onClick={close}>
      <section
        role="dialog"
        aria-modal="true"
        aria-label="Detalhes da vulnerabilidade"
        className="drawer"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="drawer-heading">
          <span className="eyebrow">INVESTIGAÇÃO</span>
          <button
            id="close-details"
            aria-label="Fechar detalhes"
            onClick={close}
          >
            <X size={20} />
          </button>
        </div>
        <h1>{id}</h1>
        <ErrorBox error={error} />
        {data && (
          <>
            <Badge value={data.vulnerability.severity} />
            <h2>{data.vulnerability.title}</h2>
            <p className="description">{data.vulnerability.description}</p>
            <div className="detail-metrics">
              <span>
                CVSS<b>{data.vulnerability.cvss ?? "Não informado"}</b>
              </span>
              <span>
                EPSS
                <b>
                  {data.vulnerability.epss === null
                    ? "Não informado"
                    : (data.vulnerability.epss * 100).toFixed(2) + "%"}
                </b>
              </span>
              <span>
                CISA KEV
                <b>
                  {data.vulnerability.kev
                    ? "Presente"
                    : "Sem registro coletado"}
                </b>
              </span>
            </div>
            <h3>Priorização contextual</h3>
            <p>{data.priority.classification}</p>
            <ul>
              {data.priority.reasons.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
            <h3>Identificadores correlacionados</h3>
            <p>{data.aliases.join(" · ")}</p>
            <h3>Pacotes, correções e referências</h3>
            <Evidence items={data.evidence} />
            <h3>Evidências originais por fonte</h3>
            {data.advisories.map((a) => (
              <details key={a.id}>
                <summary>{a.source.toUpperCase()} · dados originais</summary>
                <pre>{JSON.stringify(a.payload, null, 2)}</pre>
              </details>
            ))}
            <h3>Registrar triagem</h3>
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
                    "mitigated",
                    "resolved",
                    "accepted",
                  ].map((s) => (
                    <option key={s}>{s}</option>
                  ))}
                </select>
              </label>
              <label>
                Justificativa
                <textarea
                  required
                  minLength={3}
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder="Registre o contexto e a evidência da decisão"
                />
              </label>
              <button disabled={mutation.isPending} className="primary">
                Salvar triagem
              </button>
              <ErrorBox error={mutation.error} />
              {mutation.isSuccess && (
                <span role="status">Triagem registrada.</span>
              )}
            </form>
            <h3>Histórico</h3>
            {data.history.map((e) => (
              <div className="history-entry" key={e.id}>
                <b>{e.kind}</b>
                <small>{formatDate(e.created_at)}</small>
                <pre>{JSON.stringify(e.data, null, 2)}</pre>
              </div>
            ))}
          </>
        )}
      </section>
    </div>
  );
}
