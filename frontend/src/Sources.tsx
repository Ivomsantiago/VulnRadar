import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  RefreshCw,
  ArrowRight,
  Database,
  Clock,
  CheckCircle2,
} from "lucide-react";
import { api, type Source } from "./api";
import { Header, ErrorBox, Badge, formatDate, useData, Empty } from "./shared";
import { Skeleton } from "./ui";
export function Sources() {
  const qc = useQueryClient();
  const data = useData<Source[]>("sources", "/sources");
  const sync = useMutation({
    mutationFn: (source: string) => api("/sources/" + source + "/sync", "POST"),
    onSuccess: () => qc.invalidateQueries(),
  });
  const descriptions: Record<string, string> = {
    nvd: "CVEs, CVSS, CWEs e produtos afetados. Carga inicial dos últimos 7 dias; atualizações incrementais.",
    github:
      "Advisories de bibliotecas com identidades de pacotes, intervalos e correções.",
    osv: "Consultas por pacote e versão na busca e SCA. Não representa um feed global.",
    kev: "Catálogo oficial de exploração conhecida; alternativa pelo espelho oficial da CISA.",
    epss: "Estimativas estatísticas de exploração para CVEs já coletados.",
  };
  return (
    <>
      <Header
        eyebrow="PLATAFORMA / CONECTIVIDADE"
        title="Fontes de inteligência"
        description="Saúde, cobertura e rastreabilidade de cada integração."
        action={
          <Link className="button secondary" to="/history">
            Histórico de sincronizações <ArrowRight size={14} />
          </Link>
        }
      />
      <ErrorBox error={data.error || sync.error} />
      {sync.isSuccess && (
        <div role="status" className="notice">
          <CheckCircle2 size={16} />
          Coleta enfileirada. A conclusão será refletida no estado da fonte.
        </div>
      )}
      {data.isPending ? (
        <Skeleton rows={6} />
      ) : (
        <div className="sources-grid">
          {data.data?.map((s) => (
            <section key={s.id} className="panel source-card">
              <div className="source-card-top">
                <span className="source-logo">
                  {s.id.slice(0, 2).toUpperCase()}
                </span>
                <div>
                  <h2>{s.id.toUpperCase()}</h2>
                  <small>
                    {s.mode === "package-query"
                      ? "Consulta sob demanda"
                      : s.mode === "incremental"
                        ? "Coleta incremental"
                        : "Catálogo / enriquecimento"}
                  </small>
                </div>
                <Badge value={s.health || s.status} />
              </div>
              <p>{descriptions[s.id]}</p>
              <div className="source-timestamps">
                <div>
                  <Clock size={13} />
                  <span>Última tentativa</span>
                  <b>{formatDate(s.last_run)}</b>
                </div>
                <div>
                  <CheckCircle2 size={13} />
                  <span>Último sucesso</span>
                  <b>{formatDate(s.last_success)}</b>
                </div>
              </div>
              <div className="source-metrics">
                <div>
                  <small>Processados</small>
                  <strong>
                    {s.last_sync?.processed_count ?? s.count ?? 0}
                  </strong>
                </div>
                <div>
                  <small>Novos</small>
                  <strong>
                    {s.id === "osv" ? "—" : (s.last_sync?.new_count ?? "—")}
                  </strong>
                </div>
                <div>
                  <small>Atualizados</small>
                  <strong>
                    {s.id === "osv" ? "—" : (s.last_sync?.updated_count ?? "—")}
                  </strong>
                </div>
                <div>
                  <small>Duração</small>
                  <strong>
                    {s.last_sync?.duration_ms != null
                      ? (s.last_sync.duration_ms / 1000).toFixed(1) + "s"
                      : "—"}
                  </strong>
                </div>
              </div>
              <div className="source-pagination">
                <Database size={13} />
                <span>
                  {s.last_sync
                    ? `${s.id === "osv" ? "Consultas por pacote; páginas não contabilizadas" : s.last_sync.pages + " páginas processadas"} · ${s.last_sync.status === "success" ? "Execução finalizada" : "Execução incompleta ou ativa"}`
                    : "Sem execução registrada"}
                </span>
              </div>
              {s.error && <div className="error">{s.error}</div>}
              <div className="source-card-actions">
                {s.id === "osv" ? (
                  <Link className="button secondary" to="/search">
                    Consultar pacote <ArrowRight size={14} />
                  </Link>
                ) : (
                  <button
                    className="secondary"
                    disabled={sync.isPending || s.status === "running"}
                    onClick={() => sync.mutate(s.id)}
                  >
                    <RefreshCw size={14} />
                    Sincronizar agora
                  </button>
                )}
                <Link to="/history">Ver execuções</Link>
              </div>
            </section>
          ))}
        </div>
      )}
      <div className="coverage-caption">
        Os dados refletem o que cada fonte publica e o que foi coletado. Uma
        coleta sem novidades pode ser saudável. Rate limits dependem do provedor
        e das credenciais da instalação; respostas 429 são tratadas com espera e
        retry.
      </div>
    </>
  );
}
