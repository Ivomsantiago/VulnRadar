import { NavLink } from "react-router-dom";
import { useQueryClient, useMutation } from "@tanstack/react-query";
import { RefreshCw, ChevronRight, CheckCircle2 } from "lucide-react";
import { api, type Source } from "./api";
import { formatDate, useData, ErrorBox, Badge, Header } from "./shared";

export function Sources() {
  const qc = useQueryClient();
  const { data, error } = useData<Source[]>("sources", "/sources");
  const mutation = useMutation({
    mutationFn: (source: string) => api("/sources/" + source + "/sync", "POST"),
    onSuccess: () => qc.invalidateQueries(),
  });
  const descriptions: Record<string, string> = {
    nvd: "CVEs, métricas CVSS, CWEs e produtos afetados. Carga inicial: últimos 7 dias.",
    github:
      "Advisories de pacotes, aliases e intervalos de versões. Carga inicial: últimos 7 dias.",
    kev: "Catálogo oficial de vulnerabilidades com exploração conhecida.",
    epss: "Estimativas de exploração para os CVEs já presentes na base.",
  };
  return (
    <>
      <Header
        eyebrow="SISTEMA"
        title="Fontes e sincronização"
        description="Dados oficiais, histórico preservado e falhas visíveis."
      />
      <ErrorBox error={error || mutation.error} />
      {mutation.isSuccess && (
        <div role="status" className="notice">
          <CheckCircle2 size={16} />
          Sincronização enfileirada. O estado será atualizado automaticamente.
        </div>
      )}
      <div className="sources-grid">
        {data?.map((s) => (
          <section className="panel padded" key={s.id}>
            <div className="panel-heading">
              <h2>{s.id.toUpperCase()}</h2>
              <Badge value={s.status} />
            </div>
            <p className="muted">{descriptions[s.id]}</p>
            <dl>
              <dt>Última tentativa</dt>
              <dd>{formatDate(s.last_run)}</dd>
              <dt>Registros processados</dt>
              <dd>{s.count}</dd>
            </dl>
            {s.error && <div className="error">{s.error}</div>}
            <button
              className="secondary"
              disabled={mutation.isPending || s.status === "running"}
              onClick={() => mutation.mutate(s.id)}
            >
              <RefreshCw size={15} />
              Sincronizar agora
            </button>
          </section>
        ))}
      </div>
      <section className="panel padded">
        <h2>OSV · consulta por pacote</h2>
        <p className="muted">
          Usado na busca de versões e nas análises SCA; não simula um feed
          global de todas as vulnerabilidades.
        </p>
        <NavLink to="/search">
          Abrir consulta <ChevronRight size={14} />
        </NavLink>
      </section>
    </>
  );
}
