import { useState } from "react";
import { useQueryClient, useMutation } from "@tanstack/react-query";
import { Eye, X, ExternalLink, Plus } from "lucide-react";
import { api, type Vulnerability, type Watch } from "./api";
import { useData, Empty, ErrorBox, Header } from "./shared";

export function Watchlist() {
  const qc = useQueryClient();
  const [checkStatus, setCheckStatus] = useState("");
  const check = useMutation({
    mutationFn: (id: number) =>
      api<{ items: Vulnerability[]; coverage: string }>(
        "/watchlist/" + id + "/check",
        "POST",
      ),
    onSuccess: (d) => {
      setCheckStatus(`${d.items.length} advisories. ${d.coverage}`);
      qc.invalidateQueries();
    },
  });
  const { data, error } = useData<Watch[]>("watchlist", "/watchlist");
  const [adding, setAdding] = useState(false);
  const [packageName, setPackage] = useState("");
  const [version, setVersion] = useState("");
  const [eco, setEco] = useState("npm");
  const mutation = useMutation({
    mutationFn: () =>
      api("/watchlist", "POST", {
        ecosystem: eco,
        package: packageName,
        version: version || null,
      }),
    onSuccess: () => {
      qc.invalidateQueries();
      setAdding(false);
      setPackage("");
    },
  });
  const remove = useMutation({
    mutationFn: (id: number) => api("/watchlist/" + id, "DELETE"),
    onSuccess: () => qc.invalidateQueries(),
  });
  return (
    <>
      <Header
        eyebrow="GESTÃO"
        title="Watchlist de tecnologias"
        description="Mantenha os componentes de interesse no seu radar."
        action={
          <button className="primary" onClick={() => setAdding(!adding)}>
            <Plus size={16} />
            Adicionar pacote
          </button>
        }
      />
      <ErrorBox error={error || remove.error || check.error} />
      {checkStatus && (
        <div role="status" className="notice">
          {checkStatus}
        </div>
      )}
      {adding && (
        <section className="panel padded">
          <form
            className="package-form"
            onSubmit={(e) => {
              e.preventDefault();
              mutation.mutate();
            }}
          >
            <label>
              Ecossistema
              <input
                required
                value={eco}
                onChange={(e) => setEco(e.target.value)}
              />
            </label>
            <label>
              Pacote
              <input
                required
                value={packageName}
                onChange={(e) => setPackage(e.target.value)}
              />
            </label>
            <label>
              Versão opcional
              <input
                value={version}
                onChange={(e) => setVersion(e.target.value)}
              />
            </label>
            <button className="primary" disabled={mutation.isPending}>
              Salvar
            </button>
            <ErrorBox error={mutation.error} />
          </form>
        </section>
      )}
      <section className="panel">
        {data?.length ? (
          data.map((w) => (
            <div className="watch-row" key={w.id}>
              <span className="source-logo">
                <Eye size={20} />
              </span>
              <div>
                <strong>{w.package}</strong>
                <small>
                  {w.ecosystem} · {w.version || "Todas as versões"}
                </small>
              </div>
              <button
                disabled={check.isPending || !w.version}
                onClick={() => check.mutate(w.id)}
              >
                Verificar versão <ExternalLink size={13} />
              </button>
              <button
                aria-label={"Remover " + w.package}
                onClick={() => remove.mutate(w.id)}
              >
                <X size={16} />
              </button>
            </div>
          ))
        ) : (
          <Empty title="O que importa para o seu software?">
            Adicione tecnologias e versões para organizar seu monitoramento.
          </Empty>
        )}
      </section>
      <p className="muted">
        Verifique manualmente versões exatas ou habilite a coleta periódica.
        Correspondências OSV geram alertas deduplicados; a consulta envia apenas
        nomes e versões dos pacotes.
      </p>
    </>
  );
}
