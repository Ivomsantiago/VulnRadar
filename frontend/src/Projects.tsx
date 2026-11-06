import { useState } from "react";
import { useQueryClient, useMutation } from "@tanstack/react-query";
import { FolderGit2, X, Plus } from "lucide-react";
import { api, type Project, type Scan } from "./api";
import { formatDate, useData, Empty, ErrorBox, Badge, Header } from "./shared";

export function Projects() {
  const qc = useQueryClient();
  const projects = useData<Project[]>("projects", "/projects");
  const scans = useData<Scan[]>("scans", "/scans");
  const [name, setName] = useState("");
  const [path, setPath] = useState("");
  const [adding, setAdding] = useState(false);
  const [selected, setSelected] = useState<Scan | null>(null);
  const mutation = useMutation({
    mutationFn: () => api("/projects", "POST", { name, path }),
    onSuccess: () => {
      qc.invalidateQueries();
      setAdding(false);
    },
  });
  const scan = useMutation({
    mutationFn: ({ id, kind }: { id: number; kind: string }) =>
      api(`/projects/${id}/scans/${kind}`, "POST"),
    onSuccess: () => qc.invalidateQueries(),
  });
  return (
    <>
      <Header
        eyebrow="APPLICATION SECURITY"
        title="Repositórios e análises"
        description="Inventário e análise estática sem executar o código do projeto."
        action={
          <button className="primary" onClick={() => setAdding(!adding)}>
            <Plus size={16} />
            Cadastrar repositório
          </button>
        }
      />
      <ErrorBox error={projects.error || scans.error || scan.error} />
      {adding && (
        <section className="panel padded">
          <p>
            O caminho deve estar em uma raiz autorizada na configuração do
            backend.
          </p>
          <form
            className="package-form"
            onSubmit={(e) => {
              e.preventDefault();
              mutation.mutate();
            }}
          >
            <label>
              Nome
              <input
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </label>
            <label>
              Caminho absoluto
              <input
                required
                value={path}
                onChange={(e) => setPath(e.target.value)}
              />
            </label>
            <button className="primary">Cadastrar</button>
            <ErrorBox error={mutation.error} />
          </form>
        </section>
      )}
      <section className="panel">
        <div className="panel-heading">
          <h2>Projetos autorizados</h2>
          <span className="chip">{projects.data?.length || 0} projetos</span>
        </div>
        {projects.data?.length ? (
          projects.data.map((p) => (
            <div className="project-row" key={p.id}>
              <FolderGit2 size={22} />
              <div>
                <strong>{p.name}</strong>
                <small>{p.path}</small>
              </div>
              <button
                disabled={scan.isPending}
                onClick={() => scan.mutate({ id: p.id, kind: "sca" })}
              >
                Analisar SCA
              </button>
              <button
                disabled={scan.isPending}
                onClick={() => scan.mutate({ id: p.id, kind: "sast" })}
              >
                Analisar SAST
              </button>
            </div>
          ))
        ) : (
          <Empty title="Conecte seu primeiro repositório">
            Configure uma raiz autorizada e cadastre o diretório de um projeto
            local.
          </Empty>
        )}
      </section>
      <section className="panel">
        <div className="panel-heading">
          <h2>Histórico de execuções</h2>
          <span className="muted">Worker local · concorrência 1</span>
        </div>
        {scans.data?.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Execução</th>
                  <th>Motor</th>
                  <th>Estado</th>
                  <th>Achados</th>
                  <th>Data</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {scans.data.map((s) => (
                  <tr key={s.id}>
                    <td>
                      #{s.id} · projeto {s.project_id}
                    </td>
                    <td>{s.kind.toUpperCase()}</td>
                    <td>
                      <Badge value={s.status} />
                    </td>
                    <td>{s.result.findings?.length ?? "—"}</td>
                    <td>{formatDate(s.created_at)}</td>
                    <td>
                      <button onClick={() => setSelected(s)}>Investigar</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="Nenhuma análise executada" />
        )}
      </section>
      {selected && (
        <div className="overlay" onClick={() => setSelected(null)}>
          <section
            role="dialog"
            aria-modal="true"
            aria-label="Resultado da análise"
            className="drawer"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              aria-label="Fechar resultado"
              onClick={() => setSelected(null)}
            >
              <X size={18} />
            </button>
            <h1>Análise #{selected.id}</h1>
            <Badge value={selected.status} />
            <p>Resultado e limitações de cobertura</p>
            <div className="button-row">
              <a
                className="button"
                href={`/api/scans/${selected.id}/export?format=json`}
                download
              >
                JSON
              </a>
              <a
                className="button"
                href={`/api/scans/${selected.id}/export?format=${selected.kind === "sca" ? "cyclonedx" : "sarif"}`}
                download
              >
                {selected.kind === "sca" ? "CycloneDX" : "SARIF"}
              </a>
            </div>
            <pre>{JSON.stringify(selected.result, null, 2)}</pre>
          </section>
        </div>
      )}
    </>
  );
}
