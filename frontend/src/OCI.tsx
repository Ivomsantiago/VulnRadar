import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, type Project, type Scan } from "./api";
import { Header, ErrorBox, Empty, Badge, useData, formatDate } from "./shared";
import { ScanDetails } from "./Projects";
import { Skeleton } from "./ui";

type Engines = { trivy: boolean; grype: boolean; oci_registries: string[] };
export function OCI() {
  const engines = useData<Engines>("engines", "/engines");
  const projects = useData<Project[]>("projects", "/projects");
  const scans = useData<Scan[]>("scans", "/scans");
  const [project, setProject] = useState("");
  const [image, setImage] = useState("");
  const [engine, setEngine] = useState("trivy");
  const [selected, setSelected] = useState<number | null>(null);
  const qc = useQueryClient();
  const run = useMutation({
    mutationFn: () =>
      api<Scan>(`/projects/${project}/oci`, "POST", { image, engine }),
    onSuccess: (scan) => {
      qc.invalidateQueries();
      setSelected(scan.id);
    },
  });
  const available =
    engine === "trivy" ? engines.data?.trivy : engines.data?.grype;
  return (
    <>
      <Header
        eyebrow="ANÁLISES / IMAGENS"
        title="Imagens OCI"
        description="Analise dependências de sistema e bibliotecas das camadas de imagens sem iniciar containers."
      />
      <ErrorBox
        error={engines.error || projects.error || scans.error || run.error}
      />
      <section className="panel padded">
        <h2>Analisar imagem</h2>
        {engines.isPending ? (
          <Skeleton />
        ) : (
          <>
            <div className="button-row">
              <Badge
                value={engines.data?.trivy ? "available" : "unavailable"}
              />{" "}
              Trivy{" "}
              <Badge
                value={engines.data?.grype ? "available" : "unavailable"}
              />{" "}
              Grype
            </div>
            {!engines.data?.trivy && !engines.data?.grype && (
              <div className="notice">
                Instale Trivy ou Grype no servidor para habilitar OCI. As
                análises SCA e SAST continuam disponíveis.{" "}
                <Link to="/settings">Ver configuração</Link>
              </div>
            )}
            {projects.data?.length ? (
              <form
                className="stack"
                onSubmit={(e) => {
                  e.preventDefault();
                  run.mutate();
                }}
              >
                <div className="form-grid">
                  <label>
                    Projeto
                    <select
                      aria-label="Projeto"
                      required
                      value={project}
                      onChange={(e) => setProject(e.target.value)}
                    >
                      <option value="">Selecionar projeto</option>
                      {projects.data.map((p) => (
                        <option value={p.id} key={p.id}>
                          {p.name}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Mecanismo
                    <select
                      aria-label="Mecanismo"
                      value={engine}
                      onChange={(e) => setEngine(e.target.value)}
                    >
                      <option value="trivy">Trivy</option>
                      <option value="grype">Grype</option>
                    </select>
                  </label>
                </div>
                <label>
                  Referência da imagem
                  <input
                    required
                    maxLength={500}
                    placeholder="docker.io/library/alpine:3.22.0"
                    value={image}
                    onChange={(e) => setImage(e.target.value)}
                  />
                </label>
                <p className="field-hint">
                  Registros autorizados:{" "}
                  {engines.data?.oci_registries?.join(", ") || "não disponível"}
                  . Prefira digest SHA256 para reproduzir a análise. O mecanismo
                  acessa o registro e sua base de advisories; nenhum comando da
                  imagem é executado.
                </p>
                <button
                  className="primary"
                  disabled={!available || run.isPending}
                >
                  {run.isPending ? "Agendando…" : "Analisar imagem"}
                </button>
              </form>
            ) : (
              <Empty title="Cadastre um projeto para associar os resultados">
                <Link to="/projects">Abrir repositórios</Link>
              </Empty>
            )}
          </>
        )}
      </section>
      <section className="panel">
        <div className="panel-heading">
          <h2>Análises de imagens</h2>
          <Link to="/priorities?kind=oci">Investigar achados OCI</Link>
        </div>
        {scans.data?.some((s) => s.kind === "oci") ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Imagem</th>
                  <th>Mecanismo</th>
                  <th>Estado</th>
                  <th>Data</th>
                  <th>Resultado</th>
                </tr>
              </thead>
              <tbody>
                {scans.data
                  .filter((s) => s.kind === "oci")
                  .map((s) => (
                    <tr key={s.id}>
                      <td>
                        {s.result.image ||
                          s.result.request?.image ||
                          "Análise #" + s.id}
                      </td>
                      <td>
                        {s.result.engine || s.result.request?.engine || "—"}
                      </td>
                      <td>
                        <Badge value={s.status} />
                      </td>
                      <td>{formatDate(s.created_at)}</td>
                      <td>
                        <button onClick={() => setSelected(s.id)}>
                          Investigar
                        </button>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="Nenhuma imagem analisada" />
        )}
      </section>
      {selected && (
        <ScanDetails id={selected} close={() => setSelected(null)} />
      )}
    </>
  );
}
