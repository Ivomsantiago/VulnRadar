import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Search, Download, Boxes } from "lucide-react";
import { type Component, type Page, type Project } from "./api";
import { Header, Empty, ErrorBox, Badge, useData } from "./shared";
import { Skeleton, Pagination, useDebounced } from "./ui";
export function Inventory() {
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useState("");
  const search = useDebounced(q);
  const page = Number(params.get("page")) || 1;
  const filter = new URLSearchParams(params);
  filter.set("q", search);
  const data = useData<Page<Component>>("inventory", "/inventory?" + filter);
  const projects = useData<Project[]>("projects", "/projects");
  const set = (key: string, value: string) => {
    const p = new URLSearchParams(params);
    value ? p.set(key, value) : p.delete(key);
    if (key !== "page") p.delete("page");
    setParams(p);
  };
  return (
    <>
      <Header
        eyebrow="APPLICATION SECURITY"
        title="Inventário de componentes"
        description="Último inventário SCA de cada projeto e resultados OCI por imagem e mecanismo."
        action={
          <Link className="button secondary" to="/projects">
            Analisar repositório
          </Link>
        }
      />
      <div className="scope-banner">
        <Boxes size={17} />
        <span>Inventário observado</span>
        <p>
          O conjunto muda com o escopo e a cobertura de cada análise. Versões
          não resolvidas são reportadas no scan.
        </p>
      </div>
      <div className="toolbar">
        <select
          aria-label="Ordenar inventário"
          value={params.get("sort") || "package"}
          onChange={(e) => set("sort", e.target.value)}
        >
          <option value="package">Por componente</option>
          <option value="ecosystem">Por ecossistema</option>
          <option value="version">Por versão (texto)</option>
        </select>
        <select
          aria-label="Relação da dependência"
          value={params.get("direct") || ""}
          onChange={(e) => set("direct", e.target.value)}
        >
          <option value="">Todas as relações</option>
          <option value="true">Diretas</option>
          <option value="false">Transitivas</option>
        </select>
        <div className="search-field">
          <Search size={16} />
          <input
            aria-label="Pesquisar componentes"
            placeholder="Nome do componente…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <select
          aria-label="Filtrar projeto"
          value={params.get("project_id") || ""}
          onChange={(e) => set("project_id", e.target.value)}
        >
          <option value="">Todos os projetos</option>
          {projects.data?.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
      </div>
      <ErrorBox error={data.error} />
      <section className="panel">
        {data.isPending ? (
          <Skeleton />
        ) : data.data?.items.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Componente</th>
                  <th>Versão</th>
                  <th>Ecossistema</th>
                  <th>Projeto</th>
                  <th>Relação</th>
                  <th>Cobertura</th>
                  <th>SBOM</th>
                </tr>
              </thead>
              <tbody>
                {data.data.items.map((c) => (
                  <tr key={c.id}>
                    <td>
                      <Link
                        to={
                          "/feed?package=" +
                          encodeURIComponent(c.package) +
                          "&ecosystem=" +
                          encodeURIComponent(c.ecosystem)
                        }
                      >
                        {c.package}
                      </Link>
                      <small className="table-sub mono">{c.file}</small>
                    </td>
                    <td className="mono">{c.version}</td>
                    <td>{c.ecosystem}</td>
                    <td>{c.project_name}</td>
                    <td>
                      {c.direct === null
                        ? "Não identificada"
                        : c.direct
                          ? "Direta"
                          : "Transitiva"}
                    </td>
                    <td>
                      <Badge
                        value={
                          c.query_status === "complete"
                            ? "success"
                            : c.query_status === "failed"
                              ? "failed"
                              : "unknown"
                        }
                      />
                    </td>
                    <td>
                      <a
                        href={`/api/scans/${c.scan_id}/export?format=cyclonedx`}
                        download
                        title="Exportar inventário desta execução"
                        className="icon-button"
                        aria-label={"Exportar SBOM do scan " + c.scan_id}
                      >
                        <Download size={15} />
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="Seu inventário começa em uma análise">
            Execute SCA com lockfiles resolvidos ou um arquivo CycloneDX JSON
            dentro de um projeto autorizado.
          </Empty>
        )}
        <Pagination
          page={page}
          total={data.data?.total || 0}
          size={data.data?.page_size || 25}
          onChange={(n) => set("page", String(n))}
        />
      </section>
    </>
  );
}
