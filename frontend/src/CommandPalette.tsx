import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  Search,
  ShieldAlert,
  FolderGit2,
  Boxes,
  ArrowRight,
} from "lucide-react";
import { api, type Vulnerability, type Project } from "./api";
import { Modal, Skeleton, useDebounced } from "./ui";
import { ErrorBox, Empty } from "./shared";
export function CommandPalette({
  close,
  onVulnerability,
}: {
  close: () => void;
  onVulnerability: (id: string) => void;
}) {
  const [q, setQ] = useState("");
  const query = useDebounced(q, 200);
  const result = useQuery({
    queryKey: ["universal", query],
    queryFn: ({ signal }) =>
      api<{
        vulnerabilities: Vulnerability[];
        projects: Project[];
        packages: { ecosystem: string; package: string }[];
      }>("/search/universal?q=" + encodeURIComponent(query), "GET", undefined, {
        signal,
      }),
    enabled: query.length >= 2,
  });
  return (
    <Modal title="Busca universal" onClose={close} wide>
      <div className="palette-search">
        <Search size={20} />
        <input
          autoFocus
          aria-label="Pesquisar no VulnRadar"
          placeholder="CVE, biblioteca, tecnologia ou repositório…"
          value={q}
          onChange={(event) => setQ(event.target.value)}
        />
        <kbd>ESC</kbd>
      </div>
      <ErrorBox error={result.error} />
      {query.length < 2 ? (
        <div className="palette-hint">
          <p>
            Digite pelo menos dois caracteres para pesquisar na base coletada.
          </p>
          <Link to="/search" onClick={close}>
            Consultar pacote e versão no OSV <ArrowRight size={14} />
          </Link>
        </div>
      ) : result.isPending ? (
        <Skeleton rows={3} />
      ) : (
        result.data && (
          <div className="palette-results">
            {[
              {
                key: "vulnerabilities",
                label: "Vulnerabilidades",
                icon: ShieldAlert,
                items: result.data.vulnerabilities.map((item) => ({
                  label: item.id,
                  context: item.title,
                  to: "/feed?q=" + encodeURIComponent(item.id),
                  id: item.id,
                })),
              },
              {
                key: "projects",
                label: "Repositórios",
                icon: FolderGit2,
                items: result.data.projects.map((item) => ({
                  label: item.name,
                  context: item.path,
                  to: "/projects?project=" + item.id,
                  id: null,
                })),
              },
              {
                key: "packages",
                label: "Tecnologias e bibliotecas",
                icon: Boxes,
                items: result.data.packages.map((item) => ({
                  label: item.package,
                  context: item.ecosystem,
                  to:
                    "/feed?package=" +
                    encodeURIComponent(item.package) +
                    "&ecosystem=" +
                    encodeURIComponent(item.ecosystem),
                  id: null,
                })),
              },
            ].map((group) => (
              <section key={group.key}>
                <h3>
                  {group.label} <span>{group.items.length}</span>
                </h3>
                {group.items.map((item, index) => (
                  <Link
                    key={item.label + index}
                    to={item.to}
                    onClick={(event) => {
                      close();
                      if (item.id) {
                        event.preventDefault();
                        onVulnerability(item.id);
                      }
                    }}
                  >
                    <group.icon size={17} />
                    <span>
                      <b>{item.label}</b>
                      <small>{item.context}</small>
                    </span>
                    <ArrowRight size={14} />
                  </Link>
                ))}
              </section>
            ))}
            {!result.data.vulnerabilities.length &&
              !result.data.projects.length &&
              !result.data.packages.length && (
                <Empty title="Nenhum resultado na base coletada">
                  Consulte um pacote no OSV ou revise os termos da pesquisa.
                </Empty>
              )}
          </div>
        )
      )}
    </Modal>
  );
}
