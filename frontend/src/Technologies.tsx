import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Search, Eye, ArrowRight } from "lucide-react";
import { api, type Technology, type Page } from "./api";
import { Header, ErrorBox, Empty, useData, Badge } from "./shared";
import { Pagination, Skeleton, useDebounced } from "./ui";
import { Products } from "./Products";
export const ecosystems = [
  "npm",
  "PyPI",
  "Maven",
  "Go",
  "crates.io",
  "NuGet",
  "Packagist",
  "RubyGems",
];
export function Technologies() {
  const [q, setQ] = useState("");
  const [eco, setEco] = useState("");
  const [page, setPage] = useState(1);
  const query = useDebounced(q);
  const qc = useQueryClient();
  const data = useData<Page<Technology>>(
    "technologies",
    `/technologies?q=${encodeURIComponent(query)}&ecosystem=${encodeURIComponent(eco)}&page=${page}`,
  );
  const [notice, setNotice] = useState("");
  const watch = useMutation({
    mutationFn: (t: Technology) =>
      api("/watchlist", "POST", { ecosystem: t.ecosystem, package: t.package }),
    onSuccess: (_, t) => {
      setNotice(t.package + " adicionado à watchlist");
      qc.invalidateQueries({ queryKey: ["watchlist"] });
    },
  });
  return (
    <>
      <Header
        eyebrow="VULNERABILITY INTELLIGENCE"
        title="Tecnologias e bibliotecas"
        description="Explore pacotes reconhecidos por identificadores estruturados nas fontes coletadas."
        action={
          <Link className="button secondary" to="/search">
            Pesquisar outro pacote <ArrowRight size={14} />
          </Link>
        }
      />
      <div className="ecosystem-tabs">
        <button
          className={!eco ? "active" : ""}
          onClick={() => {
            setEco("");
            setPage(1);
          }}
        >
          Todos
        </button>
        {ecosystems.map((e) => (
          <button
            key={e}
            className={eco === e ? "active" : ""}
            onClick={() => {
              setEco(e);
              setPage(1);
            }}
          >
            {e}
          </button>
        ))}
      </div>
      <div className="toolbar">
        <div className="search-field">
          <Search size={16} />
          <input
            aria-label="Pesquisar tecnologias"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setPage(1);
            }}
            placeholder="Pesquisar biblioteca…"
          />
        </div>
        <span className="muted">
          {data.data?.total ?? 0} identidades de pacote
        </span>
      </div>
      <ErrorBox error={data.error || watch.error} />
      {notice && (
        <div className="notice" role="status">
          {notice}
        </div>
      )}
      <section className="panel">
        {data.isPending ? (
          <Skeleton />
        ) : data.data?.items.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Biblioteca</th>
                  <th>Ecossistema</th>
                  <th>Vulnerabilidades</th>
                  <th>Última publicação</th>
                  <th>KEV</th>
                  <th>Monitoramento</th>
                </tr>
              </thead>
              <tbody>
                {data.data.items.map((t) => (
                  <tr key={t.ecosystem + ":" + t.package}>
                    <td>
                      <Link
                        to={
                          "/feed?package=" +
                          encodeURIComponent(t.package) +
                          "&ecosystem=" +
                          encodeURIComponent(t.ecosystem)
                        }
                      >
                        {t.package}
                      </Link>
                    </td>
                    <td>{t.ecosystem}</td>
                    <td>{t.vulnerabilities}</td>
                    <td>{t.last_published?.slice(0, 10) || "Não informada"}</td>
                    <td>{t.kev ? <Badge value="KEV" /> : "—"}</td>
                    <td>
                      <button
                        onClick={() => watch.mutate(t)}
                        disabled={watch.isPending}
                      >
                        <Eye size={14} />
                        Monitorar
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="Nenhuma tecnologia coletada neste filtro">
            Consulte um pacote no OSV ou sincronize os advisories do GitHub.
            Runtimes sem identidade de pacote não são associados apenas por
            nome.
          </Empty>
        )}
        <Pagination
          page={page}
          total={data.data?.total || 0}
          size={data.data?.page_size || 25}
          onChange={setPage}
        />
      </section>
      <Products />
    </>
  );
}
