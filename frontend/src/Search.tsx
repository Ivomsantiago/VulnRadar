import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { Search, PackageSearch } from "lucide-react";
import { api, type Vulnerability } from "./api";
import { Header, ErrorBox, Empty, Badge } from "./shared";
import { Skeleton } from "./ui";
import { VulnerabilityTable, Details } from "./Investigation";
import { ecosystems } from "./Technologies";
import { Products } from "./Products";
export function SearchPage() {
  const [params] = useSearchParams();
  const [ecosystem, setEco] = useState(params.get("ecosystem") || "npm");
  const [packageName, setPackage] = useState(params.get("package") || "");
  const [version, setVersion] = useState(params.get("version") || "");
  const [selected, setSelected] = useState<string | null>(null);
  const mutation = useMutation({
    mutationFn: () =>
      api<{
        items: Vulnerability[];
        status: string;
        coverage: string;
        query: { ecosystem: string; package: string; version: string | null };
      }>("/search/package", "POST", {
        ecosystem,
        package: packageName,
        version: version || null,
      }),
  });
  return (
    <>
      <Header
        eyebrow="VULNERABILITY INTELLIGENCE / PESQUISA"
        title="Busca de pacotes e versões"
        description="Uma consulta, com o contexto necessário para interpretar o resultado."
      />
      <section className="panel search-workbench">
        <div className="workbench-heading">
          <PackageSearch size={24} />
          <div>
            <h2>Avaliar componente</h2>
            <p>Pacotes arbitrários dos ecossistemas suportados pelo OSV</p>
          </div>
        </div>
        <form
          className="package-form"
          onSubmit={(e) => {
            e.preventDefault();
            mutation.mutate();
          }}
        >
          <label>
            Ecossistema
            <select value={ecosystem} onChange={(e) => setEco(e.target.value)}>
              {ecosystems.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </label>
          <label>
            Nome do pacote
            <input
              required
              maxLength={200}
              value={packageName}
              onChange={(e) => setPackage(e.target.value)}
              placeholder="Nome no gerenciador de pacotes"
            />
          </label>
          <label>
            Versão instalada
            <input
              maxLength={100}
              value={version}
              onChange={(e) => setVersion(e.target.value)}
              placeholder="Opcional · versão exata"
            />
          </label>
          <button className="primary" disabled={mutation.isPending}>
            <Search size={15} />
            {mutation.isPending ? "Consultando…" : "Consultar OSV"}
          </button>
        </form>
        <p className="field-hint">
          Sem versão, a consulta retorna advisories do pacote. Isso não
          representa correspondência com uma versão instalada. Node.js e Java
          runtime não são confundidos com bibliotecas npm/Maven.
        </p>
      </section>
      {mutation.error && (
        <>
          <div className="result-state incomplete">
            <Badge value="partial" />
            <span>Consulta incompleta</span>
            <p>Não é possível concluir ausência de vulnerabilidades.</p>
          </div>
          <ErrorBox error={mutation.error} />
        </>
      )}
      {mutation.isPending ? (
        <Skeleton rows={5} />
      ) : (
        mutation.data && (
          <section className="panel">
            <div className="result-heading">
              <div>
                <span className="eyebrow">RESULTADO DA AVALIAÇÃO</span>
                <h2>
                  {mutation.data.query.package}
                  <span className="version-label">
                    {mutation.data.query.version
                      ? "@" + mutation.data.query.version
                      : " · versão não informada"}
                  </span>
                </h2>
                <p>
                  {mutation.data.query.ecosystem} · {mutation.data.items.length}{" "}
                  advisories
                </p>
              </div>
              <Badge value="completed" />
            </div>
            <div className="result-state">
              <b>
                {!mutation.data.query.version
                  ? "Versão não identificada"
                  : mutation.data.items.length
                    ? "Versão afetada segundo advisory"
                    : "Nenhuma correspondência nas fontes consultadas"}
              </b>
              <p>{mutation.data.coverage}</p>
            </div>
            {mutation.data.items.length ? (
              <VulnerabilityTable
                items={mutation.data.items}
                onSelect={setSelected}
              />
            ) : (
              <Empty title="Nenhum advisory retornado">
                A consulta foi concluída no OSV. Falta de correspondências ou
                cobertura não é comprovação de segurança.
              </Empty>
            )}
          </section>
        )
      )}
      {!mutation.data && !mutation.isPending && !mutation.error && (
        <div className="search-guidance">
          <Search size={16} />
          <p>
            Procure CVE, GHSA, tecnologia ou repositório pela busca universal{" "}
            <kbd>Ctrl K</kbd>. Para avaliar uma versão, use os controles acima.
          </p>
        </div>
      )}
      <Products />
      {selected && <Details id={selected} close={() => setSelected(null)} />}
    </>
  );
}
