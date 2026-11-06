import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Search } from "lucide-react";
import { api, type Vulnerability } from "./api";
import { Empty, ErrorBox, Header } from "./shared";
import { VulnerabilityTable, Details } from "./Investigation";

export function PackageForm({
  onResult,
}: {
  onResult: (items: Vulnerability[], coverage: string) => void;
}) {
  const [ecosystem, setEco] = useState("npm");
  const [packageName, setPackage] = useState("");
  const [version, setVersion] = useState("");
  const mutation = useMutation({
    mutationFn: () =>
      api<{ items: Vulnerability[]; coverage: string }>(
        "/search/package",
        "POST",
        { ecosystem, package: packageName, version },
      ),
    onSuccess: (d) => onResult(d.items, d.coverage),
  });
  return (
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
          {[
            "npm",
            "PyPI",
            "Maven",
            "Go",
            "crates.io",
            "NuGet",
            "Packagist",
            "RubyGems",
          ].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
      </label>
      <label>
        Nome do pacote
        <input
          required
          value={packageName}
          onChange={(e) => setPackage(e.target.value)}
          placeholder="ex.: nome-do-pacote"
        />
      </label>
      <label>
        Versão instalada
        <input
          required
          value={version}
          onChange={(e) => setVersion(e.target.value)}
          placeholder="Versão exata"
        />
      </label>
      <button className="primary" disabled={mutation.isPending}>
        <Search size={16} />
        {mutation.isPending ? "Consultando…" : "Consultar OSV"}
      </button>
      <ErrorBox error={mutation.error} />
    </form>
  );
}

export function SearchPage() {
  const [items, setItems] = useState<Vulnerability[] | null>(null);
  const [coverage, setCoverage] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  return (
    <>
      <Header
        eyebrow="INVESTIGAÇÃO"
        title="Busca de pacotes e versões"
        description="Consulte a versão instalada nas evidências da base OSV."
      />
      <section className="panel padded">
        <h2>Avaliar uma dependência</h2>
        <p className="muted">
          Informe o nome utilizado pelo gerenciador de pacotes e a versão exata.
        </p>
        <PackageForm
          onResult={(i, c) => {
            setItems(i);
            setCoverage(c);
          }}
        />
      </section>
      {items && (
        <section className="panel">
          <div className="panel-heading">
            <h2>{items.length} advisories encontrados</h2>
          </div>
          {items.length ? (
            <VulnerabilityTable items={items} onSelect={setSelected} />
          ) : (
            <Empty title="Nenhuma correspondência retornada">
              A consulta foi concluída no OSV. Isso não comprova ausência de
              falhas.
            </Empty>
          )}
          <div className="panel-note">{coverage}</div>
        </section>
      )}
      {selected && <Details id={selected} close={() => setSelected(null)} />}
    </>
  );
}
