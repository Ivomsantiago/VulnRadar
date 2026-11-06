export type SourceEvidence = {
  source: string;
  updated_at?: string | null;
  products?: {
    vendor: string;
    product: string;
    version: string;
    cpe: string;
    conditional: boolean;
  }[];
  packages: {
    ecosystem: string;
    package: string;
    ranges: unknown;
    versions?: string[];
    fixed: string[];
  }[];
  references: { url?: string }[];
  scores?: unknown;
  cwes?: unknown;
  mitigation?: string;
};
export function Evidence({ items }: { items: SourceEvidence[] }) {
  return (
    <div>
      {items.map((item, index) => (
        <section key={item.source + index} className="evidence-block">
          <h3>{item.source.toUpperCase()}</h3>
          <p className="field-hint">
            Última atualização informada:{" "}
            {item.updated_at || "Não informada pela fonte"}
          </p>
          {item.products?.map((product, index) => (
            <div className="evidence-package" key={product.cpe + index}>
              <strong>
                {product.vendor} / {product.product}
              </strong>
              <p>
                Versão CPE: {product.version} ·{" "}
                {product.conditional
                  ? "Condições de plataforma exigem investigação"
                  : "Condições do advisory"}
              </p>
              <details>
                <summary>Identificador e limites CPE</summary>
                <pre>{JSON.stringify(product, null, 2)}</pre>
              </details>
            </div>
          ))}
          {item.packages.map((p, i) => (
            <div key={p.package + i} className="evidence-package">
              <strong>{p.package}</strong>
              <small>{p.ecosystem}</small>
              <p>
                Versões corrigidas:{" "}
                {p.fixed.length
                  ? p.fixed.join(", ")
                  : "Não informadas pela fonte"}
              </p>
              <details>
                <summary>Intervalos e versões afetadas</summary>
                <pre>
                  {JSON.stringify(
                    { ranges: p.ranges, versions: p.versions },
                    null,
                    2,
                  )}
                </pre>
              </details>
            </div>
          ))}
          {item.mitigation && <p>Ação recomendada: {item.mitigation}</p>}
          <ul>
            {item.references
              .filter((r) => r.url && /^https?:\/\//i.test(r.url))
              .map((r, i) => (
                <li key={i}>
                  <a href={r.url} target="_blank" rel="noopener noreferrer">
                    {r.url}
                  </a>
                </li>
              ))}
          </ul>
          {item.scores != null && (
            <details>
              <summary>Métricas e vetores da fonte</summary>
              <pre>{JSON.stringify(item.scores, null, 2)}</pre>
            </details>
          )}
        </section>
      ))}
    </div>
  );
}
