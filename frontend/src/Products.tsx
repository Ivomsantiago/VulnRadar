import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type Page } from "./api";
import { ErrorBox, Empty, useData, formatDate } from "./shared";
import { Pagination, Skeleton } from "./ui";
import { Details } from "./Investigation";
type Product = {
  vendor: string;
  product: string;
  version: string;
  vulnerability_id: string;
  source: string;
  modified: string | null;
  version_match: string;
  conditional: boolean;
  cpe: string;
};
export function Products() {
  const [draft, setDraft] = useState({ vendor: "", product: "", version: "" });
  const [filters, setFilters] = useState(draft);
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<string | null>(null);
  const [notice, setNotice] = useState("");
  const qc = useQueryClient();
  const query = new URLSearchParams({ ...filters, page: String(page) });
  const data = useData<
    Page<Product> & {
      source_status: string;
      last_updated: string | null;
      scope: string;
    }
  >("products", "/products?" + query);
  const watch = useMutation({
    mutationFn: () =>
      api("/product-watches", "POST", { ...filters, alerts_enabled: true }),
    onSuccess: () => {
      setNotice("Produto e versão adicionados ao monitoramento NVD.");
      qc.invalidateQueries({ queryKey: ["product-watches"] });
    },
  });
  return (
    <section className="panel padded product-search">
      <h2>Produtos, runtimes e versões por CPE</h2>
      <p>
        Identidades estruturadas do NVD: Node.js, Java e outros runtimes são
        tratados como produtos.
      </p>
      <form
        className="stack"
        onSubmit={(e) => {
          e.preventDefault();
          setFilters(draft);
          setPage(1);
          setNotice("");
        }}
      >
        <div className="form-grid">
          {(
            [
              ["vendor", "Fornecedor CPE"],
              ["product", "Produto CPE"],
              ["version", "Versão do produto"],
            ] as const
          ).map(([key, label]) => (
            <label key={key}>
              {label}
              <input
                maxLength={key === "version" ? 100 : 200}
                value={draft[key]}
                onChange={(e) => setDraft({ ...draft, [key]: e.target.value })}
              />
            </label>
          ))}
        </div>
        <div className="button-row">
          <button className="primary">Consultar produtos</button>
          <button
            type="button"
            disabled={
              !filters.vendor ||
              !filters.product ||
              !filters.version ||
              watch.isPending
            }
            onClick={() => watch.mutate()}
          >
            Monitorar esta versão
          </button>
        </div>
      </form>
      <ErrorBox error={data.error || watch.error} />
      {notice && <p role="status">{notice}</p>}
      <p className="field-hint">
        NVD: {data.data?.source_status || "não consultado"} · Última coleta:{" "}
        {formatDate(data.data?.last_updated)}
      </p>
      {data.isPending ? (
        <Skeleton />
      ) : data.data?.items.length ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Fornecedor / produto</th>
                <th>Advisory</th>
                <th>Aplicabilidade da versão</th>
                <th>Fonte / atualização</th>
              </tr>
            </thead>
            <tbody>
              {data.data.items.map((p, i) => (
                <tr key={p.cpe + p.vulnerability_id + i}>
                  <td>
                    {p.vendor} / {p.product}
                    <small className="table-sub">
                      {p.version === "*"
                        ? "Intervalo definido pelo advisory"
                        : p.version}
                    </small>
                  </td>
                  <td>
                    <button onClick={() => setSelected(p.vulnerability_id)}>
                      {p.vulnerability_id}
                    </button>
                  </td>
                  <td>
                    {p.version_match === "affected"
                      ? "Correspondência de versão"
                      : "Desconhecida — investigar condições"}
                    {p.conditional && (
                      <small className="table-sub">
                        Depende de condições de plataforma
                      </small>
                    )}
                  </td>
                  <td>
                    NVD
                    <small className="table-sub">
                      {formatDate(p.modified)}
                    </small>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Empty title="Nenhum CPE correspondente na base coletada">
          Sincronize o NVD ou ajuste fornecedor/produto. Ausência de
          correspondência não comprova segurança.
        </Empty>
      )}
      <p className="field-hint">{data.data?.scope}</p>
      <Pagination
        page={page}
        total={data.data?.total || 0}
        size={25}
        onChange={setPage}
      />
      {selected && <Details id={selected} close={() => setSelected(null)} />}
    </section>
  );
}

type ProductWatch = {
  id: number;
  vendor: string;
  product: string;
  version: string;
  alerts_enabled: boolean;
};
export function ProductWatches() {
  const data = useData<ProductWatch[]>("product-watches", "/product-watches");
  const [draft, setDraft] = useState({ vendor: "", product: "", version: "" });
  const [notice, setNotice] = useState("");
  const qc = useQueryClient();
  const add = useMutation({
    mutationFn: () => api("/product-watches", "POST", draft),
    onSuccess: () => {
      setDraft({ vendor: "", product: "", version: "" });
      qc.invalidateQueries();
      setNotice("Monitoramento salvo.");
    },
  });
  const remove = useMutation({
    mutationFn: (id: number) => api(`/product-watches/${id}`, "DELETE"),
    onSuccess: () => qc.invalidateQueries(),
  });
  const check = useMutation({
    mutationFn: (id: number) =>
      api<{ items: Product[]; scope: string }>(
        `/product-watches/${id}/check`,
        "POST",
      ),
    onSuccess: (result) => {
      setNotice(
        `${result.items.filter((p) => p.version_match === "affected").length} correspondências; ${result.items.filter((p) => p.version_match === "unknown").length} com aplicabilidade desconhecida. ${result.scope}`,
      );
      qc.invalidateQueries();
    },
  });
  return (
    <section className="panel padded product-search">
      <h2>Monitoramento de produtos e runtimes</h2>
      <p>
        Verificado automaticamente após sincronização NVD; alertas preservam a
        fonte e a versão monitorada.
      </p>
      <form
        className="stack"
        onSubmit={(e) => {
          e.preventDefault();
          add.mutate();
        }}
      >
        <div className="form-grid">
          {(
            [
              ["vendor", "Fornecedor monitorado"],
              ["product", "Produto monitorado"],
              ["version", "Versão monitorada"],
            ] as const
          ).map(([key, label]) => (
            <label key={key}>
              {label}
              <input
                required
                maxLength={key === "version" ? 100 : 200}
                value={draft[key]}
                onChange={(e) => setDraft({ ...draft, [key]: e.target.value })}
              />
            </label>
          ))}
        </div>
        <button className="primary" disabled={add.isPending}>
          Adicionar produto
        </button>
      </form>
      <ErrorBox
        error={data.error || add.error || remove.error || check.error}
      />
      {notice && <p role="status">{notice}</p>}
      {data.data?.length ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Produto</th>
                <th>Versão</th>
                <th>Alertas</th>
                <th>Ações</th>
              </tr>
            </thead>
            <tbody>
              {data.data.map((p) => (
                <tr key={p.id}>
                  <td>
                    {p.vendor} / {p.product}
                  </td>
                  <td>{p.version}</td>
                  <td>{p.alerts_enabled ? "Ativos" : "Desativados"}</td>
                  <td>
                    <div className="button-row">
                      <button
                        disabled={check.isPending}
                        onClick={() => check.mutate(p.id)}
                      >
                        Verificar produto
                      </button>
                      <button
                        aria-label={`Remover produto ${p.product}`}
                        disabled={remove.isPending}
                        onClick={() => remove.mutate(p.id)}
                      >
                        Remover
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Empty title="Nenhum produto monitorado" />
      )}
    </section>
  );
}
