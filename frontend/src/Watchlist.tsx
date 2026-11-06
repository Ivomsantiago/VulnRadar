import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Eye,
  Plus,
  RefreshCw,
  Trash2,
  Settings2,
  ArrowRight,
  Bell,
} from "lucide-react";
import { api, type Watch, type Vulnerability, type Activity } from "./api";
import {
  Header,
  Empty,
  ErrorBox,
  Badge,
  useData,
  severityLabel,
  formatDate,
} from "./shared";
import { Modal, Skeleton } from "./ui";
import { ecosystems } from "./Technologies";
import { ProductWatches } from "./Products";
function WatchEditor({ item, close }: { item?: Watch; close: () => void }) {
  const qc = useQueryClient();
  const [ecosystem, setEco] = useState(item?.ecosystem || "npm");
  const [packageName, setPackage] = useState(item?.package || "");
  const [version, setVersion] = useState(item?.version || "");
  const [severity, setSeverity] = useState(item?.min_severity || "LOW");
  const [alerts, setAlerts] = useState(item?.alerts_enabled ?? true);
  const mutation = useMutation({
    mutationFn: () =>
      api("/watchlist" + (item ? "/" + item.id : ""), item ? "PATCH" : "POST", {
        ecosystem,
        package: packageName,
        version: version || null,
        min_severity: severity,
        alerts_enabled: alerts,
      }),
    onSuccess: () => {
      qc.invalidateQueries();
      close();
    },
  });
  return (
    <Modal
      title={item ? "Editar monitoramento" : "Adicionar pacote à watchlist"}
      onClose={close}
    >
      <form
        className="stack"
        onSubmit={(e) => {
          e.preventDefault();
          mutation.mutate();
        }}
      >
        <div className="form-grid">
          <label>
            Ecossistema
            <select value={ecosystem} onChange={(e) => setEco(e.target.value)}>
              {ecosystems.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </label>
          <label>
            Severidade mínima
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((s) => (
                <option key={s} value={s}>
                  {severityLabel[s]}
                </option>
              ))}
            </select>
          </label>
        </div>
        <label>
          Pacote
          <input
            autoFocus
            required
            maxLength={200}
            value={packageName}
            onChange={(e) => setPackage(e.target.value)}
            placeholder="Nome usado no gerenciador de pacotes"
          />
        </label>
        <label>
          Versão opcional
          <input
            maxLength={100}
            value={version}
            onChange={(e) => setVersion(e.target.value)}
            placeholder="Sem versão: acompanha advisories do pacote"
          />
        </label>
        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={alerts}
            onChange={(e) => setAlerts(e.target.checked)}
          />
          Alertar novas correspondências acima da severidade mínima
        </label>
        <ErrorBox error={mutation.error} />
        <button className="primary" disabled={mutation.isPending}>
          Salvar
        </button>
      </form>
    </Modal>
  );
}
export function Watchlist() {
  const qc = useQueryClient();
  const [editor, setEditor] = useState<Watch | null | undefined>();
  const [filter, setFilter] = useState("all");
  const [notice, setNotice] = useState("");
  const watches = useData<Watch[]>("watchlist", "/watchlist");
  const alerts = useData<Activity[]>("activity", "/activity?kind=alert");
  const check = useMutation({
    mutationFn: (id: number) =>
      api<{ items: Vulnerability[]; coverage: string }>(
        "/watchlist/" + id + "/check",
        "POST",
      ),
    onSuccess: (d) => {
      setNotice(`${d.items.length} advisories. ${d.coverage}`);
      qc.invalidateQueries();
    },
  });
  const remove = useMutation({
    mutationFn: (id: number) => api("/watchlist/" + id, "DELETE"),
    onSuccess: () => qc.invalidateQueries(),
  });
  const relevantAlerts =
    alerts.data?.filter((e) => e.subject.startsWith("watch:")) || [];
  const alerted = new Set(
    relevantAlerts.map((e) => Number(e.subject.split(":")[1])),
  );
  const items = (watches.data || []).filter(
    (w) =>
      filter === "all" ||
      (filter === "new" && alerted.has(w.id)) ||
      (filter === "kev" && (w.kev_count || 0) > 0),
  );
  return (
    <>
      <Header
        eyebrow="GESTÃO / MONITORAMENTO"
        title="Watchlist de tecnologias"
        description="Acompanhe os componentes relevantes, suas versões e novas correspondências."
        action={
          <button className="primary" onClick={() => setEditor(null)}>
            <Plus size={16} />
            Adicionar pacote
          </button>
        }
      />
      <ProductWatches />
      <div className="watch-summary">
        <div>
          <Eye size={18} />
          <span>
            <b>{watches.data?.length || 0}</b> tecnologias monitoradas
          </span>
        </div>
        <div>
          <Bell size={18} />
          <span>
            <b>{relevantAlerts.length}</b> alertas no histórico recente
          </span>
        </div>
        <Link to="/alerts">
          Abrir central de alertas <ArrowRight size={14} />
        </Link>
      </div>
      <div className="queue-tabs">
        <button
          className={filter === "all" ? "active" : ""}
          onClick={() => setFilter("all")}
        >
          Todas
        </button>
        <button
          className={filter === "new" ? "active" : ""}
          onClick={() => setFilter("new")}
        >
          Com correspondências recentes
        </button>
        <button
          className={filter === "history" ? "active" : ""}
          onClick={() => setFilter("history")}
        >
          Histórico de alertas
        </button>
        <button
          className={filter === "kev" ? "active" : ""}
          onClick={() => setFilter("kev")}
        >
          Com exploração conhecida
        </button>
      </div>
      <ErrorBox error={watches.error || check.error || remove.error} />
      {notice && (
        <div role="status" className="notice">
          {notice}
        </div>
      )}
      <section className="panel">
        {watches.isPending ? (
          <Skeleton />
        ) : filter === "history" ? (
          relevantAlerts.length ? (
            relevantAlerts.map((a) => (
              <div className="event-row" key={a.id}>
                <Bell size={16} />
                <div>
                  <b>{String(a.data.package || a.subject)}</b>
                  <p>{String(a.data.reason)}</p>
                  <small>{formatDate(a.created_at)}</small>
                </div>
                <Link
                  to={
                    "/feed?q=" +
                    encodeURIComponent(String(a.data.vulnerability || ""))
                  }
                >
                  Investigar
                </Link>
              </div>
            ))
          ) : (
            <Empty title="Nenhuma correspondência notificada" />
          )
        ) : items.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Tecnologia</th>
                  <th>Versão</th>
                  <th>Severidade mínima</th>
                  <th>Alertas</th>
                  <th>Investigar</th>
                  <th>Ações</th>
                </tr>
              </thead>
              <tbody>
                {items.map((w) => (
                  <tr key={w.id}>
                    <td>
                      <b>{w.package}</b>
                      <small className="table-sub">
                        {w.ecosystem} ·{" "}
                        {w.vulnerability_count == null
                          ? "Sem consulta registrada"
                          : `${w.vulnerability_count} advisories · ${w.kev_count || 0} KEV`}
                      </small>
                    </td>
                    <td className="mono">{w.version || "Não informada"}</td>
                    <td>
                      <Badge value={w.min_severity || "LOW"} />
                    </td>
                    <td>
                      {w.alerts_enabled === false
                        ? "Desabilitados"
                        : "Habilitados"}
                    </td>
                    <td>
                      <Link
                        to={
                          "/feed?package=" +
                          encodeURIComponent(w.package) +
                          "&ecosystem=" +
                          encodeURIComponent(w.ecosystem)
                        }
                      >
                        Advisories <ArrowRight size={13} />
                      </Link>
                    </td>
                    <td>
                      <div className="button-row">
                        <button
                          title="Consultar OSV agora"
                          aria-label={"Verificar " + w.package}
                          disabled={check.isPending}
                          onClick={() => check.mutate(w.id)}
                        >
                          <RefreshCw size={14} />
                        </button>
                        <button
                          aria-label={"Editar " + w.package}
                          onClick={() => setEditor(w)}
                        >
                          <Settings2 size={14} />
                        </button>
                        <button
                          aria-label={"Remover " + w.package}
                          disabled={remove.isPending}
                          onClick={() => remove.mutate(w.id)}
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="getting-started">
            <span className="project-icon">
              <Eye size={28} />
            </span>
            <h2>Monitore o que faz parte do seu software</h2>
            <p>
              Adicione um pacote usado pela sua equipe — por exemplo, uma
              biblioteca npm, um componente Maven ou um pacote PyPI. Os
              registros são consultados nas fontes, sem dados demonstrativos.
            </p>
            <button className="primary" onClick={() => setEditor(null)}>
              <Plus size={15} />
              Adicionar primeiro pacote
            </button>
          </div>
        )}
      </section>
      <div className="coverage-caption">
        Itens sem versão acompanham advisories do pacote e não confirmam que uma
        versão instalada esteja afetada. Consultas enviam apenas identidade e
        versão do componente.
      </div>
      {editor !== undefined && (
        <WatchEditor
          item={editor || undefined}
          close={() => setEditor(undefined)}
        />
      )}
    </>
  );
}
