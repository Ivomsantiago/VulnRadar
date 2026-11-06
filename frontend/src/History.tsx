import { useState } from "react";
import { Link } from "react-router-dom";
import { Bell, History, ArrowRight } from "lucide-react";
import { type Activity as Event, type Scan, type SyncRun } from "./api";
import { Header, Empty, ErrorBox, Badge, formatDate, useData } from "./shared";
import { Tabs, Skeleton } from "./ui";
export function HistoryPage({ alerts = false }: { alerts?: boolean }) {
  const [tab, setTab] = useState("events");
  const data = useData<Event[]>(
    "activity",
    alerts ? "/activity?kind=alert" : "/activity",
  );
  const jobs = useData<Scan[]>("scans", "/scans");
  const syncs = useData<SyncRun[]>("sync-runs", "/sync-runs");
  const deliveries = useData<
    {
      id: number;
      activity_id: number;
      status: string;
      attempts: number;
      last_attempt: string | null;
      error: string | null;
    }[]
  >("notification-deliveries", "/notification-deliveries");
  const [selectedKind, setKind] = useState("all");
  const [severity, setSeverity] = useState("all");
  const [project, setProject] = useState("all");
  const events = (data.data || []).filter(
    (e) =>
      selectedKind === "all" ||
      e.kind === selectedKind ||
      String(e.data.source) === selectedKind,
  );
  const filteredEvents = events.filter(
    (e) =>
      (severity === "all" ||
        String(e.data.severity || "UNKNOWN") === severity) &&
      (project === "all" || String(e.data.project_id) === project),
  );
  const timeline = (
    <>
      {alerts && (
        <div className="toolbar">
          <select
            aria-label="Filtrar alertas por fonte"
            value={selectedKind}
            onChange={(e) => setKind(e.target.value)}
          >
            <option value="all">Todas as fontes e projetos</option>
            {[
              ...new Set(
                (data.data || []).map((e) => String(e.data.source || e.kind)),
              ),
            ].map((k) => (
              <option key={k}>{k}</option>
            ))}
          </select>
          <span className="muted">
            {events.length} eventos no histórico recente
          </span>
        </div>
      )}
      {data.isPending ? (
        <Skeleton />
      ) : filteredEvents.length ? (
        <div className="compact-timeline">
          {filteredEvents.map((e) => (
            <div key={e.id}>
              <span className="timeline-dot" />
              <div>
                <b>{String(e.data.reason || e.kind)}</b>
                <small>{e.subject}</small>
                {e.data.project_id != null && (
                  <Link to={"/priorities?project_id=" + e.data.project_id}>
                    Projeto #{String(e.data.project_id)}{" "}
                    <ArrowRight size={12} />
                  </Link>
                )}
                {e.data.finding_id != null && (
                  <span className="muted">
                    {" "}
                    · Achado #{String(e.data.finding_id)}
                  </span>
                )}
              </div>
              <time>{formatDate(e.created_at)}</time>
            </div>
          ))}
        </div>
      ) : (
        <Empty
          title={alerts ? "Nenhum alerta registrado" : "Ainda não há eventos"}
        >
          Novas correspondências, alterações de triagem e análises aparecerão
          aqui com seus estados reais.
        </Empty>
      )}
    </>
  );
  return (
    <>
      <Header
        eyebrow={alerts ? "GESTÃO / NOTIFICAÇÕES" : "PLATAFORMA / OPERAÇÕES"}
        title={alerts ? "Central de alertas" : "Histórico e jobs"}
        description={
          alerts
            ? "Novas evidências para investigar, sem transformar avisos em exploração confirmada."
            : "Execuções, cobertura e decisões preservadas para rastreabilidade."
        }
      />
      <ErrorBox error={data.error || jobs.error || syncs.error} />
      <section className="panel">
        {alerts ? (
          <Tabs
            value={tab}
            onChange={setTab}
            items={[
              { id: "events", label: "Alertas", content: timeline },
              {
                id: "deliveries",
                label: "Entregas por webhook",
                count: deliveries.data?.length || 0,
                content: deliveries.data?.length ? (
                  <div className="table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>Evento</th>
                          <th>Estado</th>
                          <th>Tentativas</th>
                          <th>Última tentativa</th>
                          <th>Resultado</th>
                        </tr>
                      </thead>
                      <tbody>
                        {deliveries.data.map((d) => (
                          <tr key={d.id}>
                            <td>#{d.activity_id}</td>
                            <td>
                              <Badge value={d.status} />
                            </td>
                            <td>{d.attempts}</td>
                            <td>{formatDate(d.last_attempt)}</td>
                            <td>{d.error || "—"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <Empty title="Nenhuma entrega externa registrada">
                    O webhook é opcional e exige destino HTTPS autorizado na
                    instalação. Alertas locais continuam funcionando sem esse
                    serviço.
                  </Empty>
                ),
              },
            ]}
          />
        ) : (
          <Tabs
            value={tab}
            onChange={setTab}
            items={[
              { id: "events", label: "Atividade", content: timeline },
              {
                id: "jobs",
                label: "Análises",
                count: jobs.data?.length || 0,
                content: jobs.data?.length ? (
                  <div className="table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>Execução</th>
                          <th>Projeto</th>
                          <th>Tipo</th>
                          <th>Estado</th>
                          <th>Início</th>
                          <th>Conclusão</th>
                          <th>Ações</th>
                        </tr>
                      </thead>
                      <tbody>
                        {jobs.data.map((j) => (
                          <tr key={j.id}>
                            <td>#{j.id}</td>
                            <td>#{j.project_id}</td>
                            <td>{j.kind.toUpperCase()}</td>
                            <td>
                              <Badge value={j.status} />
                            </td>
                            <td>{formatDate(j.created_at)}</td>
                            <td>{formatDate(j.completed_at)}</td>
                            <td>
                              <Link to={"/projects?scan=" + j.id}>
                                Resultado <ArrowRight size={13} />
                              </Link>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <Empty title="Nenhum job registrado" />
                ),
              },
              {
                id: "sync",
                label: "Sincronizações",
                count: syncs.data?.length || 0,
                content: syncs.data?.length ? (
                  <div className="table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>Fonte</th>
                          <th>Estado</th>
                          <th>Início</th>
                          <th>Duração</th>
                          <th>Novos</th>
                          <th>Atualizados</th>
                          <th>Páginas</th>
                        </tr>
                      </thead>
                      <tbody>
                        {syncs.data.map((s) => (
                          <tr key={s.id}>
                            <td>{s.source.toUpperCase()}</td>
                            <td>
                              <Badge value={s.status} />
                            </td>
                            <td>{formatDate(s.started_at)}</td>
                            <td>
                              {s.duration_ms == null
                                ? "—"
                                : (s.duration_ms / 1000).toFixed(1) + "s"}
                            </td>
                            <td>{s.source === "osv" ? "—" : s.new_count}</td>
                            <td>
                              {s.source === "osv" ? "—" : s.updated_count}
                            </td>
                            <td>{s.source === "osv" ? "—" : s.pages}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <Empty title="Nenhuma sincronização registrada" />
                ),
              },
            ]}
          />
        )}
      </section>
    </>
  );
}
