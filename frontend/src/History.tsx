import { Bell, History } from "lucide-react";
import { type Activity as Event } from "./api";
import { formatDate, useData, Empty, ErrorBox, Badge, Header } from "./shared";

export function HistoryPage({ alerts = false }: { alerts?: boolean }) {
  const { data, error } = useData<Event[]>(
    "activity",
    alerts ? "/activity?kind=alert" : "/activity",
  );
  return (
    <>
      <Header
        eyebrow={alerts ? "GESTÃO" : "SISTEMA"}
        title={alerts ? "Central de alertas" : "Histórico operacional"}
        description={
          alerts
            ? "Novos advisories de alta severidade e inclusões no KEV."
            : "Eventos de sincronização, alterações de triagem e análises."
        }
      />
      <ErrorBox error={error} />
      <section className="panel">
        {data?.length ? (
          data.map((e) => (
            <div className="event-row" key={e.id}>
              <span className="source-logo">
                {alerts ? <Bell size={18} /> : <History size={18} />}
              </span>
              <div>
                <strong>{e.subject}</strong>
                <p>{String(e.data.reason || e.kind)}</p>
                <small>{formatDate(e.created_at)}</small>
              </div>
              <Badge value={String(e.data.status || e.kind)} />
            </div>
          ))
        ) : (
          <Empty
            title={alerts ? "Nenhum alerta registrado" : "Ainda não há eventos"}
          />
        )}
      </section>
    </>
  );
}
