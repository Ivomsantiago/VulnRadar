import { Link } from "react-router-dom";
import { type Scan } from "./api";
import { Header, ErrorBox, Empty, Badge, useData, formatDate } from "./shared";
import { ScanDetails } from "./Projects";
import { useState } from "react";

export function OCI() {
  const scans = useData<Scan[]>("scans", "/scans");
  const [selected, setSelected] = useState<number | null>(null);
  const history = scans.data?.filter((scan) => scan.kind === "oci") || [];
  return (
    <>
      <Header
        eyebrow="HISTÓRICO / COMPATIBILIDADE"
        title="Análises OCI anteriores"
        description="A execução de scanners de imagens foi descontinuada. Evidências existentes permanecem disponíveis para investigação."
      />
      <ErrorBox error={scans.error} />
      <section className="panel padded">
        <h2>Inteligência para suas aplicações</h2>
        <p>
          Consulte advisories, avalie versões de pacotes e monitore tecnologias
          com as fontes de inteligência integradas.
        </p>
        <div className="button-row">
          <Link to="/search" className="primary">
            Consultar pacote e versão
          </Link>
          <Link to="/feed" className="secondary">
            Investigar advisories
          </Link>
          <Link to="/inventory" className="secondary">
            Abrir inventário
          </Link>
        </div>
      </section>
      <section className="panel padded">
        <h2>Evidências preservadas</h2>
        {history.length ? (
          <ul>
            {history.map((scan) => (
              <li key={scan.id}>
                <button className="link" onClick={() => setSelected(scan.id)}>
                  Análise #{scan.id}
                </button>{" "}
                <Badge value={scan.status} /> {formatDate(scan.created_at)}
              </li>
            ))}
          </ul>
        ) : (
          <Empty
            title={
              scans.isPending
                ? "Carregando histórico…"
                : "Nenhuma análise OCI no histórico recente"
            }
          />
        )}
        <Link to="/priorities?kind=oci">Consultar achados históricos OCI</Link>
      </section>
      {selected !== null && (
        <ScanDetails id={selected} close={() => setSelected(null)} />
      )}
    </>
  );
}
