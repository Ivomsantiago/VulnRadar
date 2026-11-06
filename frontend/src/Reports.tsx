import { Download } from "lucide-react";
import { Header, ExportButtons } from "./shared";

export function Reports() {
  return (
    <>
      <Header
        eyebrow="GESTÃO"
        title="Relatórios e exportação"
        description="Exporte os dados coletados para investigação e documentação."
      />
      <section className="panel padded">
        <Download size={26} />
        <h2>Base de vulnerabilidades</h2>
        <p className="muted">
          Exportação dos registros coletados, até 50 mil entradas. CSV protegido
          contra fórmulas.
        </p>
        <ExportButtons />
      </section>
      <div className="notice">
        Exporte SARIF (SAST), CycloneDX (inventário SCA) e JSON de cada execução
        em Repositórios e análises → Investigar.
      </div>
    </>
  );
}
