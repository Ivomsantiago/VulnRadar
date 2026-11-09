import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { ErrorBox } from "./shared";

export function VexPanel({ findingId }: { findingId: number }) {
  const qc = useQueryClient();
  const [file, setFile] = useState<File | null>(null);
  const [format, setFormat] = useState("openvex");
  const [apply, setApply] = useState(false);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<Error | null>(null);
  const [pending, setPending] = useState(false);
  const [saved, setSaved] = useState(false);
  return (
    <details className="evidence-block">
      <summary>Declaração VEX de não afetação</summary>
      <p>
        A declaração deve corresponder ao advisory e à versão PURL instalada.
        Importar não aplica uma decisão automaticamente. VEX expressa uma
        avaliação, sem comprovar explorabilidade.
      </p>
      <form
        className="stack"
        onSubmit={async (event) => {
          event.preventDefault();
          setError(null);
          setPending(true);
          setSaved(false);
          try {
            if (!file || file.size > 4_900_000)
              throw new Error("Selecione um VEX JSON de até 4,9 MB");
            await api(`/findings/${findingId}/vex`, "POST", {
              document: JSON.parse(await file.text()),
              format,
              apply_decision: apply,
              reason,
            });
            await qc.invalidateQueries();
            setSaved(true);
          } catch (value) {
            setError(
              value instanceof Error
                ? value
                : new Error("Importação VEX falhou"),
            );
          } finally {
            setPending(false);
          }
        }}
      >
        <label>
          Formato VEX
          <select
            value={format}
            onChange={(event) => setFormat(event.target.value)}
          >
            <option value="openvex">OpenVEX 0.2.0</option>
            <option value="cyclonedx">CycloneDX VEX 1.5</option>
          </select>
        </label>
        <label>
          Arquivo VEX
          <input
            type="file"
            accept=".json,application/json"
            required
            onChange={(event) => setFile(event.target.files?.[0] || null)}
          />
        </label>
        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={apply}
            onChange={(event) => setApply(event.target.checked)}
          />
          Aplicar “não aplicável” à triagem desta versão
        </label>
        {apply && (
          <label>
            Justificativa da decisão
            <input
              required
              minLength={3}
              maxLength={4000}
              value={reason}
              onChange={(event) => setReason(event.target.value)}
            />
          </label>
        )}
        <ErrorBox error={error} />
        <button disabled={pending}>
          {pending ? "Importando…" : "Registrar VEX"}
        </button>
        {saved && (
          <p role="status">
            Declaração registrada. A identidade do revisor foi incluída na
            auditoria.
          </p>
        )}
      </form>
      <div className="button-row">
        <a
          href={`/api/findings/${findingId}/vex?format=openvex`}
          download={`finding-${findingId}-openvex.json`}
        >
          Exportar OpenVEX aplicado
        </a>
        <a
          href={`/api/findings/${findingId}/vex?format=cyclonedx`}
          download={`finding-${findingId}-vex.cdx.json`}
        >
          Exportar CycloneDX VEX aplicado
        </a>
      </div>
      <p className="field-hint">
        A exportação exige VEX aplicado e triagem ainda não aplicável.
        Justificativas sem conversão inequívoca precisam permanecer em OpenVEX.
      </p>
    </details>
  );
}
