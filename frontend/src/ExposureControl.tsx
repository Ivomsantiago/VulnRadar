import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api, type Project } from "./api";
import { ErrorBox } from "./shared";

export function ExposureControl({ project }: { project: Project }) {
  const qc = useQueryClient();
  const [error, setError] = useState<Error | null>(null);
  const [pending, setPending] = useState(false);
  return (
    <details>
      <summary>Contexto de exposição</summary>
      <label>
        Exposição declarada da aplicação
        <select
          disabled={pending}
          value={
            project.internet_exposed == null
              ? "unknown"
              : String(project.internet_exposed)
          }
          onChange={async (event) => {
            const value = event.target.value;
            setPending(true);
            setError(null);
            try {
              await api(`/projects/${project.id}/exposure`, "PATCH", {
                internet_exposed: value === "unknown" ? null : value === "true",
              });
              await qc.invalidateQueries();
            } catch (reason) {
              setError(
                reason instanceof Error
                  ? reason
                  : new Error("Não foi possível salvar o contexto"),
              );
            } finally {
              setPending(false);
            }
          }}
        >
          <option value="unknown">Não informada</option>
          <option value="true">Exposta externamente</option>
          <option value="false">Somente interna</option>
        </select>
      </label>
      <p className="field-hint">
        Declaração administrativa auditada, sem detecção automática. Novas
        análises registram este contexto.
      </p>
      <ErrorBox error={error} />
    </details>
  );
}
