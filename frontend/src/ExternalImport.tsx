import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api, type Project, type Scan } from "./api";
import { ErrorBox } from "./shared";

export function ExternalImport({
  projects,
  onScan,
}: {
  projects: Project[];
  onScan: (id: number) => void;
}) {
  const [project, setProject] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [pending, setPending] = useState(false);
  const qc = useQueryClient();
  return (
    <details className="panel padded">
      <summary>Importar análise SARIF externa</summary>
      <p>
        Receba resultados SARIF 2.1.0 de CodeQL, Datadog ou outros analisadores.
        Importações preservam evidências e não resolvem achados por ausência.
      </p>
      <form
        className="stack"
        onSubmit={async (event) => {
          event.preventDefault();
          setError(null);
          setPending(true);
          try {
            if (!file || file.size > 4_900_000)
              throw new Error("Selecione um arquivo SARIF de até 4,9 MB");
            const document = JSON.parse(await file.text());
            const scan = await api<Scan>(
              `/projects/${project}/imports/sarif`,
              "POST",
              { document },
            );
            await qc.invalidateQueries();
            onScan(scan.id);
          } catch (reason) {
            setError(
              reason instanceof Error
                ? reason
                : new Error("Não foi possível importar o documento"),
            );
          } finally {
            setPending(false);
          }
        }}
      >
        <label>
          Projeto da análise externa
          <select
            required
            value={project}
            onChange={(event) => setProject(event.target.value)}
          >
            <option value="">Selecione o projeto</option>
            {projects.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Arquivo SARIF
          <input
            type="file"
            accept=".sarif,.json,application/json"
            required
            onChange={(event) => setFile(event.target.files?.[0] || null)}
          />
        </label>
        <ErrorBox error={error} />
        <button className="primary" disabled={pending}>
          {pending ? "Importando…" : "Importar SARIF"}
        </button>
      </form>
    </details>
  );
}
