import React from "react";
import { useData, ErrorBox, Header } from "./shared";

export function SettingsPage() {
  const { data, error } = useData<Record<string, unknown>>(
    "settings",
    "/settings",
  );
  return (
    <>
      <Header
        eyebrow="SISTEMA"
        title="Configurações"
        description="Configuração efetiva da instância. Credenciais nunca são retornadas."
      />
      <ErrorBox error={error} />
      <section className="panel padded">
        <h2>Ambiente local</h2>
        <p className="muted">
          Defina variáveis VULNRADAR_ no arquivo .env local ou no ambiente do
          processo e reinicie o backend. Não armazene credenciais no Git.
        </p>
        <dl className="settings-list">
          {data &&
            Object.entries(data).map(([key, value]) => (
              <React.Fragment key={key}>
                <dt>{key}</dt>
                <dd>
                  {typeof value === "boolean"
                    ? value
                      ? "Sim"
                      : "Não"
                    : Array.isArray(value)
                      ? value.join(", ") || "Nenhuma"
                      : String(value)}
                </dd>
              </React.Fragment>
            ))}
        </dl>
      </section>
    </>
  );
}
