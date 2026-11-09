import { createContext, type ReactNode, useContext, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { ErrorBox } from "./shared";
import { Skeleton } from "./ui";
import { Button, Field } from "./base";

type Session = {
  authentication_required: boolean;
  principal: { name: string; role: string } | null;
};
const RoleContext = createContext("viewer");
export const useRole = () => useContext(RoleContext);
function clearWorkspacePreferences() {
  for (const name of Object.keys(localStorage))
    if (name.startsWith("vr-")) localStorage.removeItem(name);
}
export function AccessBoundary({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const session = useQuery({
    queryKey: ["access-session"],
    queryFn: () => api<Session>("/auth/session"),
    retry: false,
    refetchInterval: 30000,
  });
  const [key, setKey] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  if (session.isPending)
    return (
      <main className="panel padded">
        <Skeleton rows={3} />
      </main>
    );
  if (session.error)
    return (
      <main className="panel padded">
        <h1>Acesso indisponível</h1>
        <ErrorBox error={session.error} />
        <button onClick={() => session.refetch()}>Tentar novamente</button>
      </main>
    );
  if (session.data?.authentication_required && !session.data.principal)
    return (
      <main className="panel padded access-panel">
        <h1>Entrar no VulnRadar</h1>
        <p>
          Use sua chave pessoal fornecida pelo administrador. Não compartilhe
          esta chave.
        </p>
        <form
          className="stack"
          onSubmit={async (event) => {
            event.preventDefault();
            setPending(true);
            setError(null);
            const credential = key;
            setKey("");
            try {
              await api("/auth/login", "POST", { access_key: credential });
              clearWorkspacePreferences();
              qc.clear();
              await session.refetch();
            } catch (reason) {
              setError(
                reason instanceof Error
                  ? reason
                  : new Error("Não foi possível entrar"),
              );
            } finally {
              setPending(false);
            }
          }}
        >
          <Field label="Chave pessoal">
            <input
              type="password"
              name="access-key"
              autoComplete="off"
              required
              minLength={43}
              maxLength={43}
              value={key}
              onChange={(event) => setKey(event.target.value)}
            />
          </Field>
          <ErrorBox error={error} />
          <Button type="submit" className="primary" disabled={pending}>
            {pending ? "Autenticando…" : "Entrar"}
          </Button>
        </form>
      </main>
    );
  return (
    <RoleContext.Provider value={session.data?.principal?.role || "viewer"}>
      {session.data?.authentication_required && (
        <div className="access-session" role="region" aria-label="Sessão atual">
          <span>
            {session.data.principal?.name} · {session.data.principal?.role}
          </span>
          <button
            onClick={async () => {
              await api("/auth/logout", "POST");
              clearWorkspacePreferences();
              qc.clear();
              window.location.assign("/");
            }}
          >
            Sair
          </button>
        </div>
      )}
      {children}
    </RoleContext.Provider>
  );
}
