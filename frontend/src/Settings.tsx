import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { Header, ErrorBox, useData, Badge } from "./shared";
import { Skeleton } from "./ui";
type Preferences = { theme: string; density: string; epss_threshold: number };
function PreferencesForm({ value }: { value: Preferences }) {
  const qc = useQueryClient();
  const [theme, setTheme] = useState(value.theme);
  const [density, setDensity] = useState(value.density);
  const [epss, setEpss] = useState(value.epss_threshold);
  const mutation = useMutation({
    mutationFn: () =>
      api("/preferences", "PATCH", { theme, density, epss_threshold: epss }),
    onSuccess: () => {
      qc.invalidateQueries();
      document.documentElement.dataset.theme =
        theme === "system"
          ? matchMedia("(prefers-color-scheme: light)").matches
            ? "light"
            : "dark"
          : theme;
      localStorage.setItem("vr-table-density", JSON.stringify(density));
    },
  });
  return (
    <form
      className="stack"
      onSubmit={(e) => {
        e.preventDefault();
        mutation.mutate();
      }}
    >
      <div className="form-grid">
        <label>
          Tema visual
          <select value={theme} onChange={(e) => setTheme(e.target.value)}>
            <option value="dark">Escuro</option>
            <option value="light">Claro</option>
            <option value="system">Seguir sistema</option>
          </select>
        </label>
        <label>
          Densidade das tabelas
          <select value={density} onChange={(e) => setDensity(e.target.value)}>
            <option value="compact">Compacta</option>
            <option value="comfortable">Confortável</option>
          </select>
        </label>
      </div>
      <label>
        Limiar de referência EPSS (0 a 1)
        <input
          type="number"
          min="0"
          max="1"
          step="0.01"
          required
          value={epss}
          onChange={(e) => setEpss(Number(e.target.value))}
        />
      </label>
      <p className="field-hint">
        Referência de investigação, sem representar exploração confirmada ou
        risco preciso de uma aplicação.
      </p>
      <ErrorBox error={mutation.error} />
      <div>
        <button className="primary" disabled={mutation.isPending}>
          Salvar preferências
        </button>
      </div>
      {mutation.isSuccess && (
        <p className="success-text" role="status">
          Preferências salvas.
        </p>
      )}
    </form>
  );
}
function SchedulerForm() {
  const data = useData<{
    enabled: boolean;
    interval_minutes: number;
    last_started?: string;
  }>("scheduler", "/scheduler");
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [interval, setInterval] = useState<number | null>(null);
  const qc = useQueryClient();
  const mutation = useMutation({
    mutationFn: () =>
      api("/scheduler", "PATCH", {
        enabled: enabled ?? data.data?.enabled ?? false,
        interval_minutes: interval ?? data.data?.interval_minutes ?? 60,
      }),
    onSuccess: () => qc.invalidateQueries(),
  });
  return (
    <form
      className="stack"
      onSubmit={(e) => {
        e.preventDefault();
        mutation.mutate();
      }}
    >
      <label className="checkbox-label">
        <input
          type="checkbox"
          checked={enabled ?? data.data?.enabled ?? false}
          onChange={(e) => setEnabled(e.target.checked)}
        />
        Coletar fontes e verificar a watchlist periodicamente
      </label>
      <label>
        Intervalo em minutos
        <input
          type="number"
          required
          min="5"
          max="1440"
          value={interval ?? data.data?.interval_minutes ?? 60}
          onChange={(e) => setInterval(Number(e.target.value))}
        />
      </label>
      <p className="field-hint">
        Frequência de consulta, sujeita aos limites e à latência das fontes.
        Desabilitar não cancela uma coleta já iniciada.
      </p>
      <ErrorBox error={data.error || mutation.error} />
      <div>
        <button className="secondary" disabled={mutation.isPending}>
          Salvar monitoramento
        </button>
      </div>
      {mutation.isSuccess && (
        <p role="status" className="success-text">
          Monitoramento atualizado.
        </p>
      )}
    </form>
  );
}
export function SettingsPage() {
  const settings = useData<{
    allowed_roots: string[];
    semgrep_available: boolean;
    webhook_configured: boolean;
    webhook_format: string;
    nvd_key_configured: boolean;
    github_token_configured: boolean;
    max_files: number;
    scan_timeout: number;
  }>("settings", "/settings");
  const preferences = useData<Preferences>("preferences", "/preferences");
  return (
    <>
      <Header
        eyebrow="PLATAFORMA / PREFERÊNCIAS"
        title="Configurações"
        description="Ajustes de experiência e monitoramento, com segurança da instalação preservada."
      />
      <ErrorBox error={settings.error || preferences.error} />
      <div className="settings-grid">
        <section className="panel padded">
          <h2>Experiência de investigação</h2>
          <p>Tema, densidade e referência de probabilidade.</p>
          {preferences.data ? (
            <PreferencesForm value={preferences.data} />
          ) : (
            <Skeleton rows={4} />
          )}
        </section>
        <section className="panel padded">
          <h2>Monitoramento contínuo</h2>
          <p>Coleta incremental, enriquecimento e pacotes da watchlist.</p>
          <SchedulerForm />
        </section>
        <section className="panel padded">
          <h2>Mecanismos e credenciais</h2>
          <div className="check-row">
            <b>Webhook de notificações</b>
            <Badge
              value={
                settings.data?.webhook_configured ? "ready" : "Não configurado"
              }
            />
          </div>
          <div className="check-row">
            <b>Semgrep local</b>
            <Badge
              value={settings.data?.semgrep_available ? "ready" : "missing"}
            />
          </div>
          <div className="check-row">
            <b>Chave NVD opcional</b>
            <Badge
              value={
                settings.data?.nvd_key_configured ? "ready" : "Não configurada"
              }
            />
          </div>
          <div className="check-row">
            <b>Token GitHub opcional</b>
            <Badge
              value={
                settings.data?.github_token_configured
                  ? "ready"
                  : "Não configurado"
              }
            />
          </div>
          <p className="field-hint">
            Credenciais são configuradas no ambiente seguro da instalação. Seus
            valores não são retornados ao navegador.
          </p>
        </section>
        <section className="panel padded">
          <h2>Diretórios autorizados</h2>
          <p>Somente estas raízes podem ser selecionadas para análise.</p>
          {settings.data?.allowed_roots.length ? (
            <ul className="authorized-roots">
              {settings.data.allowed_roots.map((r) => (
                <li className="mono" key={r}>
                  {r}
                </li>
              ))}
            </ul>
          ) : (
            <div className="notice">
              Nenhuma pasta foi liberada pelo administrador desta instalação.
            </div>
          )}
          <details>
            <summary>Orientação para a instalação local</summary>
            <p>
              Na raiz do projeto, configure o arquivo .env conforme a seção
              “Autorizar diretórios” do README e reinicie o serviço. Use apenas
              pastas de projetos que você pretende analisar, nunca o disco
              inteiro.
            </p>
          </details>
          <p className="field-hint">
            Limites: {settings.data?.max_files ?? "—"} arquivos por análise e{" "}
            {settings.data?.scan_timeout ?? "—"} segundos. Estes controles não
            podem ser relaxados pelo navegador.
          </p>
        </section>
      </div>
    </>
  );
}
