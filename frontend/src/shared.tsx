import React from "react";
import { useQuery } from "@tanstack/react-query";
import { Radar, Download, AlertTriangle } from "lucide-react";
import { api } from "./api";

export const formatDate = (value: string | null | undefined) =>
  value ? new Date(value).toLocaleString("pt-BR") : "Não informado";

export const severityLabel: Record<string, string> = {
  CRITICAL: "Crítica",
  HIGH: "Alta",
  MEDIUM: "Média",
  LOW: "Baixa",
  UNKNOWN: "Não informada",
};

export function useData<T>(key: string, path: string) {
  return useQuery({
    queryKey: [key, path],
    queryFn: ({ signal }) => api<T>(path, "GET", undefined, { signal }),
  });
}

export function Empty({
  title,
  children,
}: {
  title: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="empty">
      <Radar size={34} />
      <h3>{title}</h3>
      <p>
        {children ||
          "Os dados aparecerão aqui assim que estiverem disponíveis."}
      </p>
    </div>
  );
}

export function ErrorBox({ error }: { error: Error | null }) {
  return error ? (
    <div role="alert" className="error">
      <AlertTriangle size={16} />
      {error.message}
    </div>
  ) : null;
}

export const statusLabels: Record<string, string> = {
  delivered: "Entregue",
  retry: "Aguardando nova tentativa",
  new: "Novo",
  pending: "Pendente",
  investigating: "Em análise",
  applicable: "Aplicável",
  not_applicable: "Não aplicável",
  false_positive: "Falso positivo",
  planned: "Correção planejada",
  remediating: "Em remediação",
  mitigated: "Mitigado",
  resolved: "Resolvido",
  accepted: "Risco aceito",
  running: "Executando",
  completed: "Concluído",
  partial: "Parcial",
  failed: "Falhou",
  cancelled: "Cancelado",
  never: "Não consultada",
  healthy: "Saudável",
  syncing: "Sincronizando",
  stale: "Atrasada",
  unavailable: "Indisponível",
  success: "Saudável",
  ready: "Disponível",
  missing: "Requer atenção",
  queued: "Pendente",
  preparing: "Preparando",
  inventory: "Inventariando",
  advisories: "Consultando advisories",
  sast: "Executando SAST",
  consolidating: "Consolidando",
  unknown: "Não verificado",
};
export function Badge({ value }: { value: string }) {
  return (
    <span className={`badge ${value.toLowerCase()}`}>
      {severityLabel[value] || statusLabels[value] || value}
    </span>
  );
}

export function Header({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow: string;
  title: string;
  description: string;
  action?: React.ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action}
    </header>
  );
}

export function ExportButtons() {
  return (
    <div className="button-row">
      <a className="button secondary" href="/api/export?format=csv" download>
        <Download size={15} />
        CSV
      </a>
      <a className="button secondary" href="/api/export?format=json" download>
        JSON
      </a>
    </div>
  );
}
