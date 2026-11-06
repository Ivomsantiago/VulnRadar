export type Vulnerability = {
  id: string;
  title: string;
  description: string;
  severity: string;
  cvss: number | null;
  epss: number | null;
  kev: boolean;
  published: string | null;
  triage: string;
};
export type Source = {
  id: string;
  status: string;
  count: number;
  last_run?: string;
  error?: string;
};
export type Watch = {
  id: number;
  ecosystem: string;
  package: string;
  version: string | null;
};
export type Project = { id: number; name: string; path: string };
export type Scan = {
  id: number;
  project_id: number;
  kind: string;
  status: string;
  created_at: string;
  result: {
    inventory?: unknown[];
    findings?: unknown[];
    warnings?: unknown[];
    coverage?: string;
  };
};
export type Activity = {
  id: number;
  kind: string;
  subject: string;
  data: Record<string, unknown>;
  created_at: string;
};
export type Dashboard = {
  total: number;
  severities: Record<string, number>;
  kev: number;
  watchlist: number;
  projects: number;
  scans: number;
  trend: { date: string; count: number }[];
  coverage: string;
};
export async function api<T>(
  path: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  const response = await fetch(`/api${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      "X-VulnRadar-Client": "web",
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    let message = `Erro ${response.status}`;
    try {
      const data = await response.json();
      message = typeof data.detail === "string" ? data.detail : message;
    } catch {
      /* non-JSON failure */
    }
    throw new Error(message);
  }
  return response.status === 204 ? (undefined as T) : response.json();
}
