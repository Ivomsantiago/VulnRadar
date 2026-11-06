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
  modified?: string | null;
  components?: { ecosystem: string; package: string }[];
};
export type Source = {
  id: string;
  status: string;
  count: number;
  last_run?: string;
  error?: string;
  health?: string;
  last_success?: string;
  mode?: string;
  last_sync?: SyncRun;
};
export type Watch = {
  id: number;
  ecosystem: string;
  package: string;
  version: string | null;
  min_severity?: string;
  alerts_enabled?: boolean;
  last_checked?: string | null;
  vulnerability_count?: number | null;
  kev_count?: number | null;
};
export type Project = { id: number; name: string; path: string };
export type ScanResult = {
  inventory?: Component[];
  findings?: Record<string, unknown>[];
  warnings?: string[];
  coverage?: string;
  engine?: string;
  image?: string;
  digest?: string | null;
  digest_type?: string;
  request?: { image: string; engine: string };
  comparison?: {
    new: number;
    persistent: number;
    resolved: number;
    reopened?: number;
    comparable: boolean;
  };
  sca?: ScanResult;
  sast?: ScanResult;
};
export type Scan = {
  id: number;
  project_id: number;
  kind: string;
  status: string;
  stage?: string;
  created_at: string;
  completed_at?: string | null;
  result: ScanResult;
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
  severity_trend?: { date: string; severity: string; count: number }[];
  new_kev_period?: number;
  new_24h?: number;
  period_days?: number;
  cvss_distribution?: { label: string; count: number }[];
  epss_distribution?: { label: string; count: number }[];
  cvss_missing?: number;
  epss_missing?: number;
};
export async function api<T>(
  path: string,
  method = "GET",
  body?: unknown,
  options?: { signal?: AbortSignal },
): Promise<T> {
  const response = await fetch(`/api${path}`, {
    method,
    signal: options?.signal,
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

export type Page<T> = {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  scope?: string;
};
export type Finding = {
  owner?: string | null;
  due_at?: string | null;
  risk_expires_at?: string | null;
  remediation_plan?: string | null;
  id: number;
  project_id: number;
  project_name: string;
  scan_id: number;
  kind: "sca" | "sast" | "oci";
  vulnerability_id: string | null;
  package: string | null;
  ecosystem: string | null;
  version: string | null;
  file: string;
  line: number | null;
  rule_id: string | null;
  severity: string;
  status: string;
  first_seen: string;
  last_seen: string;
  fixed_versions: string[];
  evidence: Record<string, unknown>;
  vulnerability: Vulnerability | null;
  priority: { classification: string; reasons: string[] };
  history?: Activity[];
  source_evidence?: import("./Evidence").SourceEvidence | null;
};
export type Component = {
  id: number;
  project_id: number;
  project_name: string;
  scan_id: number;
  ecosystem: string;
  package: string;
  version: string;
  file: string;
  direct: boolean | null;
  query_status: string;
};
export type Exposure = {
  oci_scanned: boolean;
  open_oci: number;
  sca_scanned: boolean;
  sast_scanned: boolean;
  projects: number;
  relevant_vulnerabilities: number;
  open_high_critical: number;
  kev: number;
  new_24h: number;
  open_sca: number;
  open_sast: number;
  resolved: number;
  scope: string;
  state: string;
};
export type Technology = {
  ecosystem: string;
  package: string;
  vulnerabilities: number;
  last_published: string | null;
  kev: number;
};
export type ProjectInspection = {
  path: string;
  languages: string[];
  lockfiles: string[];
  frameworks: string[];
  checks: { label: string; status: string; message?: string }[];
};
export type DirectoryListing = {
  path: string | null;
  parent: string | null;
  roots_configured: boolean;
  directories: { name: string; path: string }[];
};
export type SyncRun = {
  id: number;
  source: string;
  status: string;
  started_at: string;
  completed_at: string | null;
  duration_ms: number | null;
  new_count: number;
  updated_count: number;
  processed_count: number;
  pages: number;
  error: string | null;
};
