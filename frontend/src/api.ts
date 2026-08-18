export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type JobStatus =
  | "queued"
  | "cloning"
  | "collecting"
  | "analyzing"
  | "completed"
  | "failed";

export interface Job {
  id: string;
  status: JobStatus;
  repo_url: string;
  branch: string | null;
  created_at: string;
  updated_at: string;
  progress: string | null;
  error: string | null;
  report_id: string | null;
  trigger: string;
}

export interface Finding {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  executive_summary?: string;
  affected_services?: string[];
  what_happened?: string;
  root_cause?: string;
  evidence: string | null;
  impact?: string;
  recommendation: string;
  recommended_fixes?: string[];
  preventive_measures?: string[];
  related_components?: string[];
  confidence_score?: number;
  file_path: string | null;
  description?: string;
  effort: string | null;
}

export interface ReportSection {
  title: string;
  summary: string;
  findings: Finding[];
}

export interface DomainCoverage {
  domain: string;
  status: string;
  notes?: string | null;
}

export interface DevOpsReport {
  id: string;
  job_id: string;
  repo_url: string;
  branch: string | null;
  created_at: string;
  executive_summary: string;
  health_score: number;
  risk_level: Severity;
  primary_root_cause?: string | null;
  correlated_timeline?: string[];
  sections: ReportSection[];
  domain_coverage?: DomainCoverage[];
  quick_wins: string[];
  roadmap: string[];
  collected_facts: Record<string, unknown>;
}

export interface Wso2ErrorItem {
  id: string;
  log_type: string;
  severity: Severity;
  error: string;
  description: string;
  possible_occurrence: string;
  remedial_actions: string[];
  wso2_doc_refs: string[];
  evidence?: string | null;
  source_file?: string | null;
  affected_components: string[];
  logger?: string | null;
  subsystem?: string | null;
  functional_error?: string | null;
  exception_type?: string | null;
  error_source?: string | null;
  va_correlation?: string | null;
  confidence_score: number;
  technical_name?: string | null;
  plain_meaning?: string | null;
  call_flow?: string[];
  config_checks?: string[];
  impacted_customers?: string[];
  failure_count?: number | null;
  failure_total?: number | null;
  impact_pct?: number | null;
  impact_summary?: string | null;
}

export interface Wso2VaMapping {
  va_finding: string;
  related_log_errors: string[];
  correlation_notes: string;
  risk: Severity;
  recommended_actions: string[];
}

export interface Wso2Report {
  id: string;
  job_id: string;
  created_at: string;
  executive_summary: string;
  health_score: number;
  risk_level: Severity;
  primary_root_cause?: string | null;
  context: Record<string, unknown>;
  log_coverage: Record<string, unknown>;
  errors: Wso2ErrorItem[];
  va_correlations: Wso2VaMapping[];
  correlated_timeline: string[];
  quick_wins: string[];
  roadmap: string[];
  doc_references: string[];
}

const API = import.meta.env.VITE_API_URL || "";

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    ...init,
    headers: {
      ...(init?.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
      ...init?.headers,
    },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || res.statusText);
  }
  return res.json() as Promise<T>;
}

export function isWso2Report(r: DevOpsReport | Wso2Report): r is Wso2Report {
  return Array.isArray((r as Wso2Report).errors) && !!(r as Wso2Report).context;
}

export const api = {
  health: () =>
    req<{
      status: string;
      llm_configured: boolean;
      llm_provider?: string;
      llm_model?: string;
      analysis_mode?: string;
      gitlab_configured: boolean;
    }>("/api/health"),
  investigate: (body: {
    repo_url: string;
    branch?: string;
    notes?: string;
    live_probe?: boolean;
    software_info?: Record<string, unknown>;
    ip_info?: Record<string, unknown>;
    metrics?: Record<string, unknown>;
    business_metrics?: Record<string, unknown>;
    monitoring_snapshot?: Record<string, unknown>;
  }) => req<Job>("/api/investigate", { method: "POST", body: JSON.stringify(body) }),
  investigateWithLogs: async (form: FormData) => {
    const res = await fetch(`${API}/api/investigate/with-logs`, { method: "POST", body: form });
    if (!res.ok) throw new Error(await res.text());
    return res.json() as Promise<Job>;
  },
  wso2Analyze: async (form: FormData) => {
    const res = await fetch(`${API}/api/wso2/analyze`, { method: "POST", body: form });
    if (!res.ok) throw new Error(await res.text());
    return res.json() as Promise<{ job_id: string; status: string; message: string }>;
  },
  jobs: () => req<{ jobs: Job[] }>("/api/jobs"),
  job: (id: string) => req<Job>(`/api/jobs/${id}`),
  reports: () => req<{ reports: DevOpsReport[] }>("/api/reports"),
  report: (id: string) => req<DevOpsReport | Wso2Report>(`/api/reports/${id}`),
  downloadUrl: (id: string, fmt: "md" | "html" | "json") => `${API}/api/reports/${id}/download/${fmt}`,
};
