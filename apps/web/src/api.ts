export type Technique = { id: string; name: string };

export type IncidentSummary = {
  id: string;
  status: string;
  title: string;
  first: string;
  last: string;
  stages: string[];
  rules: string[];
  max_severity: number;
  risk: number;
  risk_factors: Record<string, number>;
  finding_count: number;
  event_count: number;
  degraded_clock: boolean;
  version: string;
  sources: { source_id: string; filename: string }[];
};

export type GNode = { id: string; type: "finding" | "ip" | "user" | "device"; label: string; data: Record<string, any> };
export type GEdge = {
  id: string;
  source: string;
  target: string;
  type: "INVOLVES" | "RELATED" | "AUTH" | "FLOW" | "CONFIGURED";
  label: string;
  data: Record<string, any>;
};

export type Ev = {
  uid: string;
  time: string;
  time_quality: string;
  event_type: string | null;
  event_subtype: string | null;
  event_code: string | null;
  severity: string | null;
  action: string | null;
  outcome: string | null;
  user: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  rule_name: string | null;
  message: string | null;
  src_country: string | null;
  src_role: string | null;
  dst_role: string | null;
  line_no: number;
  byte_offset: number;
  finding_ids: string[];
  steps: string[];
  raw?: string;
};

export type IncidentDetail = {
  incident: IncidentSummary;
  nodes: GNode[];
  edges: GEdge[];
  events: Ev[];
  hidden_targeted_accounts: Record<string, number>;
};

export type Summary = {
  findings: number;
  incidents: number;
  entities_ips: number;
  entities_users: number;
  bundle_events: number;
  findings_by_rule: Record<string, number>;
  graph_version: string | null;
  revision: number | null;
  empty: boolean;
};

/** The selected case (investigation). Every API call is scoped to it, so unrelated uploads never mix. */
function loadCase() {
  try {
    return localStorage.getItem("trustgate.case") || "default";
  } catch {
    return "default";
  }
}
export const caseState = { id: loadCase() };
export function setCase(id: string) {
  caseState.id = id;
  try {
    localStorage.setItem("trustgate.case", id);
  } catch {
    /* storage unavailable: the choice lasts for this tab only */
  }
}
export const withCase = (u: string) => `${u}${u.includes("?") ? "&" : "?"}case=${encodeURIComponent(caseState.id)}`;
export type CaseInfo = { case_id: string; name: string; created_at: string };

async function get<T>(path: string): Promise<T> {
  const r = await fetch(withCase(path));
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return r.json();
}

export const api = {
  cases: () => get<CaseInfo[]>("/api/cases"),
  summary: () => get<Summary>("/api/summary"),
  incidents: () => get<IncidentSummary[]>("/api/incidents"),
  incident: (id: string) => get<IncidentDetail>(`/api/incidents/${encodeURIComponent(id)}`),
  event: (uid: string) => get<Ev>(`/api/events/${encodeURIComponent(uid)}`),
};

export const STAGE_COLOR: Record<string, string> = {
  reconnaissance: "#64748b",
  "initial-access": "#f59e0b",
  execution: "#ef4444",
  persistence: "#a855f7",
  "privilege-escalation": "#ec4899",
  "defense-evasion": "#14b8a6",
  "credential-access": "#eab308",
  discovery: "#0ea5e9",
  "lateral-movement": "#f97316",
  collection: "#84cc16",
  "command-and-control": "#dc2626",
  exfiltration: "#be123c",
  impact: "#7f1d1d",
};

export const SEV = ["", "low", "medium", "high", "critical"];

export type StoryStep = {
  claim_id: string;
  finding_id: string;
  rule_id: string;
  title: string;
  stage: string;
  stage_plain: string;
  severity: string;
  attack: Technique[];
  first: string;
  last: string;
  event_count: number;
  sentence: string;
  limitations: string[];
  logs: { uid: string; time: string; line_no: number; step: string; raw: string }[];
  logs_omitted: number;
};

export type Story = {
  summary: string;
  stages: string[];
  steps: StoryStep[];
  relationships: { id: string; from: string; to: string; basis: string; entity: string; decision: string; gap_hours: number | string | null; sentence: string }[];
  observed: string[];
  gaps: string[];
  evidence_total: number;
};

export type ReportStatus = {
  report_id: string;
  state: string;
  stage: string;
  error?: string | null;
  attempts?: number;
  download_url?: string;
  manifest?: { narrative: { status: string; model: string | null; errors: string[] }; pdf_bytes: number; generated_at: string };
};

export const reportApi = {
  story: (id: string) => get<Story>(`/api/incidents/${encodeURIComponent(id)}/story`),
  request: async (id: string, use_llm: boolean) => {
    const r = await fetch(withCase(`/api/incidents/${encodeURIComponent(id)}/reports`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ use_llm }),
    });
    if (!r.ok) throw new Error(`report request failed: ${r.status}`);
    return (await r.json()) as { report_id: string; status_url: string; bull_board: string };
  },
  status: (rid: string) => get<ReportStatus>(`/api/reports/${rid}`),
};
