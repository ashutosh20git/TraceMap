import { useQuery } from "@tanstack/react-query";
import { withCase } from "./api";

export type SourceSummary = {
  format: string;
  compression?: string;
  events: number;
  quarantined: number;
  first: string | null;
  last: string | null;
  layouts: number;
  drift_layouts: number;
  inferred: Record<string, string>;
  coverage: Record<string, number>;
  elapsed_s?: number;
};
export type Source = {
  source_id: string;
  filename: string;
  size: number;
  status: string;
  created_at: string;
  duplicate_of?: string;
  error?: string;
  note?: string;
  summary?: SourceSummary;
};
export type RunStep = { status: string; at?: string; filename?: string; events?: number; findings?: number; incidents?: number; revision?: number; note?: string; duplicate_of?: string | null };
export type Run = { run_id: string; status: string; created_at: string; finished_at?: string; revision?: number; error?: string; note?: string; sources?: string[]; steps: Record<string, RunStep> };

async function json<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(withCase(url), init);
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}

export function useRun() {
  return useQuery({
    queryKey: ["run"],
    queryFn: () => json<Run | null>("/api/runs/latest"),
    refetchInterval: (q) => (q.state.data?.status === "running" ? 2000 : 20000),
  });
}

export function useSources(fast: boolean) {
  return useQuery({ queryKey: ["sources"], queryFn: () => json<Source[]>("/api/sources"), refetchInterval: fast ? 3000 : 20000 });
}

export const startProcessing = () => json<{ run_id: string; worker: string; sources: number }>("/api/process", { method: "POST" });

export const fmtSize = (b: number) => (b >= 1e9 ? `${(b / 1e9).toFixed(1)} GB` : b >= 1e6 ? `${(b / 1e6).toFixed(1)} MB` : `${Math.max(1, Math.round(b / 1e3))} KB`);

export const SOURCE_STATUS: Record<string, { label: string; tone: "" | "state-ok" | "state-warn" | "state-bad" }> = {
  uploading: { label: "Uploading", tone: "" },
  uploaded: { label: "Ready to process", tone: "" },
  queued: { label: "Queued", tone: "state-warn" },
  ingesting: { label: "Parsing", tone: "state-warn" },
  ingested: { label: "Parsed", tone: "state-ok" },
  duplicate: { label: "Duplicate", tone: "" },
  failed: { label: "Failed", tone: "state-bad" },
  aborted: { label: "Excluded", tone: "" },
};
