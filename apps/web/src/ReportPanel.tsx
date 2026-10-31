import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { reportApi } from "./api";

const STAGES = ["queued", "building_story", "building_assets", "rendering", "validating", "stored"];
const LABEL: Record<string, string> = {
  waiting: "Queued",
  queued: "Queued",
  active: "Starting",
  delayed: "Retrying shortly (AI model busy)",
  building_story: "Writing the story",
  building_assets: "Drawing graph and timeline",
  rendering: "Rendering PDF",
  validating: "Checking the PDF",
  stored: "Report ready",
  failed: "Report failed",
};

export default function ReportPanel({ incidentId }: { incidentId: string }) {
  const [useLlm, setUseLlm] = useState(true);
  const [rid, setRid] = useState<string | null>(null);
  const [board, setBoard] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => (setRid(null), setErr(null)), [incidentId]);

  const status = useQuery({
    queryKey: ["report", rid],
    queryFn: () => reportApi.status(rid!),
    enabled: !!rid,
    refetchInterval: (q) => (q.state.data && ["stored", "failed"].includes(q.state.data.state) ? false : 1500),
  });
  const s = status.data;
  const stage = s ? (s.state === "delayed" ? "delayed" : s.stage) : rid ? "queued" : null;
  const idx = stage ? Math.max(0, STAGES.indexOf(stage)) : 0;
  const busy = !!rid && s?.state !== "stored" && s?.state !== "failed";

  const go = async () => {
    setErr(null);
    try {
      const r = await reportApi.request(incidentId, useLlm);
      setRid(r.report_id);
      setBoard(r.bull_board);
    } catch (e) {
      setErr("The report could not be queued. Check that the report service is running (docker compose up -d).");
    }
  };

  return (
    <div className="reportbar">
      <button className="btn" onClick={go} disabled={busy}>
        Generate PDF report
      </button>
      <label className="check-inline" htmlFor="use-llm">
        <input id="use-llm" type="checkbox" checked={useLlm} onChange={(e) => setUseLlm(e.target.checked)} /> Include AI-written summary
      </label>
      {stage && (
        <>
          <div className={`progress ${stage === "failed" ? "bad" : ""}`}>
            <div style={{ width: `${((idx + 1) / STAGES.length) * 100}%` }} />
          </div>
          <span className="small">{LABEL[stage] ?? stage}</span>
        </>
      )}
      {s?.state === "stored" && s.download_url && (
        <a className="btn primary" href={s.download_url} target="_blank" rel="noreferrer">
          Download PDF
        </a>
      )}
      {s?.state === "stored" && s.manifest && (
        <span className="muted small">
          AI summary {s.manifest.narrative.status === "generated" ? "included" : s.manifest.narrative.status === "disabled" ? "not requested" : "not used (failed checks)"}
        </span>
      )}
      {s?.error && <span className="error small">{s.error}</span>}
      {err && <span className="error small">{err}</span>}
      {board && (
        <a className="muted small" href={board} target="_blank" rel="noreferrer" style={{ marginLeft: "auto" }}>
          Report queue
        </a>
      )}
    </div>
  );
}
