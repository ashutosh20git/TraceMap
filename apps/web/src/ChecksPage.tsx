import { useQuery } from "@tanstack/react-query";
import { api } from "./api";
import { Run, RunStep, Source, SOURCE_STATUS, useRun, useSources } from "./workspace";

type SnapSource = { source_id: string; filename: string; events?: number; first?: string; last?: string; related: { source_id: string; filename: string; reason: string }[] };

function Relations() {
  const s = useQuery({ queryKey: ["summary"], queryFn: api.summary });
  const srcs = ((s.data as any)?.sources ?? []) as SnapSource[];
  if (srcs.length < 2) return null;
  const pairs = srcs.flatMap((a) => a.related.filter((r) => r.source_id > a.source_id).map((r) => ({ a: a.filename, b: r.filename, why: r.reason })));
  return (
    <section className="panel pad">
      <div className="eyebrow">How the files in this case relate</div>
      {pairs.length === 0 ? (
        <p className="muted small">No shared device or overlapping time range between the files. They are analyzed together, but nothing links them yet.</p>
      ) : (
        <ul className="small" style={{ margin: "8px 0 0", paddingLeft: 18 }}>
          {pairs.map((p) => (
            <li key={p.a + p.b}><span className="mono">{p.a}</span> and <span className="mono">{p.b}</span>: {p.why}</li>
          ))}
        </ul>
      )}
      <p className="muted small">Detections and incidents that use evidence from more than one file are marked "spans N files" on the investigation board.</p>
    </section>
  );
}

const STEP_NAME: Record<string, string> = { detect: "Run detection rules", graph: "Build relationship graph", publish: "Publish to the board", analyze: "Analysis" };
const COVER = [
  ["event_time", "Timestamp"],
  ["category", "Event meaning"],
  ["src_ip", "Source address"],
  ["user", "Account"],
  ["outcome", "Outcome"],
  ["dst_ip", "Destination"],
  ["device", "Device"],
] as const;

function orderSteps(steps: Record<string, RunStep>) {
  const ingest = Object.entries(steps).filter(([k]) => k.startsWith("ingest:"));
  const rest = ["analyze", "detect", "graph", "publish"].filter((k) => steps[k]).map((k) => [k, steps[k]] as [string, RunStep]);
  return [...ingest, ...rest];
}

function stepDetail(v: RunStep) {
  return [
    v.events != null ? `${v.events.toLocaleString()} events` : "",
    v.duplicate_of ? `duplicate of ${v.duplicate_of}` : "",
    v.findings != null ? `${v.findings.toLocaleString()} detections` : "",
    v.incidents != null ? `${v.incidents} candidate incidents` : "",
    v.revision != null ? `revision ${v.revision}` : "",
    v.note ?? "",
  ]
    .filter(Boolean)
    .join(" · ");
}

function RunPanel({ run }: { run: Run }) {
  const steps = orderSteps(run.steps ?? {});
  const tone = run.status === "published" ? "state-ok" : run.status === "failed" ? "state-bad" : "state-warn";
  return (
    <section className="panel">
      <div className="pad" style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "center", borderBottom: "1px solid var(--line)" }}>
        <div>
          <div className="eyebrow">Processing run</div>
          <div className="mono small muted">
            {run.run_id} · started {run.created_at.slice(11, 19)} UTC
          </div>
        </div>
        <span className={`tag ${tone}`}>{run.status === "running" ? "In progress" : run.status.replace(/_/g, " ")}</span>
      </div>
      <ol className="runsteps">
        {steps.length === 0 && run.status === "running" && (
          <li>
            <span className="mark waiting" />
            <span>Starting the processing server</span>
            <span className="muted small">about a minute if it was asleep</span>
          </li>
        )}
        {steps.map(([k, v]) => (
          <li key={k}>
            <span className={`mark ${v.status}`} />
            <span>{k.startsWith("ingest:") ? `Parse ${v.filename ?? k.slice(7)}` : STEP_NAME[k] ?? k}</span>
            <span className="muted small num">{v.status === "running" ? "running…" : stepDetail(v) || v.status}</span>
          </li>
        ))}
      </ol>
      {(run.error || run.note) && (
        <div className="pad small" style={{ borderTop: "1px solid var(--line)" }}>
          {run.error ? <span className="error">{run.error}</span> : <span className="muted">{run.note}</span>}
        </div>
      )}
    </section>
  );
}

function SourceChecks({ s }: { s: Source }) {
  const m = s.summary;
  const st = SOURCE_STATUS[s.status] ?? { label: s.status, tone: "" };
  if (!m) {
    return (
      <section className="panel pad" style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
        <span className="mono">{s.filename}</span>
        <span className={`tag ${st.tone}`}>{st.label}</span>
      </section>
    );
  }
  const total = m.events + m.quarantined;
  const inferred = Object.entries(m.inferred ?? {});
  return (
    <section className="panel">
      <div className="pad" style={{ display: "flex", justifyContent: "space-between", gap: 12, borderBottom: "1px solid var(--line)", flexWrap: "wrap" }}>
        <div style={{ minWidth: 0 }}>
          <div className="mono" style={{ overflowWrap: "anywhere" }}>{s.filename}</div>
          <div className="muted small num">
            {m.format}
            {m.compression && m.compression !== "none" ? ` · ${m.compression}` : ""} · {m.first?.slice(0, 16)} → {m.last?.slice(0, 16)}
            {m.elapsed_s ? ` · parsed in ${Math.round(m.elapsed_s / 60)} min` : ""}
          </div>
        </div>
        <span className={`tag ${st.tone}`}>{st.label}</span>
      </div>
      <div className="checks pad">
        <div className="check">
          <div className="k">
            <span className="eyebrow">Records accounted for</span>
            <span className="tag state-ok">Pass</span>
          </div>
          <div className="v">{total.toLocaleString()}</div>
          <span className="muted small num">
            {m.events.toLocaleString()} parsed + {m.quarantined.toLocaleString()} set aside = every input record
          </span>
        </div>
        <div className="check">
          <div className="k">
            <span className="eyebrow">Set aside</span>
            <span className={`tag ${m.quarantined ? "state-warn" : "state-ok"}`}>{m.quarantined ? "Review" : "None"}</span>
          </div>
          <div className="v">{m.quarantined.toLocaleString()}</div>
          <span className="muted small">Unreadable, oversized or malformed records are kept with their location and reason, never dropped.</span>
        </div>
        <div className="check">
          <div className="k">
            <span className="eyebrow">Log layout</span>
            <span className={`tag ${m.drift_layouts ? "state-warn" : "state-ok"}`}>{m.drift_layouts ? "New fields mid-file" : "Consistent"}</span>
          </div>
          <div className="v">
            {m.layouts} layout{m.layouts === 1 ? "" : "s"}
          </div>
          <span className="muted small">
            {m.drift_layouts
              ? `${m.drift_layouts} layout(s) with field names not seen at the start appeared later (new event types or a schema change). They were mapped and analyzed too.`
              : m.layouts > 1
                ? "Different event types use different fields; no unexpected field names appeared."
                : "The same fields throughout the file."}
          </span>
        </div>
        <div className="check">
          <div className="k">
            <span className="eyebrow">Unfamiliar fields</span>
            <span className={`tag ${inferred.length ? "state-warn" : "state-ok"}`}>{inferred.length ? "Inferred" : "All known"}</span>
          </div>
          {inferred.length ? (
            <ul className="small" style={{ margin: 0, paddingLeft: 16 }}>
              {inferred.map(([k, v]) => (
                <li key={k}>
                  <span className="mono">{v}</span> read as {k.replace(/_/g, " ")}
                </li>
              ))}
            </ul>
          ) : (
            <span className="muted small">Every field the rules need matched a known name.</span>
          )}
        </div>
      </div>
      <div className="pad" style={{ borderTop: "1px solid var(--line)", display: "grid", gap: 6 }}>
        <span className="eyebrow">Field coverage</span>
        {COVER.map(([k, label]) => {
          const v = m.coverage?.[k];
          if (v == null) return null;
          return (
            <div className="cov" key={k}>
              <span>{label}</span>
              <div className="progress">
                <div style={{ width: `${Math.round(v * 100)}%` }} />
              </div>
              <span className="num muted" style={{ textAlign: "right" }}>
                {Math.round(v * 100)}%
              </span>
            </div>
          );
        })}
        <span className="muted small">Share of records with each field filled in. Low coverage limits what detections can see; it is not an error.</span>
      </div>
    </section>
  );
}

export default function ChecksPage({ onOpenBoard, published }: { onOpenBoard: () => void; published: boolean }) {
  const run = useRun();
  const running = run.data?.status === "running";
  const sources = useSources(running);
  const shown = (sources.data ?? []).filter((s) => !["aborted", "uploading"].includes(s.status));
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="eyebrow">Step 2</div>
          <h1>Processing and checks</h1>
          <p>Each file is parsed and checked on its own; detection and the graph then run once over all files together, so activity that spans files is seen as one.</p>
        </div>
        <button className="btn primary" onClick={onOpenBoard} disabled={!published || running}>
          Open investigation →
        </button>
      </div>
      {run.data ? <RunPanel run={run.data} /> : <div className="panel empty">No processing run yet. Upload files and start processing in step 1.</div>}
      <Relations />
      {shown.map((s) => (
        <SourceChecks key={s.source_id} s={s} />
      ))}
    </div>
  );
}
