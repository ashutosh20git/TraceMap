import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { reportApi, StoryStep } from "./api";

const DECISION: Record<string, string> = {
  contextual_association: "related by a shared entity",
  pivot: "pivot hypothesis",
  order_unresolved: "order unknown",
};

function Step({ s, onShowInGraph }: { s: StoryStep; onShowInGraph: (findingId: string) => void }) {
  const [open, setOpen] = useState(false);
  return (
    <article className="step" data-cid={s.claim_id.slice(1)}>
      <h3>
        {s.title}
        <span className={`tag sev sev-${s.severity}`}>{s.severity}</span>
        <span className="tag">{s.stage_plain}</span>
      </h3>
      <p>{s.sentence}</p>
      <div className="techs">
        {s.attack.map((t) => (
          <a key={t.id} className="tag" href={`https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/`} target="_blank" rel="noreferrer">
            {t.id} · {t.name}
          </a>
        ))}
      </div>
      {s.limitations.map((l) => (
        <p key={l} className="limit">{l}</p>
      ))}
      <div style={{ display: "flex", gap: 16, marginTop: 6 }}>
        <button className="btn ghost" onClick={() => setOpen(!open)} aria-expanded={open}>
          {open ? "Hide" : "Show"} source logs ({s.event_count.toLocaleString()})
        </button>
        <button className="btn ghost" onClick={() => onShowInGraph(s.finding_id)}>
          Show in flowchart
        </button>
      </div>
      {open && (
        <div className="logs">
          {s.logs.map((l) => (
            <div key={l.uid} className="log">
              <span className="meta">line {l.line_no.toLocaleString()} · {l.time.slice(0, 23)}</span>
              {/* untrusted log text: React renders it as escaped text */}
              {l.raw}
            </div>
          ))}
          {s.logs_omitted > 0 && <p className="muted small">{s.logs_omitted.toLocaleString()} more records are in the Timeline and evidence tab and the PDF appendix.</p>}
        </div>
      )}
    </article>
  );
}

export default function StoryView({ incidentId, onShowInGraph }: { incidentId: string; onShowInGraph: (fid: string) => void }) {
  const q = useQuery({ queryKey: ["story", incidentId], queryFn: () => reportApi.story(incidentId) });
  if (q.isLoading) return <p className="muted pad">Composing the story…</p>;
  if (q.error || !q.data) return <p className="error pad">The story could not be loaded: {String(q.error)}</p>;
  const st = q.data;
  return (
    <div className="story">
      <section>
        <h2>What happened</h2>
        <p className="lede">{st.summary}</p>
      </section>
      <section>
        <h2>Step by step</h2>
        <div className="steps" style={{ marginTop: 14 }}>
          {st.steps.map((s) => (
            <Step key={s.claim_id} s={s} onShowInGraph={onShowInGraph} />
          ))}
        </div>
      </section>
      {st.relationships.length > 0 && (
        <section>
          <h2>How the steps connect</h2>
          <ul className="rel small">
            {st.relationships.map((r) => (
              <li key={r.id}>
                Step {r.from.slice(1)} and step {r.to.slice(1)} share <span className="mono">{r.entity}</span>, {DECISION[r.decision] ?? r.decision}
                {r.gap_hours !== null && <span className="muted"> · {typeof r.gap_hours === "number" ? `${r.gap_hours} h apart` : r.gap_hours}</span>}
              </li>
            ))}
          </ul>
        </section>
      )}
      {st.observed.length > 0 && (
        <section>
          <h2>Observed activity around these entities</h2>
          <ul className="rel small">
            {st.observed.slice(0, 20).map((o) => (
              <li key={o}>{o}</li>
            ))}
          </ul>
        </section>
      )}
      <section>
        <h2>What this data cannot tell us</h2>
        <ul className="rel small">
          {st.gaps.map((g) => (
            <li key={g}>{g}</li>
          ))}
        </ul>
      </section>
    </div>
  );
}
