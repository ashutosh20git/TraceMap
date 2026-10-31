import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, Ev, IncidentDetail, SEV } from "./api";
import GraphView from "./GraphView";
import FlowchartView from "./FlowchartView";
import Timeline from "./Timeline";
import EventList from "./EventList";
import Inspector from "./Inspector";
import StoryView from "./StoryView";
import ReportPanel from "./ReportPanel";
import UploadPage from "./UploadPage";
import ChecksPage from "./ChecksPage";
import { useRun } from "./workspace";
import CaseSwitcher from "./CaseSwitcher";

export type Selection = { kind: "node" | "edge" | "event"; id: string } | null;
type Page = "upload" | "checks" | "investigate";
type Tab = "story" | "flow" | "graph" | "timeline";

/** Which events and graph nodes a selection lights up, so graph, timeline and list stay in sync. */
function highlight(sel: Selection, d: IncidentDetail | undefined) {
  const events = new Set<string>();
  const nodes = new Set<string>();
  if (!sel || !d) return { events, nodes };
  if (sel.kind === "event") {
    const e = d.events.find((x) => x.uid === sel.id);
    if (e) {
      events.add(e.uid);
      e.finding_ids.forEach((f) => nodes.add(`f:${f}`));
      if (e.src_ip) nodes.add(`ip:${e.src_ip}`);
      if (e.dst_ip) nodes.add(`ip:${e.dst_ip}`);
      if (e.user) nodes.add(`u:${e.user}`);
    }
  } else if (sel.kind === "node") {
    nodes.add(sel.id);
    const [kind, ...rest] = sel.id.split(":");
    const key = rest.join(":");
    const match = (e: Ev) =>
      kind === "f" ? e.finding_ids.includes(key) : kind === "ip" ? e.src_ip === key || e.dst_ip === key : kind === "u" ? e.user === key : false;
    d.events.filter(match).forEach((e) => events.add(e.uid));
    d.edges.filter((x) => x.source === sel.id || x.target === sel.id).forEach((x) => (nodes.add(x.source), nodes.add(x.target)));
  } else {
    const edge = d.edges.find((x) => x.id === sel.id);
    if (edge) {
      nodes.add(edge.source);
      nodes.add(edge.target);
      const ev = edge.data.evidence;
      (Array.isArray(ev) ? ev : ev ? [ev] : []).forEach((u: string) => events.add(u));
    }
  }
  return { events, nodes };
}

const readHash = (): Page | null => {
  const h = location.hash.slice(1);
  return h === "upload" || h === "checks" || h === "investigate" ? h : null;
};

export default function App() {
  const summary = useQuery({ queryKey: ["summary"], queryFn: api.summary, refetchInterval: 20000 });
  const run = useRun();
  const published = !!summary.data && !summary.data.empty;
  const [page, setPageState] = useState<Page | null>(readHash());
  useEffect(() => {
    const on = () => setPageState(readHash());
    addEventListener("hashchange", on);
    return () => removeEventListener("hashchange", on);
  }, []);
  const [caseVersion, setCaseVersion] = useState(0);
  const current: Page = page ?? (published ? "investigate" : "upload");
  const go = (p: Page) => {
    location.hash = p;
    setPageState(p);
  };

  const steps: [Page, string, boolean][] = [
    ["upload", "Upload", true],
    ["checks", "Checks", !!run.data],
    ["investigate", "Investigate", published],
  ];

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <circle cx="5" cy="6" r="2.5" /><circle cx="19" cy="6" r="2.5" /><circle cx="12" cy="18" r="2.5" />
            <path d="M7.2 7.3l3.6 8.5M16.8 7.3l-3.6 8.5M7.5 6h9" />
          </svg>
          <span className="product">TrustGate</span>
        </div>
        <CaseSwitcher onChanged={() => (setCaseVersion((v) => v + 1), history.replaceState(null, "", location.pathname), setPageState(null))} />
        <nav className="stepper" aria-label="Workflow">
          {steps.map(([p, label, enabled], i) => (
            <span key={p} style={{ display: "contents" }}>
              {i > 0 && <span className="sep" />}
              <button
                className={`${current === p ? "on" : ""} ${steps.findIndex((s) => s[0] === current) > i ? "done" : ""}`}
                onClick={() => go(p)}
                disabled={!enabled}
                aria-current={current === p ? "step" : undefined}
              >
                <span className="n">{i + 1}</span>
                <span className="lbl">{label}</span>
              </button>
            </span>
          ))}
        </nav>
        <div className="ws num">
          {published ? (
            <>
              <span>Revision {summary.data!.revision}</span>
              <span>{summary.data!.incidents} incidents</span>
              <span>{summary.data!.findings.toLocaleString()} detections</span>
            </>
          ) : (
            <span>{summary.isLoading ? "Loading…" : "No published data"}</span>
          )}
        </div>
      </header>
      <div className="content" key={caseVersion}>
        {!summary.isLoading && current === "upload" && <UploadPage onStarted={() => go("checks")} />}
        {!summary.isLoading && current === "checks" && <ChecksPage published={published} onOpenBoard={() => go("investigate")} />}
        {summary.isLoading && <div className="page"><div className="panel empty">Loading the workspace…</div></div>}
        {!summary.isLoading && current === "investigate" && (published ? <Investigate /> : <div className="page"><div className="panel empty">Nothing is published yet. Upload files and run processing first.</div></div>)}
      </div>
    </div>
  );
}

function Investigate() {
  const [incId, setIncId] = useState<string | null>(null);
  const [sel, setSel] = useState<Selection>(null);
  const [tab, setTab] = useState<Tab>("story");
  const [q, setQ] = useState("");
  const [minSev, setMinSev] = useState(1);
  const list = useQuery({ queryKey: ["incidents"], queryFn: api.incidents });
  const active = incId ?? list.data?.[0]?.id ?? null;
  const detail = useQuery({ queryKey: ["incident", active], queryFn: () => api.incident(active!), enabled: !!active });
  const hl = useMemo(() => highlight(sel, detail.data), [sel, detail.data]);
  const shown = (list.data ?? []).filter(
    (i) => i.max_severity >= minSev && (!q || `${i.title} ${i.rules.join(" ")} ${i.stages.join(" ")} ${i.id}`.toLowerCase().includes(q.toLowerCase())),
  );
  const inc = detail.data?.incident;

  return (
    <div className="inv">
      <aside className="list" aria-label="Incidents">
        <div className="tools">
          <input id="incident-search" className="search" placeholder="Search incidents" value={q} onChange={(e) => setQ(e.target.value)} />
          <div className="seg" role="group" aria-label="Minimum severity">
            {[1, 2, 3, 4].map((s) => (
              <button key={s} className={minSev === s ? "on" : ""} onClick={() => setMinSev(s)}>
                {s === 1 ? "All" : `${SEV[s][0].toUpperCase()}${SEV[s].slice(1)}+`}
              </button>
            ))}
          </div>
          <span className="muted small num">
            {shown.length} of {list.data?.length ?? 0} candidate incidents, highest risk first
          </span>
        </div>
        {shown.map((i) => (
          <button key={i.id} className={`item ${i.id === active ? "on" : ""}`} onClick={() => (setIncId(i.id), setSel(null), setTab("story"))}>
            <span className="r">
              <span className={`tag sev sev-${SEV[i.max_severity]}`}>{SEV[i.max_severity]}</span>
              <span className="score" title="Risk score">{i.risk}</span>
            </span>
            <span className="t">{i.title}</span>
            <span className="muted small num">
              {i.first.slice(5, 16).replace("T", " ")} → {i.last.slice(5, 16).replace("T", " ")} · {i.finding_count} detection{i.finding_count > 1 ? "s" : ""}
              {i.degraded_clock ? " · clock stall" : ""}
            </span>
            {i.sources.length > 1 && <span className="tag state-warn" title={i.sources.map((x) => x.filename).join(", ")}>spans {i.sources.length} files</span>}
          </button>
        ))}
      </aside>

      {inc && detail.data ? (
        <section className="case">
          <div className="case-head">
            <div className="case-title">
              <div style={{ minWidth: 0 }}>
                <div className="muted small num">
                  {inc.id} · candidate incident · {inc.first.slice(0, 16).replace("T", " ")} → {inc.last.slice(0, 16).replace("T", " ")} device time
                </div>
                <h1>{inc.title}</h1>
                <div className="case-meta" style={{ marginTop: 6 }}>
                  {inc.stages.map((s) => (
                    <span key={s} className="tag">{s.replace(/-/g, " ")}</span>
                  ))}
                  <span className="tag">{inc.finding_count} detections</span>
                  <span className="tag num">{inc.event_count.toLocaleString()} records</span>
                  {inc.sources.map((x) => (
                    <span key={x.source_id} className="tag filetag" title={x.source_id}>{x.filename}</span>
                  ))}
                  {inc.sources.length > 1 && <span className="tag state-warn">evidence from {inc.sources.length} files</span>}
                </div>
              </div>
              <div className="riskbox" title={Object.entries(inc.risk_factors).map(([k, v]) => `${k.replace(/_/g, " ")}: ${v}`).join("\n")}>
                <div className="eyebrow">Risk</div>
                <div className="v">{inc.risk}</div>
              </div>
            </div>
            <nav className="tabs" role="tablist">
              {(
                [
                  ["story", "Attack story"],
                  ["flow", "Flowchart"],
                  ["graph", "Entity graph"],
                  ["timeline", "Timeline and evidence"],
                ] as [Tab, string][]
              ).map(([k, label]) => (
                <button key={k} role="tab" aria-selected={tab === k} className={tab === k ? "on" : ""} onClick={() => setTab(k)}>
                  {label}
                </button>
              ))}
            </nav>
          </div>
          <ReportPanel incidentId={inc.id} />
          <div className={`work ${sel && tab !== "story" ? "split" : ""}`}>
            <div className="canvas">
              {tab === "story" && (
                <StoryView
                  incidentId={inc.id}
                  onShowInGraph={(fid) => {
                    setSel({ kind: "node", id: `f:${fid}` });
                    setTab("flow");
                  }}
                />
              )}
              {tab === "flow" && <FlowchartView detail={detail.data} highlighted={hl.nodes} selection={sel} onSelect={setSel} />}
              {tab === "graph" && <GraphView detail={detail.data} highlighted={hl.nodes} selection={sel} onSelect={setSel} />}
              {tab === "timeline" && (
                <div className="tl-wrap">
                  <Timeline detail={detail.data} highlighted={hl.events} selection={sel} onSelect={setSel} />
                  <EventList events={detail.data.events} highlighted={hl.events} selection={sel} onSelect={setSel} />
                </div>
              )}
            </div>
            {sel && tab !== "story" && (
              <aside className="side" aria-label="Details">
                <button className="close" onClick={() => setSel(null)} aria-label="Close details">×</button>
                <Inspector detail={detail.data} selection={sel} onSelect={setSel} />
              </aside>
            )}
          </div>
        </section>
      ) : (
        <div className="empty">{list.isLoading || detail.isLoading ? "Loading…" : "Select an incident."}</div>
      )}
    </div>
  );
}
