import { useQuery } from "@tanstack/react-query";
import { api, GNode, IncidentDetail } from "./api";
import type { Selection } from "./App";
import { EDGE_STYLE, EdgeSwatch, NODE_LABEL, NodeIcon, edgeKind, nodeKind } from "./graphStyle";

const DECISION: Record<string, string> = {
  observed: "Observed in the source records.",
  engine_detection: "Engine detection: a rule matched these source records.",
  contextual_association: "Contextual: shares an entity close in time. Not proof that one actor did both.",
  pivot: "Pivot hypothesis: a target of the first later acts as a source in the second.",
  order_unresolved: "Order unknown: timestamps are equal or unreliable, so which came first cannot be established.",
};
const HIDE = new Set(["attack", "title", "id", "hub_degree", "keys", "provenance"]);

function KV({ obj }: { obj: Record<string, any> }) {
  return (
    <table className="kv">
      <tbody>
        {Object.entries(obj)
          .filter(([k, v]) => !HIDE.has(k) && v !== null && v !== undefined && v !== "")
          .map(([k, v]) => (
            <tr key={k}>
              <th>{k.replace(/_/g, " ")}</th>
              <td className={typeof v === "number" ? "num" : ""}>{typeof v === "object" ? JSON.stringify(v) : String(v)}</td>
            </tr>
          ))}
      </tbody>
    </table>
  );
}

function RawEvent({ uid }: { uid: string }) {
  const q = useQuery({ queryKey: ["event", uid], queryFn: () => api.event(uid) });
  if (!q.data) return <p className="muted small">Loading the source record…</p>;
  const e = q.data;
  return (
    <>
      <h4>Source record</h4>
      <p className="muted small num">
        Line {e.line_no.toLocaleString()} · byte {e.byte_offset.toLocaleString()} · time {e.time_quality.replace(/_/g, " ")}
      </p>
      {/* untrusted log text, rendered as escaped text only */}
      <pre className="raw">{e.raw}</pre>
    </>
  );
}

function Connections({ node, detail, onSelect }: { node: GNode; detail: IncidentDetail; onSelect: (s: Selection) => void }) {
  const byId = new Map(detail.nodes.map((n) => [n.id, n]));
  const conns = detail.edges.filter((e) => e.source === node.id || e.target === node.id);
  if (!conns.length) return null;
  const groups = new Map<string, typeof conns>();
  conns.forEach((e) => {
    const k = edgeKind(e);
    groups.set(k, [...(groups.get(k) ?? []), e]);
  });
  return (
    <>
      <h4>Connections ({conns.length})</h4>
      {[...groups.entries()].map(([k, es]) => (
        <div key={k}>
          <div className="muted small" style={{ marginTop: 8 }}>
            {EDGE_STYLE[k as keyof typeof EDGE_STYLE].label}
          </div>
          <ul className="conn">
            {es.map((e) => {
              const other = byId.get(e.source === node.id ? e.target : e.source);
              const dir = e.source === node.id ? "to" : "from";
              return (
                <li key={e.id}>
                  <button onClick={() => onSelect({ kind: "edge", id: e.id })}>
                    <EdgeSwatch kind={edgeKind(e)} />
                    <span className="ct">
                      {dir} <b>{other?.label ?? "?"}</b>
                      {e.label && e.type !== "INVOLVES" ? <span className="muted"> · {e.label}</span> : null}
                      {e.type === "INVOLVES" ? <span className="muted"> · {e.data.role?.replace(/_/g, " ")}</span> : null}
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </>
  );
}

export default function Inspector({ detail, selection, onSelect }: { detail: IncidentDetail; selection: Selection; onSelect: (s: Selection) => void }) {
  if (!selection) return null;
  if (selection.kind === "event") {
    const e = detail.events.find((x) => x.uid === selection.id);
    return (
      <div className="pad">
        <div className="eyebrow">Event</div>
        <h3>{e?.message ?? e?.rule_name ?? `${e?.event_type ?? ""} ${e?.event_subtype ?? ""}`}</h3>
        {e && <KV obj={{ time: e.time, type: `${e.event_type}/${e.event_subtype}`, user: e.user, source: e.src_ip, destination: e.dst_ip, port: e.dst_port, action: e.action, outcome: e.outcome, country: e.src_country }} />}
        <RawEvent uid={selection.id} />
      </div>
    );
  }
  if (selection.kind === "edge") {
    const e = detail.edges.find((x) => x.id === selection.id);
    if (!e) return null;
    const k = edgeKind(e);
    const byId = new Map(detail.nodes.map((n) => [n.id, n]));
    const { claim, checks, missing, decision, evidence, ...rest } = e.data;
    return (
      <div className="pad">
        <div className="eyebrow" style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <EdgeSwatch kind={k} /> {EDGE_STYLE[k].label}
        </div>
        <h3>
          {byId.get(e.source)?.label} → {byId.get(e.target)?.label}
        </h3>
        <p className="decision">{DECISION[decision] ?? decision}</p>
        {claim && (<><h4>Claim</h4><p className="small">{claim}</p></>)}
        {checks && (<><h4>Checks passed</h4><KV obj={checks} /></>)}
        {missing && (<><h4>Evidence that would settle it</h4><p className="small">{missing.join(", ")}</p></>)}
        <h4>Details</h4>
        <KV obj={rest} />
        {Array.isArray(evidence) && <p className="muted small">{evidence.length} evidence record(s) are highlighted on the timeline.</p>}
      </div>
    );
  }
  const n = detail.nodes.find((x) => x.id === selection.id);
  if (!n) return null;
  const kind = nodeKind(n);
  const d = n.data;
  return (
    <div className="pad">
      <div className="eyebrow" style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <span className={`gicon ${kind === "ext" ? "ext" : ""}`} style={{ width: 22, height: 22 }}>
          <NodeIcon kind={kind} />
        </span>
        {NODE_LABEL[kind]}
      </div>
      <h3>{n.label}</h3>
      {kind === "finding" ? (
        <>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 8 }}>
            <span className={`tag sev sev-${d.severity}`}>{d.severity}</span>
            <span className="tag">{d.stage.replace(/-/g, " ")}</span>
            <span className="tag">{d.rule_id}</span>
          </div>
          <p className="decision">{DECISION.engine_detection}</p>
          {d.time_reliability !== "ok" && (
            <p className="warn small">{Math.round(d.stall_fraction * 100)}% of this detection's records share one stalled timestamp, so counts within that period are unreliable.</p>
          )}
          <h4>ATT&CK</h4>
          <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
            {d.attack.map((t: any) => (
              <li key={t.id}>
                <a href={`https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/`} target="_blank" rel="noreferrer">{t.id}</a> {t.name}
              </li>
            ))}
          </ul>
          <h4>Facts</h4>
          <KV obj={{ first_seen: d.first, last_seen: d.last, records: d.event_count, peak_in_window: d.metric, time_reliability: d.time_reliability }} />
        </>
      ) : (
        <>
          <p className="muted small">
            {kind === "user" ? "An account name, not a person or session." : kind === "device" ? "The reporting device." : "An address, not proof of a specific machine or of who controls it."}
          </p>
          {d.hub_degree > 0 && <p className="warn small">Shared by {d.hub_degree} detections, so it is never used to join detections into one incident.</p>}
          <KV obj={d} />
        </>
      )}
      <Connections node={n} detail={detail} onSelect={onSelect} />
    </div>
  );
}
