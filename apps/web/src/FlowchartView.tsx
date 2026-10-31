import { useMemo } from "react";
import { Background, Controls, Edge, Handle, MarkerType, Node, NodeProps, Position, ReactFlow } from "@xyflow/react";
import { IncidentDetail } from "./api";
import type { Selection } from "./App";

/** Storyline flowchart: detections top to bottom in time order. Detections whose time windows overlap
 *  sit side by side as branches (their order is not established). Curved connectors join adjacent rows
 *  only, so no line crosses a card; entities are chips on the cards instead of separate nodes. */
const CARD_W = 300;
const CARD_H = 172;
const COL_GAP = 70;
const ROW_GAP = 96;
const MAX_CHIPS = 5;

type Chip = { id: string; label: string; role: string; kind: "ip" | "user" | "device" };
type Card = { id: string; claim: number; f: Record<string, any>; chips: Chip[]; hidden: number; files: string[] };

const fmt = (t: string) => t.slice(5, 16).replace("T", " ");

function CardNode({ data }: NodeProps) {
  const c = data.card as Card;
  const f = c.f;
  const select = data.onSelect as (s: Selection) => void;
  return (
    <div className={`fcard sev-b-${f.severity} ${data.dim ? "dim" : ""} ${data.selected ? "sel" : ""}`} style={{ width: CARD_W }}>
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <div className="fhead">
        <span className="fnum">{c.claim}</span>
        <span className={`tag sev sev-${f.severity}`}>{f.severity}</span>
        <span className="muted small num">{fmt(f.first)}{f.first !== f.last ? ` → ${fmt(f.last)}` : ""}</span>
      </div>
      <div className="ftitle" title={f.title}>{f.title}</div>
      <div className="muted small">
        {f.stage.replace(/-/g, " ")} · {f.event_count.toLocaleString()} record{f.event_count === 1 ? "" : "s"}
        {f.time_reliability !== "ok" ? " · clock stall" : ""}
      </div>
      {(data.multi as boolean) && <div className="small filesline" title={c.files.join(", ")}>from {c.files.join(", ")}</div>}
      <div className="chips">
        {c.chips.map((ch) => (
          <button
            key={ch.id + ch.role}
            className={`chip ${ch.kind} ${data.hl && (data.hl as Set<string>).has(ch.id) ? "on" : ""}`}
            title={`${ch.role.replace(/_/g, " ")}: ${ch.label}`}
            onClick={(e) => (e.stopPropagation(), select({ kind: "node", id: ch.id }))}
          >
            {ch.label}
          </button>
        ))}
        {c.hidden > 0 && <span className="muted small">+{c.hidden} more</span>}
      </div>
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
    </div>
  );
}

function RowLabel({ data }: NodeProps) {
  return (
    <div className="rowlabel">
      <div className="num">{data.time as string}</div>
      {(data.concurrent as boolean) && <div className="muted small">same time · order not established</div>}
    </div>
  );
}

const nodeTypes = { card: CardNode, rowlabel: RowLabel };

type Props = { detail: IncidentDetail; highlighted: Set<string>; selection: Selection; onSelect: (s: Selection) => void };

export default function FlowchartView({ detail, highlighted, selection, onSelect }: Props) {
  const { nodes, edges } = useMemo(() => {
    const byId = new Map(detail.nodes.map((n) => [n.id, n]));
    const findings = detail.nodes.filter((n) => n.type === "finding").sort((a, b) => (a.data.first < b.data.first ? -1 : a.data.first > b.data.first ? 1 : 0));
    const cards: Card[] = findings.map((n, i) => {
      const inv = detail.edges.filter((e) => e.type === "INVOLVES" && e.source === n.id);
      const order = { source: 0, account: 1, target: 2, targeted_account: 3 } as Record<string, number>;
      const chips = inv
        .sort((a, b) => (order[a.data.role] ?? 9) - (order[b.data.role] ?? 9))
        .map((e) => {
          const t = byId.get(e.target)!;
          return { id: t.id, label: t.label, role: e.data.role, kind: t.type as Chip["kind"] };
        });
      const names = Object.fromEntries((detail.incident.sources ?? []).map((x) => [x.source_id, x.filename]));
      const files = [...new Set(detail.events.filter((e) => e.finding_ids.includes(n.data.id)).map((e: any) => names[e.source_id] ?? e.source_id))];
      return { id: n.id, claim: i + 1, f: n.data, chips: chips.slice(0, MAX_CHIPS), hidden: Math.max(0, chips.length - MAX_CHIPS), files };
    });
    // rows: detections that start at the same recorded second are a branch (their order cannot be
    // established); anything later starts a new row, even if an earlier, longer detection is still open
    const rows: Card[][] = [];
    cards.forEach((c) => {
      const last = rows[rows.length - 1];
      if (last && last[0].f.first.slice(0, 19) === c.f.first.slice(0, 19) && last.length < 4) last.push(c);
      else rows.push([c]);
    });
    const widest = Math.max(...rows.map((r) => r.length));
    const ns: Node[] = [];
    const pos = new Map<string, number>();
    rows.forEach((r, ri) => {
      const y = ri * (CARD_H + ROW_GAP);
      ns.push({
        id: `row-${ri}`, type: "rowlabel", position: { x: -((widest * (CARD_W + COL_GAP)) / 2) - 190, y: y + 16 },
        data: { time: fmt(r[0].f.first), concurrent: r.length > 1 }, selectable: false, draggable: false,
      });
      r.forEach((c, ci) => {
        pos.set(c.id, ri);
        const x = (ci - (r.length - 1) / 2) * (CARD_W + COL_GAP) - CARD_W / 2;
        ns.push({ id: c.id, type: "card", position: { x, y }, draggable: false, data: { card: c } });
      });
    });
    const es: Edge[] = [];
    const related = detail.edges.filter((e) => e.type === "RELATED");
    for (let ri = 0; ri + 1 < rows.length; ri++) {
      const a = rows[ri];
      const b = rows[ri + 1];
      a.forEach((ca, i) => {
        const targets = a.length === 1 ? b : [b[Math.min(i, b.length - 1)]];
        targets.forEach((cb) => {
          const rel = related.find((e) => (e.source === ca.id && e.target === cb.id) || (e.source === cb.id && e.target === ca.id));
          es.push({
            id: `seq-${ca.id}-${cb.id}`,
            source: ca.id,
            target: cb.id,
            type: "default",
            label: rel ? `shared ${rel.data.entity}` : undefined,
            markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16, color: rel ? "var(--ctx)" : "var(--muted)" },
            style: { stroke: rel ? "var(--ctx)" : "var(--muted)", strokeWidth: rel ? 2.2 : 1.6, strokeDasharray: rel ? "7 5" : undefined },
            labelStyle: { fontSize: 11, fill: "var(--ink)", fontFamily: "var(--font-ui)" },
            labelBgStyle: { fill: "var(--surface)" },
            labelBgPadding: [6, 3] as [number, number],
            data: rel ? { relatedId: rel.id } : {},
          });
        });
      });
    }
    return { nodes: ns, edges: es };
  }, [detail]);

  const any = highlighted.size > 0;
  const live = nodes.map((n) =>
    n.type === "card"
      ? { ...n, data: { ...n.data, onSelect, hl: highlighted, multi: (detail.incident.sources ?? []).length > 1, dim: any && !highlighted.has(n.id), selected: selection?.kind === "node" && selection.id === n.id } }
      : n,
  );
  const liveEdges = edges.map((e) => ({ ...e, style: { ...e.style, opacity: !any || (highlighted.has(e.source) && highlighted.has(e.target)) ? 1 : 0.15 } }));

  return (
    <div className="graphwrap">
      <div className="legendbar">
        <span className="li"><span className="fnum" style={{ width: 20, height: 20, fontSize: 11 }}>1</span>Detection, in time order</span>
        <span className="li"><span className="swatch-card" />Cards side by side start at the same recorded time; their order is not established</span>
        <span className="li"><svg width="42" height="10" aria-hidden="true"><path d="M2 5 C14 0 26 10 38 5" style={{ stroke: "var(--muted)", strokeWidth: 1.6, fill: "none" }} /></svg>Next in time</span>
        <span className="li"><svg width="42" height="10" aria-hidden="true"><path d="M2 5 C14 0 26 10 38 5" style={{ stroke: "var(--ctx)", strokeWidth: 2.2, strokeDasharray: "7 5", fill: "none" }} /></svg>Shares an entity (contextual)</span>
        <span className="li muted">Click a card or an entity chip for details</span>
      </div>
      <div className="flow">
        <ReactFlow
          nodes={live}
          edges={liveEdges}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.12, maxZoom: 1 }}
          minZoom={0.1}
          nodesConnectable={false}
          onNodeClick={(_, n) => n.type === "card" && onSelect({ kind: "node", id: n.id })}
          onEdgeClick={(_, e) => (e.data as any)?.relatedId && onSelect({ kind: "edge", id: (e.data as any).relatedId })}
          onPaneClick={() => onSelect(null)}
          proOptions={{ hideAttribution: true }}
        >
          <Background gap={24} size={1} color="var(--line)" />
          <Controls showInteractive={false} position="bottom-right" />
        </ReactFlow>
      </div>
    </div>
  );
}
