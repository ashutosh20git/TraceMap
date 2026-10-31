import { useEffect, useMemo, useState } from "react";
import { Background, BaseEdge, Controls, Edge, EdgeProps, Handle, MarkerType, MiniMap, Node, NodeProps, Position, ReactFlow } from "@xyflow/react";
import ELK from "elkjs/lib/elk.bundled.js";
import { GNode, IncidentDetail } from "./api";
import type { Selection } from "./App";
import { EDGE_STYLE, EdgeKind, EdgeSwatch, NODE_LABEL, NodeIcon, edgeKind, nodeKind } from "./graphStyle";

const elk = new ELK();
const W = 220;
const H = 56;
// columns read left to right: who came in -> what we detected -> which accounts -> what inside was touched
const COLUMN = { ext: 0, finding: 1, user: 2, int: 3, device: 3 } as const;
type Pt = { x: number; y: number };

function EntityNode({ data }: NodeProps) {
  const g = data.g as GNode;
  const d = g.data;
  const kind = nodeKind(g);
  let sub = "";
  if (kind === "finding") sub = `${d.rule_id} · ${d.event_count.toLocaleString()} records${d.time_reliability !== "ok" ? " · clock stall" : ""}`;
  else if (kind === "ext" || kind === "int") sub = [NODE_LABEL[kind], d.country].filter(Boolean).join(" · ");
  else if (kind === "user") sub = d.hub_degree ? `Account · in ${d.hub_degree} detections` : "Account";
  else sub = "Device";
  return (
    <div
      className={`gnode ${kind === "finding" ? `finding sev-b-${d.severity}` : ""} ${d.hub_degree ? "hub" : ""} ${data.dim ? "dim" : ""} ${data.selected ? "sel" : ""}`}
      title={`${NODE_LABEL[kind]}: ${g.label}`}
    >
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <Handle id="tl" type="target" position={Position.Left} style={{ opacity: 0 }} />
      <span className={`gicon ${kind === "ext" ? "ext" : ""}`}>
        <NodeIcon kind={kind} />
      </span>
      <span style={{ minWidth: 0 }}>
        <div className="gl">{g.label}</div>
        <div className="gs">{sub}</div>
      </span>
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
      <Handle id="sl" type="source" position={Position.Left} style={{ opacity: 0 }} />
    </div>
  );
}

/** Draws the route ELK computed around the nodes, with rounded corners, instead of a straight curve
 *  that could pass over other nodes. */
function RoutedEdge({ id, data, style, markerEnd, label, labelStyle, labelBgStyle, labelBgPadding, labelBgBorderRadius, sourceX, sourceY, targetX, targetY }: EdgeProps) {
  const pts = (data?.points as Pt[] | undefined) ?? [{ x: sourceX, y: sourceY }, { x: targetX, y: targetY }];
  const r = 14;
  let d = `M${pts[0].x},${pts[0].y}`;
  for (let i = 1; i < pts.length - 1; i++) {
    const p = pts[i], a = pts[i - 1], b = pts[i + 1];
    const la = Math.hypot(p.x - a.x, p.y - a.y), lb = Math.hypot(b.x - p.x, b.y - p.y);
    const k = Math.min(r, la / 2, lb / 2);
    const p1 = { x: p.x - ((p.x - a.x) / (la || 1)) * k, y: p.y - ((p.y - a.y) / (la || 1)) * k };
    const p2 = { x: p.x + ((b.x - p.x) / (lb || 1)) * k, y: p.y + ((b.y - p.y) / (lb || 1)) * k };
    d += ` L${p1.x},${p1.y} Q${p.x},${p.y} ${p2.x},${p2.y}`;
  }
  const last = pts[pts.length - 1];
  d += ` L${last.x},${last.y}`;
  // label on the longest straight run
  let best = 0, lx = (pts[0].x + last.x) / 2, ly = (pts[0].y + last.y) / 2;
  for (let i = 1; i < pts.length; i++) {
    const len = Math.hypot(pts[i].x - pts[i - 1].x, pts[i].y - pts[i - 1].y);
    if (len > best) [best, lx, ly] = [len, (pts[i].x + pts[i - 1].x) / 2, (pts[i].y + pts[i - 1].y) / 2];
  }
  return (
    <BaseEdge id={id} path={d} style={style} markerEnd={markerEnd} label={label} labelX={lx} labelY={ly}
      labelStyle={labelStyle} labelShowBg labelBgStyle={labelBgStyle} labelBgPadding={labelBgPadding} labelBgBorderRadius={labelBgBorderRadius} interactionWidth={14} />
  );
}

const nodeTypes = { entity: EntityNode };
const edgeTypes = { routed: RoutedEdge };

function Legend() {
  return (
    <div className="legendbar" aria-label="Legend">
      {(["ext", "finding", "user", "int", "device"] as const).map((k) => (
        <span className="li" key={k}>
          <span className={`gicon ${k === "ext" ? "ext" : ""}`} style={{ width: 20, height: 20 }}>
            <NodeIcon kind={k} />
          </span>
          {NODE_LABEL[k]}
        </span>
      ))}
      <span className="li">
        <span style={{ display: "flex", gap: 2 }}>
          {["--crit", "--high", "--med"].map((c) => (
            <span key={c} style={{ width: 4, height: 16, background: `var(${c})`, borderRadius: 1 }} />
          ))}
        </span>
        Severity
      </span>
      <span className="lsep" />
      {(Object.keys(EDGE_STYLE) as EdgeKind[]).map((k) => (
        <span className="li" key={k} title={EDGE_STYLE[k].meaning}>
          <EdgeSwatch kind={k} />
          {EDGE_STYLE[k].label}
        </span>
      ))}
    </div>
  );
}

type Props = { detail: IncidentDetail; highlighted: Set<string>; selection: Selection; onSelect: (s: Selection) => void };

export default function GraphView({ detail, highlighted, selection, onSelect }: Props) {
  const [layout, setLayout] = useState<{ pos: Record<string, Pt>; routes: Record<string, Pt[]> }>({ pos: {}, routes: {} });
  const [hover, setHover] = useState<string | null>(null);
  const col = useMemo(() => Object.fromEntries(detail.nodes.map((n) => [n.id, COLUMN[nodeKind(n)]])), [detail]);

  useEffect(() => {
    let live = true;
    const laid = detail.edges.filter((e) => e.type !== "RELATED");
    elk
      .layout({
        id: "root",
        layoutOptions: {
          "elk.algorithm": "layered",
          "elk.direction": "RIGHT",
          "elk.partitioning.activate": "true",
          "elk.edgeRouting": "ORTHOGONAL",
          "elk.layered.spacing.nodeNodeBetweenLayers": "200",
          "elk.spacing.nodeNode": "56",
          "elk.layered.spacing.edgeNodeBetweenLayers": "40",
          "elk.spacing.edgeNode": "28",
          "elk.spacing.edgeEdge": "14",
          "elk.layered.spacing.edgeEdgeBetweenLayers": "14",
          "elk.layered.nodePlacement.strategy": "NETWORK_SIMPLEX",
          "elk.layered.crossingMinimization.strategy": "LAYER_SWEEP",
          "elk.layered.mergeEdges": "false",
        },
        children: detail.nodes.map((n) => ({ id: n.id, width: W, height: H, layoutOptions: { "elk.partitioning.partition": String(col[n.id]) } })),
        // layout edges always point to the right-hand column; drawn edges keep their true direction
        edges: laid.map((e) => {
          const fwd = col[e.source] <= col[e.target];
          return { id: e.id, sources: [fwd ? e.source : e.target], targets: [fwd ? e.target : e.source] };
        }),
      })
      .then((g) => {
        if (!live) return;
        const pos: Record<string, Pt> = {};
        g.children?.forEach((c) => (pos[c.id] = { x: c.x ?? 0, y: c.y ?? 0 }));
        const routes: Record<string, Pt[]> = {};
        const byId = new Map(laid.map((e) => [e.id, e]));
        (g.edges ?? []).forEach((le: any) => {
          const s = le.sections?.[0];
          if (!s) return;
          const pts: Pt[] = [s.startPoint, ...(s.bendPoints ?? []), s.endPoint];
          const e = byId.get(le.id)!;
          routes[le.id] = col[e.source] <= col[e.target] ? pts : pts.reverse();
        });
        setLayout({ pos, routes });
      });
    return () => {
      live = false;
    };
  }, [detail, col]);

  const any = highlighted.size > 0;
  const nodes: Node[] = useMemo(
    () =>
      detail.nodes.map((n) => ({
        id: n.id,
        type: "entity",
        position: layout.pos[n.id] ?? { x: 0, y: 0 },
        draggable: false,
        data: { g: n, dim: any && !highlighted.has(n.id), selected: selection?.kind === "node" && selection.id === n.id },
      })),
    [detail, layout, highlighted, selection, any],
  );
  const edges: Edge[] = useMemo(
    () =>
      detail.edges.map((e) => {
        const k = edgeKind(e);
        const st = EDGE_STYLE[k];
        const isSel = selection?.kind === "edge" && selection.id === e.id;
        const touchesSel = selection?.kind === "node" && (e.source === selection.id || e.target === selection.id);
        const on = !any || (highlighted.has(e.source) && highlighted.has(e.target));
        const showLabel = isSel || hover === e.id || touchesSel;
        const related = k.startsWith("RELATED");
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          // detection-to-detection links arc out to the left of the detection column
          type: related ? "default" : "routed",
          ...(related ? { sourceHandle: "sl", targetHandle: "tl" } : {}),
          data: { points: layout.routes[e.id] },
          label: showLabel ? (k === "INVOLVES" ? e.label : e.label || st.label) : undefined,
          markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14, color: st.stroke },
          zIndex: related ? 2 : 1,
          style: {
            stroke: st.stroke,
            strokeDasharray: st.dash,
            strokeWidth: isSel || hover === e.id ? st.width + 1.4 : st.width,
            opacity: on ? 1 : 0.12,
            fill: "none",
          },
          labelStyle: { fontSize: 11, fill: "var(--ink)", fontFamily: "var(--font-ui)" },
          labelBgStyle: { fill: "var(--surface)" },
          labelBgPadding: [6, 3] as [number, number],
          labelBgBorderRadius: 3,
        };
      }),
    [detail, highlighted, selection, any, hover, layout],
  );

  return (
    <div className="graphwrap">
      <Legend />
      <div className="flow">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          fitView
          fitViewOptions={{ padding: 0.12, maxZoom: 1.1 }}
          minZoom={0.05}
          key={detail.incident.id + Object.keys(layout.pos).length}
          onNodeClick={(_, n) => onSelect({ kind: "node", id: n.id })}
          onEdgeClick={(_, e) => onSelect({ kind: "edge", id: e.id })}
          onEdgeMouseEnter={(_, e) => setHover(e.id)}
          onEdgeMouseLeave={() => setHover(null)}
          onPaneClick={() => onSelect(null)}
          proOptions={{ hideAttribution: true }}
          nodesConnectable={false}
        >
          <Background gap={24} size={1} color="var(--line)" />
          <Controls showInteractive={false} position="bottom-right" />
          {detail.nodes.length > 25 && <MiniMap pannable zoomable position="bottom-left" nodeColor="var(--line)" maskColor="rgba(0,0,0,0.06)" />}
        </ReactFlow>
      </div>
    </div>
  );
}
