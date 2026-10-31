import type { GEdge, GNode } from "./api";

/** One definition of how each relationship looks, shared by canvas, legend and inspector.
 *  Line style carries the meaning (solid = observed, dashed = inferred link, dotted = engine membership). */
export type EdgeKind = "AUTH" | "CONFIGURED" | "FLOW" | "INVOLVES" | "RELATED_CTX" | "RELATED_PIVOT" | "RELATED_UNRESOLVED";

export const EDGE_STYLE: Record<EdgeKind, { stroke: string; dash?: string; width: number; label: string; meaning: string }> = {
  AUTH: { stroke: "var(--obs)", width: 1.8, label: "Login", meaning: "Observed: login attempts from an address to an account" },
  CONFIGURED: { stroke: "var(--obs)", width: 1.8, label: "Config change", meaning: "Observed: an account changed device configuration" },
  FLOW: { stroke: "var(--flow)", width: 1.4, label: "Network flow", meaning: "Observed: connections between two addresses" },
  INVOLVES: { stroke: "var(--muted)", dash: "1.5 4", width: 1.2, label: "Involves", meaning: "Engine: a detection involves this entity" },
  RELATED_CTX: { stroke: "var(--ctx)", dash: "7 5", width: 2, label: "Related", meaning: "Inferred: two detections share an entity close in time" },
  RELATED_PIVOT: { stroke: "var(--ctx)", width: 2.2, label: "Pivot", meaning: "Inferred: a target later acts as a source" },
  RELATED_UNRESOLVED: { stroke: "var(--muted)", dash: "3 4", width: 1.6, label: "Order unknown", meaning: "Inferred: occur together, order cannot be established" },
};

export function edgeKind(e: GEdge): EdgeKind {
  if (e.type !== "RELATED") return e.type as EdgeKind;
  const d = e.data.decision;
  return d === "pivot" ? "RELATED_PIVOT" : d === "order_unresolved" ? "RELATED_UNRESOLVED" : "RELATED_CTX";
}

export function nodeKind(n: GNode): "finding" | "ext" | "int" | "user" | "device" {
  if (n.type === "finding") return "finding";
  if (n.type === "ip") return n.data.scope === "external" ? "ext" : "int";
  return n.type;
}

export const NODE_LABEL = { finding: "Detection", ext: "External address", int: "Internal address", user: "Account", device: "Device" };

const P = { width: 16, height: 16, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 2, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
export function NodeIcon({ kind }: { kind: ReturnType<typeof nodeKind> }) {
  switch (kind) {
    case "finding":
      return (<svg {...P} aria-hidden="true"><path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z" /><path d="M12 8v5M12 16h.01" /></svg>);
    case "ext":
      return (<svg {...P} aria-hidden="true"><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3a14 14 0 010 18M12 3a14 14 0 000 18" /></svg>);
    case "int":
      return (<svg {...P} aria-hidden="true"><rect x="3" y="4" width="18" height="12" rx="1" /><path d="M8 20h8M12 16v4" /></svg>);
    case "user":
      return (<svg {...P} aria-hidden="true"><circle cx="12" cy="8" r="4" /><path d="M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6" /></svg>);
    default:
      return (<svg {...P} aria-hidden="true"><rect x="3" y="6" width="18" height="12" rx="1" /><path d="M7 10h.01M11 10h.01M3 14h18" /></svg>);
  }
}

export function EdgeSwatch({ kind }: { kind: EdgeKind }) {
  const s = EDGE_STYLE[kind];
  return (
    <svg width="42" height="10" aria-hidden="true">
      <line x1="2" y1="5" x2="34" y2="5" style={{ stroke: s.stroke, strokeWidth: s.width, strokeDasharray: s.dash }} />
      <path d="M33 1 L40 5 L33 9 z" style={{ fill: s.stroke }} />
    </svg>
  );
}
