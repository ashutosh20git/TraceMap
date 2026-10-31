import { useEffect, useMemo, useRef, useState } from "react";
import { Ev, IncidentDetail } from "./api";

const SEV_VAR: Record<string, string> = { critical: "var(--crit)", high: "var(--high)", medium: "var(--med)", low: "var(--low)" };
import type { Selection } from "./App";

const LANE_H = 22;
const LEFT = 150;
const TOP = 26;
const MAX_LANES = 24;
const TICKS = [1e3, 5e3, 15e3, 6e4, 3e5, 9e5, 36e5, 216e5, 864e5, 6048e5];

const ms = (t: string) => Date.parse(t.replace(" ", "T").replace(/\+00$/, "Z"));
const laneKey = (e: Ev) => e.src_ip ?? e.user ?? "unknown";

function fmt(t: number, step: number) {
  const iso = new Date(t).toISOString();
  return step >= 864e5 ? iso.slice(5, 10) : step >= 6e4 ? iso.slice(5, 16).replace("T", " ") : iso.slice(11, 19);
}

type Props = { detail: IncidentDetail; highlighted: Set<string>; selection: Selection; onSelect: (s: Selection) => void };

/** Time-scaled lanes (one per source host/account) with finding spans on top. Wheel = zoom, drag = pan, double-click = reset. */
export default function Timeline({ detail, highlighted, selection, onSelect }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(800);
  useEffect(() => {
    const ro = new ResizeObserver(([e]) => setWidth(e.contentRect.width));
    if (ref.current) ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);

  const findings = detail.nodes.filter((n) => n.type === "finding");
  const sevOf = useMemo(() => Object.fromEntries(findings.map((f) => [f.data.id, f.data.severity])), [findings]);

  const { lanes, t0, t1 } = useMemo(() => {
    const counts = new Map<string, number>();
    detail.events.forEach((e) => counts.set(laneKey(e), (counts.get(laneKey(e)) ?? 0) + 1));
    const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([k]) => k);
    const lanes = sorted.length > MAX_LANES ? [...sorted.slice(0, MAX_LANES - 1), "(other)"] : sorted;
    const times = detail.events.map((e) => ms(e.time));
    const spans = findings.flatMap((f) => [ms(f.data.first), ms(f.data.last)]);
    const all = [...times, ...spans];
    let t0 = Math.min(...all);
    let t1 = Math.max(...all);
    if (t1 - t0 < 1000) (t0 -= 500), (t1 += 500);
    return { lanes, t0, t1 };
  }, [detail]);

  const [view, setView] = useState<[number, number]>([t0, t1]);
  useEffect(() => setView([t0, t1]), [t0, t1]);
  const plotW = Math.max(100, width - LEFT - 12);
  const x = (t: number) => LEFT + ((t - view[0]) / (view[1] - view[0])) * plotW;
  const laneIdx = useMemo(() => new Map(lanes.map((l, i) => [l, i])), [lanes]);
  const bandH = findings.length * 10 + 8;
  const height = TOP + bandH + lanes.length * LANE_H + 8;

  const span = view[1] - view[0];
  const step = TICKS.find((s) => span / s <= plotW / 90) ?? TICKS[TICKS.length - 1];
  const ticks: number[] = [];
  for (let t = Math.ceil(view[0] / step) * step; t <= view[1]; t += step) ticks.push(t);

  const drag = useRef<{ x: number; v: [number, number] } | null>(null);
  const onWheel = (e: React.WheelEvent) => {
    const rect = ref.current!.getBoundingClientRect();
    const f = Math.min(1, Math.max(0, (e.clientX - rect.left - LEFT) / plotW));
    const center = view[0] + f * span;
    const k = e.deltaY > 0 ? 1.25 : 0.8;
    const ns = Math.max(200, span * k);
    setView([center - f * ns, center + (1 - f) * ns]);
  };

  // stacked events at one exact instant (e.g. a stalled source clock) are summarized per lane
  const stackKey = (e: Ev) => `${laneKey(e)}|${e.time}`;
  const stacks = useMemo(() => {
    const m = new Map<string, number>();
    detail.events.forEach((e) => m.set(stackKey(e), (m.get(stackKey(e)) ?? 0) + 1));
    return m;
  }, [detail]);

  const any = highlighted.size > 0;
  return (
    <div
      className="tl"
      ref={ref}
      onWheel={onWheel}
      onMouseDown={(e) => (drag.current = { x: e.clientX, v: view })}
      onMouseMove={(e) => {
        if (!drag.current) return;
        const dt = ((e.clientX - drag.current.x) / plotW) * (drag.current.v[1] - drag.current.v[0]);
        setView([drag.current.v[0] - dt, drag.current.v[1] - dt]);
      }}
      onMouseUp={() => (drag.current = null)}
      onMouseLeave={() => (drag.current = null)}
      onDoubleClick={() => setView([t0, t1])}
    >
      <div className="tlhead muted small">
        {detail.events.length.toLocaleString()} evidence records on device time · bars are detections, dots are records, a ringed dot is several records at the same instant · scroll to zoom, drag to pan, double-click to reset
      </div>
      <svg width={width} height={height}>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={x(t)} x2={x(t)} y1={TOP - 6} y2={height} className="grid" />
            <text x={x(t) + 3} y={TOP - 10} className="tick">
              {fmt(t, step)}
            </text>
          </g>
        ))}
        {findings.map((f, i) => {
          const a = x(ms(f.data.first));
          const b = Math.max(a + 3, x(ms(f.data.last)));
          const on = !any || highlighted.has(`f:${f.data.id}`) || detail.events.some((e) => highlighted.has(e.uid) && e.finding_ids.includes(f.data.id));
          return (
            <g key={f.id} onClick={() => onSelect({ kind: "node", id: f.id })} style={{ cursor: "pointer" }} opacity={on ? 1 : 0.25}>
              <rect x={a} y={TOP + i * 10} width={b - a} height={7} rx={2} fill={SEV_VAR[f.data.severity] ?? "var(--low)"} />
              <title>{`${f.data.rule_id}: ${f.data.title}\n${f.data.first} → ${f.data.last}`}</title>
            </g>
          );
        })}
        <text x={4} y={TOP + 8} className="lane">
          findings
        </text>
        {lanes.map((l, i) => (
          <g key={l}>
            <line x1={LEFT} x2={width} y1={TOP + bandH + i * LANE_H + LANE_H / 2} y2={TOP + bandH + i * LANE_H + LANE_H / 2} className="laneline" />
            <text x={4} y={TOP + bandH + i * LANE_H + LANE_H / 2 + 4} className="lane">
              {l}
            </text>
          </g>
        ))}
        {detail.events.map((e) => {
          const t = ms(e.time);
          if (t < view[0] || t > view[1]) return null;
          const li = laneIdx.get(laneKey(e)) ?? lanes.length - 1;
          const cy = TOP + bandH + li * LANE_H + LANE_H / 2;
          const sel = selection?.kind === "event" && selection.id === e.uid;
          const on = !any || highlighted.has(e.uid);
          const n = stacks.get(stackKey(e)) ?? 1;
          return (
            <circle
              key={e.uid}
              cx={x(t)}
              cy={cy}
              r={sel ? 7 : n > 1 ? 5 : 4}
              fill={SEV_VAR[sevOf[e.finding_ids[0]]] ?? "var(--low)"}
              stroke={sel ? "var(--ink)" : n > 1 ? "var(--surface)" : "none"}
              strokeWidth={sel ? 2 : 1}
              opacity={on ? 0.95 : 0.12}
              style={{ cursor: "pointer" }}
              onClick={(ev) => (ev.stopPropagation(), onSelect({ kind: "event", id: e.uid }))}
            >
              <title>{`${e.time}${n > 1 ? ` (${n} events at this instant)` : ""}\n${e.event_type}/${e.event_subtype} ${e.action ?? ""} ${e.outcome ?? ""}\n${e.message ?? e.rule_name ?? ""}`}</title>
            </circle>
          );
        })}
      </svg>
    </div>
  );
}
