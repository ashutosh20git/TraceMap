import { useEffect, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Ev } from "./api";
import type { Selection } from "./App";

type Props = { events: Ev[]; highlighted: Set<string>; selection: Selection; onSelect: (s: Selection) => void };

/** Virtualized chronological evidence list; scrolls to the selected event. */
export default function EventList({ events, highlighted, selection, onSelect }: Props) {
  const parent = useRef<HTMLDivElement>(null);
  const v = useVirtualizer({ count: events.length, getScrollElement: () => parent.current, estimateSize: () => 26, overscan: 12 });
  useEffect(() => {
    if (selection?.kind !== "event") return;
    const i = events.findIndex((e) => e.uid === selection.id);
    if (i >= 0) v.scrollToIndex(i, { align: "center" });
  }, [selection, events]);
  const any = highlighted.size > 0;
  return (
    <div className="elist" ref={parent}>
      <div style={{ height: v.getTotalSize(), position: "relative" }}>
        {v.getVirtualItems().map((r) => {
          const e = events[r.index];
          const sel = selection?.kind === "event" && selection.id === e.uid;
          return (
            <div
              key={e.uid}
              className={`erow ${sel ? "sel" : ""} ${any && !highlighted.has(e.uid) ? "dim" : ""}`}
              style={{ transform: `translateY(${r.start}px)`, height: r.size }}
              onClick={() => onSelect({ kind: "event", id: e.uid })}
            >
              <span className="mono">{e.time.slice(0, 23)}</span>
              <span>{e.event_type}/{e.event_subtype}</span>
              <span className="mono">
                {e.src_ip ?? "—"} → {e.dst_ip ?? "—"}
                {e.dst_port ? `:${e.dst_port}` : ""}
              </span>
              <span>{e.user ?? ""}</span>
              <span>{[e.action, e.outcome].filter(Boolean).join(" / ")}</span>
              <span className="msg" title={e.message ?? e.rule_name ?? ""}>
                {e.message ?? e.rule_name ?? ""}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
