import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { withCase } from "./api";

type CovRule = {
  id: string; title: string; severity: string; type: string; stage: string; source: string;
  status: "fired" | "no_match" | "error" | "not_applicable" | "not_run"; findings: number; error?: string; needs?: string[];
  attack: { id: string; name: string }[];
};
type Coverage = { tactics: { tactic: string; rules: CovRule[]; total: number; applicable: number; fired: number }[]; rules: number; native: number; imported: number; analyzed: boolean };

const STATUS: Record<CovRule["status"], string> = {
  fired: "Fired",
  no_match: "Ran, no match",
  error: "Error",
  not_applicable: "No matching data",
  not_run: "Not run yet",
};
const SHOW = 8;

export default function CoveragePage() {
  const q = useQuery({ queryKey: ["coverage"], queryFn: async () => (await fetch(withCase("/api/coverage"))).json() as Promise<Coverage> });
  const [search, setSearch] = useState("");
  const [source, setSource] = useState<"all" | "native" | "sigma">("all");
  const [onlyApplicable, setOnlyApplicable] = useState(false);
  const [open, setOpen] = useState<Record<string, boolean>>({});

  const cols = useMemo(() => {
    const s = search.trim().toLowerCase();
    return (q.data?.tactics ?? []).map((c) => ({
      ...c,
      shown: c.rules.filter(
        (r) =>
          (source === "all" || r.source === source) &&
          (!onlyApplicable || r.status === "fired" || r.status === "no_match") &&
          (!s || `${r.id} ${r.title} ${r.attack.map((a) => a.id + " " + a.name).join(" ")}`.toLowerCase().includes(s)),
      ),
    }));
  }, [q.data, search, source, onlyApplicable]);

  if (q.isLoading) return <div className="page"><div className="panel empty">Loading rules…</div></div>;
  if (!q.data) return <div className="page"><div className="panel empty">Rules could not be loaded.</div></div>;
  const d = q.data;
  const covered = d.tactics.filter((t) => t.tactic !== "unmapped" && t.total > 0).length;
  const fired = d.tactics.filter((t) => t.tactic !== "unmapped" && t.fired > 0).length;

  return (
    <div className="page wide">
      <div className="page-head">
        <div>
          <div className="eyebrow">Detection rules</div>
          <h1>ATT&CK coverage</h1>
          <p>
            {d.rules.toLocaleString()} rules ({d.native} written for TrustGate, {d.imported.toLocaleString()} imported) cover {covered} of 14 tactics.
            {d.analyzed ? ` On this case's data, rules fired in ${fired} tactics.` : " Process data in this case to see which rules apply and fire."}
          </p>
        </div>
      </div>
      <div className="actionbar">
        <input id="rule-search" className="search" style={{ maxWidth: 320 }} placeholder="Search rules or technique IDs" value={search} onChange={(e) => setSearch(e.target.value)} />
        <div className="seg" role="group" aria-label="Rule source" style={{ width: 260 }}>
          {(["all", "native", "sigma"] as const).map((x) => (
            <button key={x} className={source === x ? "on" : ""} onClick={() => setSource(x)}>
              {x === "all" ? "All rules" : x === "native" ? "TrustGate" : "Sigma"}
            </button>
          ))}
        </div>
        <label className="check-inline" htmlFor="only-app">
          <input id="only-app" type="checkbox" checked={onlyApplicable} onChange={(e) => setOnlyApplicable(e.target.checked)} /> Only rules that apply to this data
        </label>
      </div>
      <div className="covgrid">
        {cols.map((c) => {
          const list = open[c.tactic] ? c.shown : c.shown.slice(0, SHOW);
          return (
            <section key={c.tactic} className={`covcol ${c.total === 0 ? "none" : ""}`}>
              <header>
                <div className="covname">{c.tactic.replace(/-/g, " ")}</div>
                <div className="covnums num">
                  <b>{c.fired}</b> fired · {c.applicable} applicable · {c.total} rules
                </div>
                <div className="covbar" aria-hidden="true">
                  <span className="a" style={{ width: `${c.total ? (c.applicable / c.total) * 100 : 0}%` }} />
                  <span className="f" style={{ width: `${c.total ? (c.fired / c.total) * 100 : 0}%` }} />
                </div>
              </header>
              {c.total === 0 && <p className="muted small">No rule. This tactic leaves no trace in host or network logs.</p>}
              <ul>
                {list.map((r) => (
                  <li key={r.id} className={`covrule st-${r.status}`} title={`${STATUS[r.status]}${r.error ? `: ${r.error}` : ""}${r.needs ? ` (needs ${r.needs.join(", ")} events)` : ""}`}>
                    <span className="dot" />
                    <span className="ct">
                      <span className="t">{r.title}</span>
                      <span className="muted small">
                        {r.id}{r.source === "sigma" ? " · Sigma" : ""}{r.findings ? ` · ${r.findings} detection${r.findings > 1 ? "s" : ""}` : ` · ${STATUS[r.status]}`}
                      </span>
                    </span>
                  </li>
                ))}
              </ul>
              {c.shown.length > SHOW && (
                <button className="btn ghost small" onClick={() => setOpen({ ...open, [c.tactic]: !open[c.tactic] })}>
                  {open[c.tactic] ? "Show fewer" : `Show all ${c.shown.length}`}
                </button>
              )}
            </section>
          );
        })}
      </div>
      <div className="small muted covlegend">
        <span className="covrule st-fired"><span className="dot" /> fired</span>
        <span className="covrule st-no_match"><span className="dot" /> ran on this data, no match</span>
        <span className="covrule st-not_applicable"><span className="dot" /> the data has no events of the kind it needs</span>
        <span className="covrule st-error"><span className="dot" /> could not run</span>
      </div>
    </div>
  );
}
