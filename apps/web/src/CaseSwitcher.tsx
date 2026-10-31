import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, caseState, setCase, withCase } from "./api";

/** Cases keep unrelated investigations apart: each has its own files, runs, published revisions and reports.
 *  Files inside one case are analyzed together, so activity that crosses them is found. */
export default function CaseSwitcher({ onChanged }: { onChanged: () => void }) {
  const qc = useQueryClient();
  const cases = useQuery({ queryKey: ["cases"], queryFn: api.cases });
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);

  const pick = (id: string) => {
    setCase(id);
    qc.removeQueries({ predicate: (q) => q.queryKey[0] !== "cases" });
    onChanged();
  };

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    const r = await fetch(withCase("/api/cases"), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name }) });
    if (!r.ok) return setError("Could not create the case.");
    const c = await r.json();
    await qc.invalidateQueries({ queryKey: ["cases"] });
    setAdding(false);
    setName("");
    pick(c.case_id);
  };

  if (adding) {
    return (
      <form className="caseform" onSubmit={create}>
        <input id="new-case-name" className="search" autoFocus placeholder="Case name, e.g. Branch office firewall" value={name} onChange={(e) => setName(e.target.value)} />
        <button className="btn primary" disabled={!name.trim()}>Create</button>
        <button type="button" className="btn ghost" onClick={() => setAdding(false)}>Cancel</button>
        {error && <span className="error small">{error}</span>}
      </form>
    );
  }
  return (
    <div className="caseswitch">
      <label className="eyebrow" htmlFor="case-select">Case</label>
      <select id="case-select" value={caseState.id} onChange={(e) => pick(e.target.value)}>
        {(cases.data ?? [{ case_id: caseState.id, name: caseState.id, created_at: "" }]).map((c) => (
          <option key={c.case_id} value={c.case_id}>{c.name}</option>
        ))}
      </select>
      <button className="btn ghost" onClick={() => setAdding(true)}>New case</button>
    </div>
  );
}
