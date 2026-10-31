import { useCallback, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { uploadFile } from "./uploads";
import { SOURCE_STATUS, fmtSize, startProcessing, useRun, useSources } from "./workspace";

type Local = { id: string; name: string; size: number; progress: number; note: string; error?: string; duplicateOf?: string };
const FILES_IN_PARALLEL = 2;

export default function UploadPage({ onStarted }: { onStarted: () => void }) {
  const qc = useQueryClient();
  const run = useRun();
  const running = run.data?.status === "running";
  const sources = useSources(running);
  const [local, setLocal] = useState<Local[]>([]);
  const [drag, setDrag] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  const addFiles = useCallback(
    async (files: File[]) => {
      if (!files.length) return;
      const items = files.map((f) => ({ file: f, id: `${f.name}-${f.size}-${Math.random().toString(36).slice(2, 7)}` }));
      setLocal((l) => [...items.map((i) => ({ id: i.id, name: i.file.name, size: i.file.size, progress: 0, note: "Waiting" })), ...l]);
      const set = (id: string, patch: Partial<Local>) => setLocal((l) => l.map((x) => (x.id === id ? { ...x, ...patch } : x)));
      let next = 0;
      const worker = async () => {
        while (next < items.length) {
          const it = items[next++];
          try {
            const r = await uploadFile(it.file, (p, note) => set(it.id, { progress: p, note: note ?? "" }));
            set(it.id, r.duplicate_of ? { progress: 1, note: "Already uploaded", duplicateOf: r.duplicate_of } : { progress: 1, note: "Uploaded" });
          } catch (e) {
            set(it.id, { error: String(e).replace(/^Error: /, "") });
          }
          qc.invalidateQueries({ queryKey: ["sources"] });
        }
      };
      await Promise.all(Array.from({ length: Math.min(FILES_IN_PARALLEL, items.length) }, worker));
    },
    [qc],
  );

  const all = sources.data ?? [];
  const ready = all.filter((s) => s.status === "uploaded" || s.status === "failed");
  const parsed = all.filter((s) => s.status === "ingested");
  const uploading = local.some((l) => !l.error && l.progress < 1);

  const start = async () => {
    setError(null);
    setStarting(true);
    try {
      await startProcessing();
      qc.invalidateQueries({ queryKey: ["run"] });
      qc.invalidateQueries({ queryKey: ["sources"] });
      onStarted();
    } catch (e) {
      setError(String(e).replace(/^Error: \d+ /, ""));
    } finally {
      setStarting(false);
    }
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="eyebrow">Step 1</div>
          <h1>Upload log files</h1>
          <p>Any format works: JSON lines, syslog, CEF, LEEF, CSV, key=value, or compressed .gz/.zst. Files go straight to storage in parts, so large files and several at once are fine.</p>
        </div>
      </div>

      <div
        className={`drop ${drag ? "on" : ""}`}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && input.current?.click()}
        onDragOver={(e) => (e.preventDefault(), setDrag(true))}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDrag(false);
          addFiles([...e.dataTransfer.files]);
        }}
        onClick={() => input.current?.click()}
      >
        <input id="file-input" ref={input} type="file" multiple hidden onChange={(e) => (e.target.files && addFiles([...e.target.files]), (e.target.value = ""))} />
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" aria-hidden="true">
          <path d="M12 16V4M7 9l5-5 5 5" />
          <path d="M4 16v3a1 1 0 001 1h14a1 1 0 001-1v-3" />
        </svg>
        <b>Drop files here, or click to choose</b>
        <span className="muted small">Up to 50 GB per file · the same file uploaded twice is detected and reused</span>
      </div>

      {local.length > 0 && (
        <section className="panel files" aria-label="Uploads in this session">
          {local.map((l) => (
            <div className="file" key={l.id}>
              <div className="name">
                <div className="mono">{l.name}</div>
                <div className={`small ${l.error ? "error" : "muted"}`}>
                  {l.error ?? (l.duplicateOf ? `Same content as ${l.duplicateOf}; not uploaded again` : l.note)}
                </div>
              </div>
              <div className={`progress ${l.error ? "bad" : ""}`}>
                <div style={{ width: `${Math.round(l.progress * 100)}%` }} />
              </div>
              <div className="stat small num muted">
                {Math.round(l.progress * 100)}% of {fmtSize(l.size)}
              </div>
            </div>
          ))}
        </section>
      )}

      <div className="actionbar">
        <button className="btn primary" onClick={start} disabled={starting || running || uploading || (ready.length === 0 && parsed.length === 0)}>
          {running ? "Processing…" : ready.length ? `Start processing ${ready.length} file${ready.length > 1 ? "s" : ""}` : "Re-run analysis"}
        </button>
        {uploading && <span className="muted small">Processing starts once uploads finish.</span>}
        {running && (
          <button className="btn ghost" onClick={onStarted}>
            View progress →
          </button>
        )}
        {error && <span className="error small">{error}</span>}
      </div>

      <section>
        <div className="eyebrow" style={{ marginBottom: 8 }}>
          Files in this workspace
        </div>
        <div className="panel files">
          {all.length === 0 && <div className="empty">No files yet. Uploaded files appear here.</div>}
          {all.map((s) => {
            const st = SOURCE_STATUS[s.status] ?? { label: s.status, tone: "" };
            return (
              <div className="file" key={s.source_id}>
                <div className="name">
                  <div className="mono">{s.filename}</div>
                  <div className="muted small num">
                    {fmtSize(s.size)} · added {s.created_at.slice(0, 16).replace("T", " ")}
                    {s.summary ? ` · ${s.summary.events.toLocaleString()} events` : ""}
                    {s.duplicate_of ? ` · same content as ${s.duplicate_of}` : ""}
                  </div>
                  {s.error && <div className="error small">{s.error}</div>}
                </div>
                <div className="small muted">{s.summary?.format ?? ""}</div>
                <div className="stat">
                  <span className={`tag ${st.tone}`}>{st.label}</span>
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}
