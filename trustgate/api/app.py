"""FastAPI over a published graph snapshot (no corpus scans per request).

    TRUSTGATE_SNAPSHOT=path-or-s3-uri uvicorn trustgate.api.app:app --port 8000
"""
import contextvars
import json
import os
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

import yaml
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[2]
TARGET_SAMPLE = 8  # attempted usernames shown per finding; the rest are summarized

app = FastAPI(title="TrustGate API", version="0.1.0")


def _read(uri: str) -> bytes:
    if uri.startswith("s3://"):
        import boto3
        b, k = uri[5:].split("/", 1)
        from ..service import state
        return boto3.client("s3", region_name=state._env("AWS_REGION")).get_object(Bucket=b, Key=k)["Body"].read()
    return Path(uri).read_bytes()


EMPTY = {k: [] for k in ("findings", "ips", "users", "involves", "incidents", "links", "auth", "flows", "configured",
                         "bundle", "hubs", "sources")}
_cases: dict = {}  # case id -> {"key", "store", "head_at", "head"}
_static: dict = {}  # pinned snapshot path -> indexed store
# set by the report worker to render one exact snapshot file (case + revision pinned at request time)
PINNED_SNAPSHOT = contextvars.ContextVar("trustgate_pinned_snapshot", default=None)


def _case():
    from ..service import state
    return state.ws()


def _head():
    """Published head of the current case, re-checked every few seconds (None = nothing published)."""
    import time
    c = _cases.setdefault(_case(), {"key": None, "store": None, "head_at": 0.0, "head": None})
    if time.time() - c["head_at"] > 3:
        from ..service import state
        c["head"], c["head_at"] = state.get_head(), time.time()
    return c["head"]


def snapshot_file(case: str, revision: int) -> Path:
    return ROOT / "data" / "snapshots" / case / f"rev-{revision}.json"


def store():
    """A pinned snapshot (tests, report worker) or the current case's published head revision.
    No head -> empty board."""
    path = PINNED_SNAPSHOT.get() or os.environ.get("TRUSTGATE_SNAPSHOT")
    if path:
        if path not in _static:
            _static.clear()
            _static[path] = _index(json.loads(_read(str(path))))
        return _static[path]
    head = _head()
    c = _cases[_case()]
    if not head:
        key, loader = "empty", lambda: EMPTY
    else:
        key = f"rev-{head['revision']}"
        local = snapshot_file(_case(), head["revision"])

        def loader():
            if not local.exists():
                from ..service import state
                local.parent.mkdir(parents=True, exist_ok=True)
                tmp = local.with_suffix(".tmp")
                tmp.write_bytes(_read(f"s3://{state._env('TRUSTGATE_LAKE_BUCKET')}/{head['snapshot_key']}"))
                os.replace(tmp, local)
            return json.loads(local.read_bytes())
    if c["key"] != key:
        c["store"], c["key"] = _index(loader()), key
    return c["store"]


def _index(snap):
    s = {"snap": snap}
    s["findings"] = {f["id"]: f for f in snap["findings"]}
    s["ips"] = {i["addr"]: i for i in snap["ips"]}
    s["users"] = {u["name"]: u for u in snap.get("users", [])}
    s["hubs"] = {h["value"]: h["degree"] for h in snap.get("hubs", [])}
    s["involves"] = defaultdict(list)
    for r in snap["involves"]:
        s["involves"][r["finding_id"]].append(r)
    s["events"] = {e["uid"]: e for e in snap.get("bundle", [])}
    s["events_by_finding"] = defaultdict(list)
    for e in snap.get("bundle", []):
        for fid in e["finding_ids"]:
            s["events_by_finding"][fid].append(e["uid"])
    s["incidents"] = {i["id"]: i for i in snap["incidents"]}
    return s


def _incident_sources(inc, s):
    """Which uploaded files this incident's evidence came from (cross-file incidents list several)."""
    names = {x["source_id"]: x.get("filename", x["source_id"]) for x in s["snap"].get("sources", [])}
    sids = sorted({s["events"][u].get("source_id") for f in inc["finding_ids"] for u in s["events_by_finding"][f]} - {None})
    return [{"source_id": sid, "filename": names.get(sid, sid)} for sid in sids]


def _title(inc, s):
    best = max((s["findings"][f] for f in inc["finding_ids"]), key=lambda f: ({"low": 1, "medium": 2, "high": 3, "critical": 4}[f["severity"]], f["event_count"]))
    return best["title"]


@app.get("/api/summary")
def summary():
    s = store()
    by_rule = defaultdict(int)
    for f in s["snap"]["findings"]:
        by_rule[f["rule_id"]] += 1
    return {"findings": len(s["findings"]), "incidents": len(s["incidents"]), "entities_ips": len(s["ips"]),
            "entities_users": len(s["snap"]["users"]), "findings_by_rule": by_rule,
            "bundle_events": len(s["events"]), "graph_version": s["snap"]["incidents"][0]["version"] if s["incidents"] else None,
            "revision": s["snap"].get("revision"), "sources": s["snap"].get("sources", []),
            "growth": s["snap"].get("growth", []),
            "empty": not s["snap"]["incidents"] and not s["snap"]["findings"]}


@app.get("/api/incidents")
def incidents():
    s = store()
    out = []
    for i in s["snap"]["incidents"]:
        fs = [s["findings"][f] for f in i["finding_ids"]]
        out.append({k: i[k] for k in ("id", "status", "first", "last", "stages", "rules", "max_severity", "risk", "version")}
                   | {k: i.get(k) for k in ("first_rev", "change", "change_rev")}
                   | {"title": _title(i, s), "risk_factors": json.loads(i["risk_factors"]), "finding_count": len(fs),
                      "event_count": sum(f["event_count"] for f in fs),
                      "degraded_clock": any(f["time_reliability"] != "ok" for f in fs),
                      "sources": _incident_sources(i, s)})
    return sorted(out, key=lambda x: -x["risk"])


def _node(kind, key, s, role=None):
    if kind == "ip":
        ip = s["ips"].get(key, {"addr": key})
        return {"id": f"ip:{key}", "type": "ip", "label": key, "data": ip | {"hub_degree": s["hubs"].get(key, 0)}}
    if kind == "user":
        return {"id": f"u:{key}", "type": "user", "label": key,
                "data": {"name": key, "hub_degree": s["hubs"].get(key, 0), "first_rev": s["users"].get(key, {}).get("first_rev")}}
    return {"id": f"d:{key}", "type": "device", "label": key, "data": {"name": key}}


@app.get("/api/incidents/{inc_id}")
def incident(inc_id: str):
    s = store()
    inc = s["incidents"].get(inc_id)
    if not inc:
        raise HTTPException(404, "unknown incident")
    fids = set(inc["finding_ids"])
    nodes, edges, hidden = {}, [], defaultdict(int)
    for fid in fids:
        f = s["findings"][fid]
        nodes[f"f:{fid}"] = {"id": f"f:{fid}", "type": "finding", "label": f["title"],
                             "data": f | {"attack": json.loads(f["attack"]), "keys": json.loads(f["keys"] or "null")}}
        targeted = 0
        for r in s["involves"][fid]:
            if r["role"] == "targeted_account":
                targeted += 1
                if targeted > TARGET_SAMPLE:
                    hidden[fid] += 1
                    continue
            n = _node(r["kind"], r["value"], s)
            nodes.setdefault(n["id"], n)
            edges.append({"id": f"inv:{fid}:{n['id']}:{r['role']}", "source": f"f:{fid}", "target": n["id"],
                          "type": "INVOLVES", "label": r["role"],
                          "data": {"role": r["role"], "decision": "engine_detection", "first_rev": f.get("first_rev")}})
    ent = {k for k in nodes if not k.startswith("f:")}
    for l in s["snap"]["links"]:
        if l["a"] in fids and l["b"] in fids:
            edges.append({"id": f"rel:{l['a']}:{l['b']}:{l['basis']}:{l['entity']}", "source": f"f:{l['a']}",
                          "target": f"f:{l['b']}", "type": "RELATED", "label": l["basis"],
                          "data": l | {"checks": json.loads(l["checks"]), "missing": json.loads(l["missing"])}})
    for a in s["snap"]["auth"]:
        if f"ip:{a['src_ip']}" in ent or f"u:{a['user']}" in ent:
            for n in (_node("ip", a["src_ip"], s), _node("user", a["user"], s)):
                nodes.setdefault(n["id"], n)
            edges.append({"id": f"auth:{a['src_ip']}:{a['user']}:{a['outcome']}", "source": f"ip:{a['src_ip']}",
                          "target": f"u:{a['user']}", "type": "AUTH", "label": f"login {a['outcome']} ×{a['count']}",
                          "data": a | {"decision": "observed"}})
    for fl in s["snap"]["flows"]:
        if f"ip:{fl['src_ip']}" in ent and (f"ip:{fl['dst_ip']}" in ent or len(ent) < 60):
            n = _node("ip", fl["dst_ip"], s)
            nodes.setdefault(n["id"], n)
            edges.append({"id": f"flow:{fl['src_ip']}:{fl['dst_ip']}:{fl['dst_port']}", "source": f"ip:{fl['src_ip']}",
                          "target": n["id"], "type": "FLOW", "label": f":{fl['dst_port']} ×{fl['count']}",
                          "data": fl | {"decision": "observed"}})
    for c in s["snap"]["configured"]:
        if f"u:{c['user']}" in ent:
            n = _node("device", c["device"], s)
            nodes.setdefault(n["id"], n)
            edges.append({"id": f"cfg:{c['event_uid']}", "source": f"u:{c['user']}", "target": n["id"],
                          "type": "CONFIGURED", "label": c["action"], "data": c | {"decision": "observed"}})
    uids = sorted({u for fid in fids for u in s["events_by_finding"][fid]}, key=lambda u: s["events"][u]["time"])
    events = [{k: v for k, v in s["events"][u].items() if k != "raw"} for u in uids]
    summary = next(i for i in incidents() if i["id"] == inc_id)
    return {"incident": summary, "nodes": list(nodes.values()), "edges": edges, "events": events,
            "hidden_targeted_accounts": hidden}


@app.get("/api/events/{uid}")
def event(uid: str):
    e = store()["events"].get(uid)
    if not e:
        raise HTTPException(404, "event not in a published evidence bundle")
    return e


@app.get("/api/findings")
def findings(rule_id: str | None = None, limit: int = Query(100, le=1000), offset: int = 0):
    fs = [f for f in store()["snap"]["findings"] if not rule_id or f["rule_id"] == rule_id]
    fs.sort(key=lambda f: f["first"])
    return {"total": len(fs), "items": fs[offset:offset + limit]}


@lru_cache(maxsize=1)
def _ruleset():
    from ..detection.rules import load_rules
    return load_rules(str(ROOT / "config" / "rules"))


@app.get("/api/coverage")
def coverage():
    """Every rule under the 14 ATT&CK tactics, with its status on this case's data."""
    from ..detection.rules import TACTICS
    rs = _ruleset()
    status = store()["snap"].get("rule_status", {})
    cols = {t: [] for t in TACTICS + ["unmapped"]}
    for r in rs.rules:
        st = status.get(r.id, {"status": "not_run", "findings": 0})
        item = {"id": r.id, "title": r.title, "severity": r.severity, "type": r.type, "stage": r.stage,
                "attack": [t.model_dump() for t in r.attack], "source": (r.source or {}).get("kind", "native"),
                "status": st["status"], "findings": st.get("findings", 0), "error": st.get("error"), "needs": st.get("needs")}
        for t in (r.tactics or [r.stage]):
            cols.setdefault(t, []).append(item)
    order = {"fired": 0, "no_match": 1, "error": 2, "not_applicable": 3, "not_run": 4}
    out = []
    for t, items in cols.items():
        items.sort(key=lambda i: (order.get(i["status"], 9), i["source"] != "native", i["id"]))
        out.append({"tactic": t, "rules": items, "total": len(items),
                    "applicable": sum(i["status"] in ("fired", "no_match") for i in items),
                    "fired": sum(i["status"] == "fired" for i in items)})
    return {"tactics": out, "rules": len(rs.rules), "native": sum(not r.source for r in rs.rules),
            "imported": sum(bool(r.source) for r in rs.rules), "analyzed": bool(status)}


@app.get("/api/rules")
def rules():
    with open(ROOT / "config" / "rules" / "core.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------- uploads, sources, processing
PART_SIZE = 64 << 20
MAX_PARTS = 10000


def _aws(service):
    import boto3
    from ..service import state
    return boto3.client(service, region_name=state._env("AWS_REGION"))


class UploadRequest(BaseModel):
    filename: str
    size: int
    quick_fp: str  # sha256(first MiB + last MiB + size), computed in the browser


class CompleteRequest(BaseModel):
    parts: list[dict]


@app.post("/api/uploads", status_code=201)
def create_upload(req: UploadRequest):
    from ..service import state
    if req.size <= 0 or req.size > PART_SIZE * MAX_PARTS:
        raise HTTPException(400, "file size out of range")
    name = "".join(ch for ch in os.path.basename(req.filename) if ch.isalnum() or ch in "._-")[:120] or "upload.log"
    for o in state.list_sources():  # same bytes already uploaded (or uploading): reuse, never double count
        if o.get("quick_fp") == req.quick_fp and int(o.get("size", -1)) == req.size and o["status"] not in ("failed", "aborted"):
            return {"duplicate_of": o["source_id"], "source": o}
    sid = state.new_id("src")
    key = f"sources/{sid}/{name}"
    s3 = _aws("s3")
    bucket = state._env("TRUSTGATE_RAW_BUCKET")
    up = s3.create_multipart_upload(Bucket=bucket, Key=key, Metadata={"source-id": sid, "original-name": name})
    n = max(1, -(-req.size // PART_SIZE))
    urls = [s3.generate_presigned_url("upload_part", Params={"Bucket": bucket, "Key": key, "UploadId": up["UploadId"],
                                                              "PartNumber": i}, ExpiresIn=6 * 3600) for i in range(1, n + 1)]
    state.put_source({"source_id": sid, "filename": name, "size": req.size, "quick_fp": req.quick_fp, "key": key,
                      "upload_id": up["UploadId"], "status": "uploading", "created_at": state.now()})
    return {"source_id": sid, "part_size": PART_SIZE, "urls": urls}


@app.post("/api/uploads/{sid}/complete")
def complete_upload(sid: str, req: CompleteRequest):
    from ..service import state
    src = state.get_source(sid)
    if not src or src["status"] != "uploading":
        raise HTTPException(409, "upload is not in progress")
    parts = sorted(({"PartNumber": int(p["PartNumber"]), "ETag": str(p["ETag"])} for p in req.parts),
                   key=lambda p: p["PartNumber"])
    r = _aws("s3").complete_multipart_upload(Bucket=state._env("TRUSTGATE_RAW_BUCKET"), Key=src["key"],
                                             UploadId=src["upload_id"], MultipartUpload={"Parts": parts})
    state.update_source(sid, expected_status="uploading", status="uploaded", version_id=r.get("VersionId") or "",
                        uploaded_at=state.now())
    return state.get_source(sid)


@app.post("/api/uploads/{sid}/abort")
def abort_upload(sid: str):
    from ..service import state
    src = state.get_source(sid)
    if src and src["status"] == "uploading":
        _aws("s3").abort_multipart_upload(Bucket=state._env("TRUSTGATE_RAW_BUCKET"), Key=src["key"], UploadId=src["upload_id"])
        state.update_source(sid, status="aborted")
    return {"ok": True}


@app.get("/api/sources")
def sources():
    from ..service import state
    out = sorted(state.list_sources(), key=lambda s: s["created_at"], reverse=True)
    for s in out:
        if isinstance(s.get("summary"), str):
            s["summary"] = json.loads(s["summary"])
        s.pop("upload_id", None)
    return out


def _ensure_worker():
    """Start the EC2 processing worker if it is stopped; it stops itself after idling."""
    from ..service import state
    try:
        iid = state._env("TRUSTGATE_WORKER_INSTANCE_ID")
    except RuntimeError:
        return "not_configured"
    ec2 = _aws("ec2")
    st = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]["State"]["Name"]
    if st == "stopped":
        ec2.start_instances(InstanceIds=[iid])
        return "starting"
    return st


@app.post("/api/process", status_code=202)
def process():
    from ..service import state
    from ..service.worker import send
    srcs = state.list_sources()
    todo = [s for s in srcs if s["status"] in ("uploaded", "failed") and s.get("key")]
    if not todo and not any(s["status"] == "ingested" for s in srcs):
        raise HTTPException(400, "nothing to process: upload at least one log file first")
    rid = state.new_id("run")
    state.put_run({"run_id": rid, "status": "running", "created_at": state.now(), "pending": len(todo),
                   "done_sources": {"-"}, "sources": [s["source_id"] for s in todo], "steps": {}})
    for s in todo:
        state.update_source(s["source_id"], status="queued", run_id=rid)
        send({"type": "ingest", "run_id": rid, "source_id": s["source_id"]})
    if not todo:  # only re-analysis of already ingested data
        send({"type": "analyze", "run_id": rid})
    return {"run_id": rid, "worker": _ensure_worker(), "sources": len(todo)}


@app.get("/api/runs/latest")
def latest_run():
    from ..service import state
    r = state.latest_run()
    if r:
        r.pop("done_sources", None)
    return r


REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6380")
BULL_BOARD_URL = os.environ.get("BULL_BOARD_URL", "http://localhost:3001/admin/queues")
_queue = None


def _reports_queue():
    global _queue
    if _queue is None:
        from bullmq import Queue
        _queue = Queue("reports", {"connection": REDIS_URL})
    return _queue


@lru_cache(maxsize=64)
def _snap_sha(path: str) -> str:
    """Revision files are immutable, so their hash is cached by path."""
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


@app.get("/api/incidents/{inc_id}/story")
def incident_story(inc_id: str):
    """Canonical deterministic story (no LLM, no PDF) for the UI."""
    if inc_id not in store()["incidents"]:
        raise HTTPException(404, "unknown incident")
    from ..reports.pipeline import build_story
    doc, _ = build_story(inc_id)
    doc.pop("evidence_index")
    doc.pop("appendix")
    return doc


class ReportRequest(BaseModel):
    use_llm: bool = True


@app.post("/api/incidents/{inc_id}/reports", status_code=202)
async def request_report(inc_id: str, req: ReportRequest):
    if inc_id not in store()["incidents"]:
        raise HTTPException(404, "unknown incident")
    from bullmq import Job
    from ..reports.pipeline import report_id
    head = _head()
    if not head:
        raise HTTPException(409, "nothing published in this case")
    snap = snapshot_file(_case(), head["revision"])  # pin case + revision now; later revisions never change it
    rid = report_id(inc_id, _snap_sha(str(snap)), req.use_llm)
    q = _reports_queue()
    existing = await Job.fromId(q, rid)
    if existing and await existing.getState() == "failed":
        await existing.remove()  # explicit re-request after a failure starts a fresh attempt
        existing = None
    if not existing:
        await q.add("render", {"incident_id": inc_id, "use_llm": req.use_llm, "case": _case(), "revision": head["revision"],
                               "snapshot": snap.relative_to(ROOT / "data").as_posix()},
                    {"jobId": rid, "attempts": 3, "backoff": {"type": "exponential", "delay": 20000},
                     "removeOnComplete": {"age": 7 * 86400}, "removeOnFail": {"age": 7 * 86400}})
    return {"report_id": rid, "status_url": f"/api/reports/{rid}", "bull_board": BULL_BOARD_URL}


@app.get("/api/reports/{rid}")
async def report_status(rid: str):
    from ..reports.pipeline import REPORTS_DIR
    m = REPORTS_DIR / rid / "manifest.json"
    if m.exists():
        return {"report_id": rid, "state": "stored", "stage": "stored", "manifest": json.loads(m.read_text()),
                "download_url": f"/api/reports/{rid}/download"}
    from bullmq import Job
    job = await Job.fromId(_reports_queue(), rid)
    if not job:
        raise HTTPException(404, "unknown report")
    state = await job.getState()
    prog = job.progress if isinstance(job.progress, dict) else {}
    return {"report_id": rid, "state": state, "stage": "failed" if state == "failed" else prog.get("stage", state),
            "error": job.failedReason or None, "attempts": job.attemptsMade}


@app.get("/api/reports/{rid}/download")
def report_download(rid: str):
    from ..reports.pipeline import REPORTS_DIR
    if not rid.startswith("rpt-") or not rid[4:].isalnum():
        raise HTTPException(400, "bad report id")
    pdf = REPORTS_DIR / rid / "report.pdf"
    if not pdf.exists():
        raise HTTPException(404, "report not ready")
    return FileResponse(pdf, media_type="application/pdf", filename=f"trustgate-{rid}.pdf")


@app.middleware("http")
async def case_scope(request, call_next):
    """Every API call works inside one case (?case=<id>, default "default")."""
    from ..service import state
    try:
        state.use_case(request.query_params.get("case", "default"))
    except ValueError:
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "invalid case id"}, status_code=400)
    return await call_next(request)


class CaseRequest(BaseModel):
    name: str


@app.get("/api/cases")
def cases():
    from ..service import state
    out = state.list_cases()
    if not any(c["case_id"] == "default" for c in out):
        out.insert(0, {"case_id": "default", "name": "First case", "created_at": ""})
    return sorted(out, key=lambda c: c.get("created_at", ""))


@app.post("/api/cases", status_code=201)
def create_case(req: CaseRequest):
    import re as _re
    from ..service import state
    name = req.name.strip()
    if not name:
        raise HTTPException(400, "give the case a name")
    cid = (_re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:28] or "case") + "-" + state.new_id("c")[-4:]
    state.put_case(cid, name)
    return {"case_id": cid, "name": name}


@app.delete("/api/cases/{case_id}")
def delete_case(case_id: str):
    import shutil
    from ..service import state
    if case_id == "default":
        raise HTTPException(400, "the first case cannot be deleted")
    try:
        out = state.delete_case(case_id)
    except ValueError:
        raise HTTPException(400, "invalid case id")
    except RuntimeError as e:
        raise HTTPException(409, str(e))
    shutil.rmtree(ROOT / "data" / "snapshots" / case_id, ignore_errors=True)
    _cases.pop(case_id, None)
    return out


_dist = ROOT / "apps" / "web" / "dist"
if _dist.exists():
    app.mount("/assets", StaticFiles(directory=_dist / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        f = (_dist / path).resolve()
        if path and f.is_file() and f.is_relative_to(_dist.resolve()):
            return FileResponse(f)
        return FileResponse(_dist / "index.html")
