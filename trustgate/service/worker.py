"""Processing worker (EC2): consumes the SQS ingest queue.

  {"type": "ingest",  "run_id", "source_id"}  parse one uploaded file -> canonical Parquet
  {"type": "analyze", "run_id"}               detect + graph over ALL ingested sources -> new snapshot revision

Files are parsed independently and in parallel, but analysis always runs over
the union of every ingested source, so windows/sequences that cross file
boundaries (e.g. consecutive hourly files from one firewall) are evaluated
once. One analysis per workspace at a time (DynamoDB lease); a run that
arrives while another analysis holds the lease waits and then publishes the
next revision. The board only changes when a complete snapshot is published.

    python -m trustgate.service.worker
"""
import json
import os
import threading
import time
import traceback

import boto3

from . import state

IDLE_STOP_MIN = int(os.environ.get("TRUSTGATE_IDLE_STOP_MIN", "30"))
RULES = os.environ.get("TRUSTGATE_RULES", "config/rules/core.yaml")


def _sqs():
    return boto3.client("sqs", region_name=state._env("AWS_REGION"))


def _lake():
    return state._env("TRUSTGATE_LAKE_BUCKET")


def send(msg: dict, delay=0):
    msg = {"case": state.ws(), **msg}
    _sqs().send_message(QueueUrl=state._env("TRUSTGATE_INGEST_QUEUE_URL"), MessageBody=json.dumps(msg), DelaySeconds=delay)


class Heartbeat(threading.Thread):
    """Keeps a long job's SQS message invisible so it is not redelivered mid-run."""

    def __init__(self, receipt):
        super().__init__(daemon=True)
        self.receipt, self.stop = receipt, threading.Event()

    def run(self):
        while not self.stop.wait(240):
            try:
                _sqs().change_message_visibility(QueueUrl=state._env("TRUSTGATE_INGEST_QUEUE_URL"),
                                                 ReceiptHandle=self.receipt, VisibilityTimeout=900)
            except Exception:
                pass


def _step(run_id, name, status, **extra):
    run = state.get_run(run_id) or {}
    steps = run.get("steps", {})
    steps[name] = {"status": status, "at": state.now(), **extra}
    state.update_run(run_id, steps=steps)


def handle_ingest(msg):
    from ..ingest.pipeline import IngestConfig, ingest
    rid, sid = msg["run_id"], msg["source_id"]
    src = state.get_source(sid)
    if src and src["status"] not in ("ingested", "duplicate"):
        state.update_source(sid, status="ingesting", ingest_started_at=state.now())
        _step(rid, f"ingest:{sid}", "running", filename=src["filename"])
        cfg = IngestConfig(workers=max(1, (os.cpu_count() or 2)))
        m = ingest(f"s3://{state._env('TRUSTGATE_RAW_BUCKET')}/{src['key']}", f"s3://{_lake()}/canonical/source={sid}",
                   sid, cfg, log=lambda s: print(f"[{sid}] {s}", flush=True))
        dup = next((o for o in state.list_sources() if o["source_id"] != sid and o["status"] == "ingested"
                    and o.get("content_sha256") == m["stored_sha256"]), None)
        sch = m["schema"]
        summary = {"format": m["format"], "compression": m["compression"], "events": m["accounting"]["normalized"],
                   "quarantined": m["accounting"]["quarantined"], "first": m["event_time_range"][0],
                   "last": m["event_time_range"][1], "layouts": sch["distinct_layouts"], "drift_layouts": len(sch["drift"]),
                   "inferred": {k: v["key"] for k, v in sch["inferred_mappings"].items()},
                   "coverage": sch["coverage"], "elapsed_s": m["elapsed_s"]}
        if dup:  # same bytes already analyzed: keep provenance, drop the duplicate canonical copy
            s3 = boto3.resource("s3", region_name=state._env("AWS_REGION"))
            s3.Bucket(_lake()).objects.filter(Prefix=f"canonical/source={sid}/").delete()
            state.update_source(sid, status="duplicate", duplicate_of=dup["source_id"], content_sha256=m["stored_sha256"],
                                summary=json.dumps(summary))
        else:
            state.update_source(sid, status="ingested", content_sha256=m["stored_sha256"], summary=json.dumps(summary),
                                ingested_at=state.now())
        _step(rid, f"ingest:{sid}", "done", filename=src["filename"], duplicate_of=dup["source_id"] if dup else None,
              events=summary["events"])
    if state.finish_ingest(rid, sid) <= 0:
        send({"type": "analyze", "run_id": rid})


def _source_relations(con, sources):
    rows = con.execute("""SELECT source_id, min(event_time)::VARCHAR, max(event_time)::VARCHAR,
                                 list_distinct(list(device) FILTER (device IS NOT NULL))[1:10], count(*)
                          FROM ev GROUP BY source_id""").fetchall()
    info = {r[0]: {"first": r[1], "last": r[2], "devices": r[3], "events": r[4]} for r in rows}
    out = []
    for s in sources:
        i = info.get(s["source_id"], {})
        rel = []
        for o in sources:
            j = info.get(o["source_id"])
            if o["source_id"] == s["source_id"] or not i or not j:
                continue
            overlap = i["first"] <= j["last"] and j["first"] <= i["last"]
            shared = sorted(set(i["devices"]) & set(j["devices"]))
            if overlap or shared:
                why = ("same device " + ", ".join(shared[:3]) if shared else "") + (
                    (" and " if shared and overlap else "") + "overlapping time range" if overlap else "")
                rel.append({"source_id": o["source_id"], "filename": o["filename"], "reason": why.strip()})
        out.append({"source_id": s["source_id"], "filename": s["filename"], **i, "related": rel})
    return out


def handle_analyze(msg, receipt):
    from ..detection import engine
    from ..detection.rules import load_rules
    from ..graph import build as g
    rid = msg["run_id"]
    if not state.acquire_lock(rid):
        _step(rid, "analyze", "waiting", note="another analysis is publishing; this run follows it")
        _sqs().change_message_visibility(QueueUrl=state._env("TRUSTGATE_INGEST_QUEUE_URL"), ReceiptHandle=receipt,
                                         VisibilityTimeout=60)
        return False  # keep the message; retried after the current analysis
    try:
        srcs = sorted((s for s in state.list_sources() if s["status"] == "ingested"), key=lambda s: s["created_at"])
        if not srcs:
            state.update_run(rid, status="nothing_to_analyze", finished_at=state.now())
            return True
        ids = [s["source_id"] for s in srcs]
        head = state.get_head()
        if head and sorted(head["sources"]) == sorted(ids):  # coalesced: data already published
            state.update_run(rid, status="published", revision=head["revision"], finished_at=state.now(),
                             note="no new data since the published revision")
            return True
        rev = (head["revision"] if head else 0) + 1
        globs = [f"s3://{_lake()}/canonical/source={i}/events/*.parquet" for i in ids]
        fdir = f"s3://{_lake()}/findings/ws={state.ws()}/rev-{rev}"
        _step(rid, "detect", "running")
        con = engine.connect(temp_dir="/data/duckdb-spill" if os.path.isdir("/data/duckdb-spill") else None)
        res = engine.run(load_rules(RULES), globs, fdir, con=con, log=lambda s: print(s, flush=True))
        _step(rid, "detect", "done", findings=sum(res["findings"].values()))
        _step(rid, "graph", "running")
        graph = g.build(globs, fdir, con=con)
        graph["sources"] = _source_relations(con, srcs)
        graph["revision"] = rev
        if os.environ.get("NEO4J_PASSWORD"):
            try:
                g.load(graph, os.environ.get("NEO4J_URI", "bolt://localhost:7687"), "neo4j", os.environ["NEO4J_PASSWORD"])
            except Exception as e:  # graph DB is a secondary view; the published snapshot is authoritative
                print(f"neo4j load failed: {e}", flush=True)
        _step(rid, "graph", "done", incidents=len(graph["incidents"]))
        _step(rid, "publish", "running")
        key = f"graph/ws={state.ws()}/rev-{rev}.json"
        g.write_snapshot(graph, f"s3://{_lake()}/{key}")
        state.advance_head(rev, key, rid, ids)
        _step(rid, "publish", "done", revision=rev)
        state.update_run(rid, status="published", revision=rev, finished_at=state.now())
        return True
    finally:
        state.release_lock(rid)


def main():
    q = state._env("TRUSTGATE_INGEST_QUEUE_URL")
    last_work = time.time()
    print("processing worker ready", flush=True)
    while True:
        r = _sqs().receive_message(QueueUrl=q, MaxNumberOfMessages=1, WaitTimeSeconds=20, VisibilityTimeout=900)
        msgs = r.get("Messages", [])
        if not msgs:
            if IDLE_STOP_MIN and time.time() - last_work > IDLE_STOP_MIN * 60:
                print(f"idle for {IDLE_STOP_MIN} min: stopping this instance to save cost", flush=True)
                os.system("shutdown -h now")
                time.sleep(120)
            continue
        m = msgs[0]
        last_work = time.time()
        hb = Heartbeat(m["ReceiptHandle"])
        hb.start()
        delete = True
        try:
            body = json.loads(m["Body"])
            state.use_case(body.get("case", "default"))
            if body["type"] == "ingest":
                handle_ingest(body)
            elif body["type"] == "analyze":
                delete = handle_analyze(body, m["ReceiptHandle"])
        except Exception as e:
            traceback.print_exc()
            body = json.loads(m["Body"]) if m.get("Body") else {}
            if body.get("run_id"):
                state.update_run(body["run_id"], status="failed", error=f"{type(e).__name__}: {e}"[:500])
            if body.get("source_id"):
                state.update_source(body["source_id"], status="failed", error=f"{type(e).__name__}: {e}"[:500])
            delete = int(m.get("Attributes", {}).get("ApproximateReceiveCount", "1")) >= 3
        finally:
            hb.stop.set()
            last_work = time.time()
        if delete:
            _sqs().delete_message(QueueUrl=q, ReceiptHandle=m["ReceiptHandle"])


if __name__ == "__main__":
    main()
