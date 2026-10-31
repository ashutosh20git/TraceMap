"""Simulate batches arriving over time: upload each file to a case and process it before the next
arrives, using the same API calls as the UI (presigned multipart upload straight to S3).

    python scripts/stream_batches.py "<case name>" batch-1.jsonl batch-2.jsonl ...
"""
import hashlib
import json
import sys
import time
import urllib.request

API = "http://127.0.0.1:8000"


def call(path, data=None, method=None, case=None):
    url = API + path + (("&" if "?" in path else "?") + f"case={case}" if case else "")
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                 method=method or ("POST" if data is not None else "GET"), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())


def upload(path, case):
    body = open(path, "rb").read()
    fp = hashlib.sha256(body[:1 << 20] + body[-(1 << 20):] + str(len(body)).encode()).hexdigest()
    s = call("/api/uploads", {"filename": path.replace("\\", "/").split("/")[-1], "size": len(body), "quick_fp": fp}, case=case)
    if s.get("duplicate_of"):
        return s["duplicate_of"]
    parts = []
    for i, url in enumerate(s["urls"]):
        chunk = body[i * s["part_size"]:(i + 1) * s["part_size"]]
        with urllib.request.urlopen(urllib.request.Request(url, data=chunk, method="PUT"), timeout=600) as r:
            parts.append({"PartNumber": i + 1, "ETag": r.headers["ETag"]})
    call(f"/api/uploads/{s['source_id']}/complete", {"parts": parts}, case=case)
    return s["source_id"]


def main():
    name, files = sys.argv[1], sys.argv[2:]
    case = call("/api/cases", {"name": name})["case_id"]
    print(f"case {case}")
    for f in files:
        sid = upload(f, case)
        run = call("/api/process", {}, case=case)
        print(f"{f.split(chr(92))[-1].split('/')[-1]} -> {sid}, run {run['run_id']} (worker {run['worker']})", flush=True)
        while True:
            time.sleep(10)
            r = call("/api/runs/latest", case=case)
            if r and r["status"] != "running":
                break
        g = call("/api/summary", case=case).get("growth", [])
        last = g[-1] if g else {}
        print(f"  rev {r.get('revision')} {r['status']}: {json.dumps({k: last.get(k) for k in ('mode', 'entities', 'entities_new', 'relationships', 'relationships_new', 'detections', 'detections_new', 'incidents', 'incidents_new', 'incidents_grew')})}", flush=True)
        if r["status"] == "failed":
            print("  error:", r.get("error"))
            break


if __name__ == "__main__":
    main()
