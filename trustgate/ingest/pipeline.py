"""Streaming ingestion: source -> framed chunks -> parallel parse/normalize ->
Parquet segments + quarantine + an accounting manifest.

The parent process only frames bytes (finds newline boundaries, counts lines,
isolates oversized records). Workers parse a whole chunk and write one closed
Parquet segment each, named by chunk index so a retry overwrites rather than
duplicates. Offsets refer to the decompressed byte stream when the source is
compressed; the manifest records this as `offset_space`.
"""
import base64
import datetime as dt
import hashlib
import json
import os
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import dataclass, field

import pyarrow.compute as pc
import pyarrow.fs as pafs
import pyarrow.parquet as pq

from .normalize import BatchBuilder, infer_mapping
from .parsers import PARSERS, ParseError
from .sniff import Detected, detect_compression, detect_format, open_decompressed

QUARANTINE_PREFIX_BYTES = 4096


@dataclass
class IngestConfig:
    chunk_bytes: int = 64 << 20
    max_record_bytes: int = 1 << 20
    workers: int = max(1, (os.cpu_count() or 2) - 1)
    row_group_rows: int = 128_000


@dataclass
class Chunk:
    index: int
    data: bytes
    offset: int
    line_no: int


@dataclass
class Accounting:
    nonempty_records: int = 0
    normalized: int = 0
    quarantined: int = 0
    blank_lines: int = 0
    reasons: dict = field(default_factory=dict)
    formats: dict = field(default_factory=dict)
    time_quality: dict = field(default_factory=dict)
    schemas: dict = field(default_factory=dict)      # fingerprint -> {count, keys, first_segment}
    categories: dict = field(default_factory=dict)
    coverage: dict = field(default_factory=dict)     # canonical column -> non-null count
    unmapped_fields: int = 0
    drift_inferred: dict = field(default_factory=dict)  # segment -> mappings inferred for a changed layout
    fields_total: int = 0
    min_time_ns: int | None = None
    max_time_ns: int | None = None

    def merge(self, r: dict):
        for k in ("nonempty_records", "normalized", "quarantined", "blank_lines"):
            setattr(self, k, getattr(self, k) + r[k])
        for fp, (n, keys) in r.get("schemas", {}).items():
            cur = self.schemas.setdefault(fp, {"count": 0, "keys": keys, "first_segment": r["chunk"]})
            cur["count"] += n
            cur["first_segment"] = min(cur["first_segment"], r["chunk"])
        self.drift_inferred.update(r.get("drift_inferred", {}))
        self.unmapped_fields += r.get("unmapped_fields", 0)
        self.fields_total += r.get("fields_total", 0)
        for name in ("reasons", "formats", "time_quality", "categories", "coverage"):
            d = getattr(self, name)
            for k, v in r.get(name, {}).items():
                d[k] = d.get(k, 0) + v
        for k, fn in (("min_time_ns", min), ("max_time_ns", max)):
            if r[k] is not None:
                cur = getattr(self, k)
                setattr(self, k, r[k] if cur is None else fn(cur, r[k]))


def _open_source(uri: str):
    """Returns (raw binary stream, size or None, version id or None)."""
    if uri.startswith("s3://"):
        import boto3
        bucket, key = uri[5:].split("/", 1)
        obj = boto3.client("s3").get_object(Bucket=bucket, Key=key)
        return obj["Body"], obj["ContentLength"], obj.get("VersionId")
    return open(uri, "rb", buffering=8 << 20), os.path.getsize(uri), None


def _out_fs(out: str):
    fs, path = pafs.FileSystem.from_uri(out) if "://" in out else (pafs.LocalFileSystem(), os.path.abspath(out))
    return fs, path.rstrip("/")


def _quarantine_row(line_no, offset, raw: bytes, reason, total_len=None):
    return {"line_no": line_no, "byte_offset": offset, "byte_length": total_len if total_len is not None else len(raw),
            "reason": reason, "nul_bytes": raw.count(0),
            "prefix_b64": base64.b64encode(raw[:QUARANTINE_PREFIX_BYTES]).decode()}


def parse_any(rec: bytes, parser, primary: str):
    """Primary format first; if a record is in another format (mixed or changed
    mid-file), try the other parsers before giving up. Returns (fields, format)."""
    try:
        return parser(rec), primary
    except ParseError as first:
        for name, p in PARSERS.items():
            if name == primary:
                continue
            try:
                return p(rec), name
            except (ParseError, UnicodeDecodeError):
                continue
        raise first


def _chunk_inference(data: bytes, parser, primary: str, head_keys: set, inferred: dict) -> tuple[dict, dict | None]:
    """Schema drift inside a file: if this chunk's records use field names never seen
    in the file head, infer mappings from those records too (head mappings win)."""
    drifted = []
    for line in data[: 4 << 20].split(b"\n")[:2000]:
        try:
            f, _ = parse_any(line.rstrip(b"\r"), parser, primary)
        except Exception:
            continue
        if len(set(f) - head_keys) >= 2:
            drifted.append(f)
    if len(drifted) < 20:
        return inferred, None
    local = infer_mapping(drifted)
    return {**local, **inferred}, local


def process_chunk(chunk: Chunk, det: Detected, source_id: str, out: str, cfg: IngestConfig, inferred=None,
                  head_keys=None) -> dict:
    parser = det.parser()
    inferred = inferred or {}
    local_inferred = None
    if head_keys is not None:
        inferred, local_inferred = _chunk_inference(chunk.data, parser, det.format, head_keys, inferred)
    builder = BatchBuilder(source_id, det.format, inferred)
    quarantine = []
    stats = {"nonempty_records": 0, "normalized": 0, "quarantined": 0, "blank_lines": 0,
             "reasons": {}, "formats": {det.format: 0}, "time_quality": {}}
    data, pos, line_no = chunk.data, 0, chunk.line_no
    n = len(data)
    while pos < n:
        nl = data.find(b"\n", pos)
        end = n if nl < 0 else nl
        rec = data[pos:end]
        if rec.endswith(b"\r"):
            rec = rec[:-1]
        offset = chunk.offset + pos
        if not rec.strip(b" \t"):
            stats["blank_lines"] += 1
        else:
            stats["nonempty_records"] += 1
            reason = None
            if len(rec) > cfg.max_record_bytes:
                reason = "oversize"
            elif b"\x00" in rec:
                reason = "nul_bytes"
            else:
                try:
                    fields, fmt = parse_any(rec, parser, det.format)
                    builder.add(fields, rec, line_no, offset, fmt)
                    if fmt != det.format:
                        stats["formats"][fmt] = stats["formats"].get(fmt, 0) + 1
                except UnicodeDecodeError:
                    reason = "bad_utf8"
                except ParseError as e:
                    reason = str(e).split(":")[0] + "_parse_error"
            if reason:
                quarantine.append(_quarantine_row(line_no, offset, rec, reason))
                stats["reasons"][reason] = stats["reasons"].get(reason, 0) + 1
        line_no += 1
        pos = end + 1
    stats["quarantined"] = len(quarantine)
    stats["normalized"] = len(builder)
    stats["formats"][det.format] = len(builder) - sum(v for k, v in stats["formats"].items() if k != det.format)
    stats["min_time_ns"] = stats["max_time_ns"] = None
    fs, base = _out_fs(out)
    name = f"seg-{chunk.index:06d}"
    if len(builder):
        table = builder.table()
        tq = table.column("time_quality").value_counts().to_pylist()
        stats["time_quality"] = {d["values"]: d["counts"] for d in tq}
        times = table.column("event_time").cast("int64")
        mm = pc.min_max(times).as_py()
        stats["min_time_ns"], stats["max_time_ns"] = mm["min"], mm["max"]
        fs.create_dir(f"{base}/events", recursive=True)
        pq.write_table(table, f"{base}/events/{name}.parquet", filesystem=fs, compression="zstd",
                       row_group_size=cfg.row_group_rows)
    if quarantine:
        fs.create_dir(f"{base}/quarantine", recursive=True)
        with fs.open_output_stream(f"{base}/quarantine/{name}.jsonl") as f:
            f.write(b"".join(json.dumps(q).encode() + b"\n" for q in quarantine))
    stats["schemas"] = builder.schemas
    if local_inferred:
        stats["drift_inferred"] = {chunk.index: {k: v["key"] for k, v in local_inferred.items()}}
    stats["unmapped_fields"], stats["fields_total"] = builder.unmapped, builder.fields_total
    if len(builder):
        cats = table.column("category").value_counts().to_pylist()
        stats["categories"] = {d["values"]: d["counts"] for d in cats}
        stats["coverage"] = {c: len(table) - table.column(c).null_count
                             for c in ("event_time", "user", "src_ip", "dst_ip", "category", "outcome", "device")}
    stats["chunk"] = chunk.index
    stats["lines"] = line_no - chunk.line_no
    return stats


def frame(stream, cfg: IngestConfig, on_oversize):
    """Yield newline-aligned Chunks. A record longer than max_record_bytes that
    has no newline in sight is reported via on_oversize(line_no, offset, prefix,
    length) and skipped, so a huge corrupt tail never sits in memory."""
    buf, buf_off, line_no, index = b"", 0, 0, 0
    while True:
        block = _read_up_to(stream, cfg.chunk_bytes)
        if not block:
            break
        buf += block
        cut = buf.rfind(b"\n")
        if cut < 0:
            if len(buf) > cfg.max_record_bytes:
                prefix, start, length = buf[:QUARANTINE_PREFIX_BYTES], buf_off, len(buf)
                while True:  # discard until the record's newline or EOF
                    block = stream.read(cfg.chunk_bytes)
                    if not block:
                        buf = b""
                        break
                    nl = block.find(b"\n")
                    if nl >= 0:
                        length += nl
                        buf = block[nl + 1:]
                        break
                    length += len(block)
                on_oversize(line_no, start, prefix, length)
                line_no += 1
                buf_off = start + length + 1
            continue
        out, buf = buf[:cut + 1], buf[cut + 1:]
        yield Chunk(index, out, buf_off, line_no)
        index += 1
        line_no += out.count(b"\n")
        buf_off += len(out)
    if buf:
        yield Chunk(index, buf, buf_off, line_no)


class _Tee:
    """Hash the stored (possibly compressed) bytes as they are read."""

    def __init__(self, f):
        self.f, self.sha, self.n = f, hashlib.sha256(), 0
        self.head = b""

    def read(self, n=-1):
        b = self.f.read(n)
        self.sha.update(b)
        self.n += len(b)
        return b

    def peek_head(self, n=16):
        self.head = self.read(n)
        return self.head


class _Prefixed:
    def __init__(self, prefix, f):
        self.prefix, self.f = prefix, f

    def read(self, n=-1):
        if not self.prefix:
            return self.f.read(n)
        if n is None or n < 0:
            b, self.prefix = self.prefix, b""
            return b + self.f.read()
        b, self.prefix = self.prefix[:n], self.prefix[n:]
        return b + self.f.read(n - len(b)) if len(b) < n else b


def _schema_report(acct, inferred, segments):
    """Which field layouts were seen, which appeared only later in the file (drift),
    how much of each record we could map, and what was inferred for unknown fields."""
    fps = sorted(acct.schemas.items(), key=lambda kv: -kv[1]["count"])
    first = segments[0] if segments else 0
    base_keys = set().union(*(set(v["keys"]) for _, v in fps if v["first_segment"] == first)) if fps else set()
    drift = [{"fingerprint": fp, "count": v["count"], "first_segment": v["first_segment"],
              "new_fields": sorted(set(v["keys"]) - base_keys)[:30]}
             for fp, v in fps if v["first_segment"] != first and set(v["keys"]) - base_keys]
    total = acct.normalized or 1
    return {
        "fingerprints": [{"fingerprint": fp, "count": v["count"], "fields": len(v["keys"]), "first_segment": v["first_segment"]}
                         for fp, v in fps[:50]],
        "distinct_layouts": len(fps),
        "drift": drift[:50],
        "inferred_mappings": inferred,
        "drift_inferred_by_segment": acct.drift_inferred,
        "unmapped_field_ratio": round(acct.unmapped_fields / max(1, acct.fields_total), 4),
        "coverage": {k: round(v / total, 4) for k, v in acct.coverage.items()},
        "categories": acct.categories,
    }


def _read_up_to(stream, n):
    parts, got = [], 0
    while got < n:
        b = stream.read(n - got)
        if not b:
            break
        parts.append(b); got += len(b)
    return b"".join(parts)


def ingest(source: str, out: str, source_id: str | None = None, cfg: IngestConfig | None = None, log=print) -> dict:
    cfg = cfg or IngestConfig()
    t0 = time.time()
    raw, size, version = _open_source(source)
    tee = _Tee(raw)
    compression = detect_compression(tee.peek_head())
    stream = open_decompressed(_Prefixed(tee.head, tee), compression)
    sample = _read_up_to(stream, 1 << 20)
    fmt, header = detect_format(sample, at_eof=len(sample) < 1 << 20)
    det = Detected(compression, fmt, header)
    stream = _Prefixed(sample, stream)
    source_id = source_id or hashlib.blake2b(f"{source}:{version}".encode(), digest_size=8).hexdigest()
    log(f"source={source} compression={compression} format={fmt} source_id={source_id}")
    # unknown-schema support: infer mappings for canonical fields no known alias covers
    parser = det.parser()
    samples = []
    for line in sample.split(b"\n")[:2000]:
        try:
            samples.append(parser(line.rstrip(b"\r")))
        except Exception:
            continue
    inferred = infer_mapping(samples)
    head_keys = set().union(*(set(x) for x in samples)) if samples else set()
    if inferred:
        log(f"inferred field mappings: {{k: v['key'] for k, v in inferred.items()}}")

    acct = Accounting()
    oversize = []

    def on_oversize(line_no, offset, prefix, length):
        oversize.append(_quarantine_row(line_no, offset, prefix, "oversize", total_len=length))

    segments, lines_total, done = [], 0, 0
    with ProcessPoolExecutor(max_workers=cfg.workers) as pool:
        pending = set()
        for chunk in frame(stream, cfg, on_oversize):
            pending.add(pool.submit(process_chunk, chunk, det, source_id, out, cfg, inferred, head_keys))
            if len(pending) >= cfg.workers * 2:  # backpressure: bounded in-flight chunks
                finished, pending = wait(pending, return_when=FIRST_COMPLETED)
                for f in finished:
                    r = f.result(); acct.merge(r); segments.append(r["chunk"]); lines_total += r["lines"]
                    done += 1
                    if done % 20 == 0:
                        log(f"  {done} segments, {acct.normalized:,} events, {tee.n / 1e9:.2f} GB stored bytes read, "
                            f"{tee.n / (time.time() - t0) / 1e6:.1f} MB/s")
        for f in pending:
            r = f.result(); acct.merge(r); segments.append(r["chunk"]); lines_total += r["lines"]

    if oversize:
        fs, base = _out_fs(out)
        fs.create_dir(f"{base}/quarantine", recursive=True)
        with fs.open_output_stream(f"{base}/quarantine/oversize.jsonl") as f:
            f.write(b"".join(json.dumps(q).encode() + b"\n" for q in oversize))
        acct.nonempty_records += len(oversize)
        acct.quarantined += len(oversize)
        acct.reasons["oversize"] = acct.reasons.get("oversize", 0) + len(oversize)

    def iso(ns):
        return None if ns is None else dt.datetime.fromtimestamp(ns / 1e9, dt.timezone.utc).isoformat()

    manifest = {
        "source": source, "source_id": source_id, "source_version_id": version,
        "stored_bytes": tee.n, "stored_sha256": tee.sha.hexdigest(),
        "stored_hash_scope": "bytes as stored (compressed if compression != none)",
        "compression": compression, "format": fmt,
        "offset_space": "decompressed" if compression != "none" else "source",
        "accounting": {k: v for k, v in acct.__dict__.items() if k not in ("schemas", "coverage", "drift_inferred")} | {"balanced": acct.nonempty_records == acct.normalized + acct.quarantined},
        "event_time_range": [iso(acct.min_time_ns), iso(acct.max_time_ns)],
        "segments": sorted(segments),
        "schema": _schema_report(acct, inferred, sorted(segments)),
        "config": cfg.__dict__,
        "elapsed_s": round(time.time() - t0, 1),
        "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    fs, base = _out_fs(out)
    with fs.open_output_stream(f"{base}/manifest.json") as f:
        f.write(json.dumps(manifest, indent=2, default=str).encode())
    return manifest
