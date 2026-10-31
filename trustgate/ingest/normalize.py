"""Map parsed source fields from any format onto one canonical Arrow schema.

Source values are preserved: mapped fields are typed into columns, every
unmapped field goes to `attrs`, and the exact record bytes go to `raw`.
Vendor-neutral meaning (category/activity/outcome/zones) comes from
semantics.py, so detection rules never depend on one vendor's schema.
Unknown schemas get per-source inferred field mappings (see infer_mapping).
"""
import datetime as dt
import functools
import hashlib
import re

import pyarrow as pa

from . import semantics

SCHEMA = pa.schema([
    ("event_uid", pa.string()),
    ("source_id", pa.string()),
    ("format", pa.string()),
    ("line_no", pa.int64()),          # physical line number in the (decompressed) source, 0-based
    ("byte_offset", pa.int64()),      # offset in the decompressed byte stream; see manifest offset_space
    ("byte_length", pa.int32()),
    ("record_hash", pa.int64()),      # blake2b-64 of the raw record bytes, for exact-duplicate detection
    ("schema_fp", pa.string()),       # fingerprint of this record's field-name set (schema drift tracking)
    ("event_time", pa.timestamp("ns", tz="UTC")),
    ("event_time_text", pa.string()),
    ("time_quality", pa.string()),
    ("event_date", pa.date32()),
    ("device", pa.string()),
    ("event_type", pa.string()),
    ("event_subtype", pa.string()),
    ("event_code", pa.string()),
    ("category", pa.string()),        # vendor-neutral: authentication, account_management, configuration, network, ...
    ("activity", pa.string()),        # vendor-neutral: login, create, delete, disable_logging, flow, alert, ...
    ("severity", pa.string()),
    ("action", pa.string()),
    ("outcome", pa.string()),         # normalized success | failure | null; source wording stays in raw/attrs
    ("user", pa.string()),
    ("target_account", pa.string()),  # account acted on by account-management events
    ("src_ip", pa.string()),
    ("src_port", pa.int32()),
    ("src_zone", pa.string()),        # internal | external | dmz (source zone words, else private/public IP)
    ("src_country", pa.string()),
    ("dst_ip", pa.string()),
    ("dst_port", pa.int32()),
    ("dst_zone", pa.string()),
    ("protocol", pa.string()),
    ("app", pa.string()),
    ("rule_name", pa.string()),
    ("message", pa.string()),
    ("session_id", pa.string()),
    ("bytes_out", pa.int64()),
    ("bytes_in", pa.int64()),
    ("attrs", pa.map_(pa.string(), pa.string())),
    ("raw", pa.string()),
])

# canonical column -> candidate source keys, first present wins. Covers FortiGate, ECS/Elastic,
# Windows Security (incl. winlog.event_data.*), CEF, LEEF, Zeek, Palo Alto, Cisco/ASA-style and web logs.
ALIASES = {
    "device": ["devname", "observer.name", "observer.hostname", "host.name", "host.hostname", "agent.hostname", "dvchost",
               "deviceHostName", "Computer", "computer_name", "winlog.computer_name", "DeviceName", "syslog_host", "hostname_device"],
    "event_type": ["type", "event.category", "cat", "category", "event_type", "EventType", "log_type"],
    "event_subtype": ["subtype", "event.type", "event_subtype", "SubType", "subtype_name"],
    "event_code": ["logid", "event.code", "EventID", "EventId", "event_id", "winlog.event_id", "signature_id", "eventid", "msg_id"],
    "severity": ["level", "severity", "event.severity", "log.level", "sev", "Severity", "priority"],
    "action": ["action", "act", "event.action", "Action", "disposition"],
    "outcome": ["status", "event.outcome", "outcome", "result", "Status", "auth_result"],
    "user": ["user", "user.name", "TargetUserName", "winlog.event_data.TargetUserName", "suser", "usrName", "username",
             "user_name", "UserName", "account", "AccountName", "login", "duser", "dstuser", "srcuser", "src_user"],
    "src_ip": ["srcip", "source.ip", "src", "src_ip", "src_addr", "SourceAddress", "IpAddress", "winlog.event_data.IpAddress",
               "client.ip", "client_ip", "clientip", "c-ip", "remote_addr", "remote_ip", "sourceAddress", "id.orig_h", "remip"],
    "src_port": ["srcport", "source.port", "spt", "src_port", "srcPort", "SourcePort", "IpPort", "id.orig_p", "sport"],
    "dst_ip": ["dstip", "destination.ip", "dst", "dst_ip", "dest_ip", "dst_addr", "DestinationAddress", "server.ip",
               "server_ip", "s-ip", "destinationAddress", "id.resp_h", "locip"],
    "dst_port": ["dstport", "destination.port", "dpt", "dst_port", "dest_port", "dstPort", "DestinationPort", "id.resp_p", "dport"],
    "protocol": ["proto", "network.transport", "network.protocol", "protocol", "service", "Protocol"],
    "app": ["app", "application", "app.name", "process.name", "ProcessName", "program", "syslog_app"],
    "rule_name": ["attack", "rule.name", "virus", "threat.name", "signature", "name", "policyname"],
    "message": ["msg", "message", "logdesc", "Message", "event.original_message", "description"],
    "session_id": ["sessionid", "session.id", "externalId", "SessionID", "uid", "LogonId"],
    "bytes_out": ["sentbyte", "source.bytes", "out", "bytes_out", "bytesOut", "orig_bytes", "SentBytes"],
    "bytes_in": ["rcvdbyte", "destination.bytes", "in", "bytes_in", "bytesIn", "resp_bytes", "ReceivedBytes"],
    "src_zone_raw": ["srcintfrole", "source_zone", "src_zone", "from_zone", "SourceZone", "observer.ingress.zone", "srczone"],
    "dst_zone_raw": ["dstintfrole", "destination_zone", "dst_zone", "to_zone", "DestinationZone", "observer.egress.zone", "dstzone"],
    "src_country": ["srccountry", "source.geo.country_name", "src_country", "SourceCountry", "source_country"],
}
VIRTUAL = {"src_zone_raw", "dst_zone_raw"}  # used to derive zones, not stored as columns
INT32 = {"src_port", "dst_port"}
INT64 = {"bytes_out", "bytes_in"}
TIME_KEYS = ["eventtime", "@timestamp", "timestamp", "TimeCreated", "TimeGenerated", "time_generated", "EventTime",
             "event.created", "rt", "devTime", "datetime", "event_time", "ts", "_time", "syslog_time", "time"]
MAPPED = {k for keys in ALIASES.values() for k in keys} | set(TIME_KEYS) | {"date"}  # tz stays in attrs
_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
_FLOAT_EPOCH = re.compile(r"^\d{9,10}\.\d+$")


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _epoch_ns(digits: str):
    n = int(digits)
    scale = {19: 1, 16: 1_000, 13: 1_000_000, 10: 1_000_000_000}.get(len(digits.lstrip("-")))
    return n * scale if scale else None


@functools.lru_cache(maxsize=256)
def _tz(text):
    if not text:
        return dt.timezone.utc
    t = text.strip('"').replace(":", "")
    if len(t) == 5 and t[0] in "+-" and t[1:].isdigit():
        mins = int(t[1:3]) * 60 + int(t[3:])
        return dt.timezone(dt.timedelta(minutes=mins if t[0] == "+" else -mins))
    return None


def _parse_text_time(text: str, tzinfo):
    t = text.strip()
    try:
        d = dt.datetime.fromisoformat(t.replace("Z", "+00:00"))
    except ValueError:
        d = None
        for fmt in ("%b %d %Y %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z", "%m/%d/%Y %H:%M:%S",
                    "%m/%d/%Y %I:%M:%S %p", "%Y/%m/%d %H:%M:%S", "%d-%m-%Y %H:%M:%S"):
            try:
                d = dt.datetime.strptime(t, fmt)
                break
            except ValueError:
                continue
        if d is None:
            return None
    if d.tzinfo is None:
        if tzinfo is None:
            return None
        d = d.replace(tzinfo=tzinfo)
    delta = d - _EPOCH
    return (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1_000


def parse_time_value(v: str, tzinfo=dt.timezone.utc):
    if v.lstrip("-").isdigit():
        return _epoch_ns(v)
    if _FLOAT_EPOCH.match(v):
        return int(float(v) * 1e9)
    return _parse_text_time(v, tzinfo)


def resolve_time(f: dict, time_keys=TIME_KEYS):
    """Returns (event_time_ns | None, source_text, quality)."""
    tzinfo = _tz(f.get("tz"))
    wall = None
    if "date" in f and "time" in f:  # FortiGate-style split wall clock
        wall = _parse_text_time(f"{f['date']} {f['time']}", tzinfo)
    for key in time_keys:
        v = f.get(key)
        if not v or (key == "time" and "date" in f):
            continue
        ns = parse_time_value(v, tzinfo)
        if ns is None:
            continue
        quality = "ok"
        if wall is not None and abs(ns - wall) >= 1_000_000_000:
            off = tzinfo.utcoffset(None).total_seconds() * 1e9 if tzinfo else 0
            # epoch equals the local wall clock read as UTC: the source's tz labelling is inconsistent
            quality = "epoch_is_local_wallclock" if off and abs(ns - wall - off) < 1e9 else "conflict_wallclock"
        return ns, f"{key}={v}", quality
    if wall is not None:
        return wall, f"date+time={f['date']} {f['time']}", "wallclock_only"
    return None, None, "missing"


# ---------------------------------------------------------------- unknown-schema inference
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_NAME_HINTS = {
    "src_ip": ("src", "source", "client", "orig", "origin", "remote", "from", "attacker", "caller", "peer"),
    "dst_ip": ("dst", "dest", "destination", "server", "target", "resp", "to", "victim"),
    "user": ("user", "account", "login", "principal", "subject", "actor", "username", "uname"),
    "device": ("host", "device", "computer", "node", "sensor", "observer", "appliance"),
    "message": ("msg", "message", "desc", "detail", "text", "summary"),
    "event_code": ("eventid", "event_id", "code", "logid", "signature"),
    "action": ("action", "verb", "operation", "op"),
    "outcome": ("status", "result", "outcome", "success"),
}


def _tokens(key: str):
    return set(re.split(r"[^a-z0-9]+", re.sub(r"([a-z])([A-Z])", r"\1_\2", key).lower())) - {""}


def infer_mapping(samples: list[dict]) -> dict:
    """For canonical fields that no known alias covers in this source, pick the
    most plausible unknown key using its name tokens and the shape of its values.
    Returns {canonical: {"key": k, "confidence": c, "evidence": "..."}}."""
    if not samples:
        return {}
    keys = {}
    for s in samples:
        for k, v in s.items():
            keys.setdefault(k, []).append(v)
    covered = {c for c, al in ALIASES.items() if any(a in keys for a in al)}
    if any(k in keys for k in TIME_KEYS) or ("date" in keys and "time" in keys):
        covered.add("event_time")
    unknown = [k for k in keys if k not in MAPPED]
    out = {}

    def ratio(vals, pred):
        vals = [v for v in vals if v not in (None, "")]
        return (sum(1 for v in vals if pred(v)) / len(vals)) if vals else 0.0

    used = set()
    for col in ("src_ip", "dst_ip", "user", "device", "event_code", "action", "outcome", "message"):
        if col in covered:
            continue
        best = None
        for k in unknown:
            if k in used:
                continue
            tok = _tokens(k)
            name = len(tok & set(_NAME_HINTS.get(col, ()))) > 0
            vals = keys[k][:500]
            if col in ("src_ip", "dst_ip"):
                shape = ratio(vals, lambda v: bool(_IPV4.match(v)) or (":" in v and v.count(":") >= 2))
                score = shape * (1.0 if name else 0.0)
            elif col == "user":
                shape = ratio(vals, lambda v: not _IPV4.match(v) and not v.isdigit() and len(v) <= 128)
                score = shape * (1.0 if name else 0.0)
            elif col == "message":
                shape = ratio(vals, lambda v: " " in v and len(v) > 12)
                score = shape * (1.0 if name else 0.6)
            else:
                shape = ratio(vals, lambda v: len(v) <= 64)
                score = shape * (1.0 if name else 0.0)
            if score >= 0.8 and (best is None or score > best[1]):
                best = (k, score, f"name tokens {sorted(tok)}, {shape:.0%} of sampled values fit")
        if best:
            used.add(best[0])
            out[col] = {"key": best[0], "confidence": round(best[1], 2), "evidence": best[2]}
    if "event_time" not in covered:
        best = None
        for k in unknown:
            if k in used:
                continue
            shape = ratio(keys[k][:200], lambda v: parse_time_value(v) is not None)
            if shape >= 0.9 and (best is None or shape > best[1]):
                best = (k, shape)
        if best:
            out["event_time"] = {"key": best[0], "confidence": round(best[1], 2), "evidence": f"{best[1]:.0%} of values parse as time"}
    return out


class BatchBuilder:
    def __init__(self, source_id: str, fmt: str, inferred: dict | None = None):
        self.source_id, self.fmt = source_id, fmt
        self.cols = {name: [] for name in SCHEMA.names}
        inferred = inferred or {}
        # known aliases first; an inferred key is only consulted when none of them is present
        self.aliases = {c: al + ([inferred[c]["key"]] if c in inferred else []) for c, al in ALIASES.items()}
        self.time_keys = TIME_KEYS + ([inferred["event_time"]["key"]] if "event_time" in inferred else [])
        self.mapped = MAPPED | {v["key"] for v in inferred.values()}
        self.schemas = {}  # schema fingerprint -> [count, sorted keys]
        self._plans = {}   # field-name layout -> cached column mapping plan
        self.unmapped = 0
        self.fields_total = 0

    def __len__(self):
        return len(self.cols["raw"])

    def add(self, fields: dict, raw: bytes, line_no: int, offset: int, fmt: str | None = None):
        c = self.cols
        h = hashlib.blake2b(raw, digest_size=8).digest()
        c["event_uid"].append(hashlib.blake2b(f"{self.source_id}:{offset}".encode(), digest_size=12).hexdigest())
        c["source_id"].append(self.source_id)
        c["format"].append(fmt or self.fmt)
        c["line_no"].append(line_no)
        c["byte_offset"].append(offset)
        c["byte_length"].append(len(raw))
        c["record_hash"].append(int.from_bytes(h, "little", signed=True))
        keyset = tuple(sorted(fields))
        plan = self._plans.get(keyset)
        if plan is None:  # once per distinct field layout: which source key feeds each column
            plan = self._plan(keyset)
        fp, picks, time_keys, unmapped_keys = plan
        self.schemas[fp][0] += 1
        c["schema_fp"].append(fp)
        ns, text, quality = resolve_time(fields, time_keys)
        c["event_time"].append(ns)
        c["event_time_text"].append(text)
        c["time_quality"].append(quality)
        c["event_date"].append(ns // 86_400_000_000_000 if ns is not None else None)
        row = {}
        for col, k in picks:
            val = fields[k] if k is not None else None
            if col in INT32 or col in INT64:
                val = _int(val)
            row[col] = val
        cat, act, out = semantics.classify(row["event_code"], row["event_type"], row["event_subtype"], row["action"],
                                           row["outcome"], row["message"])
        row["outcome"] = out
        row["category"], row["activity"] = cat, act
        row["target_account"] = semantics.target_account(cat, act, fields, row["message"])
        row["src_zone"] = semantics.zone(row.pop("src_zone_raw"), row["src_ip"])
        row["dst_zone"] = semantics.zone(row.pop("dst_zone_raw"), row["dst_ip"])
        for col, val in row.items():
            c[col].append(val)
        c["attrs"].append([(k, fields[k]) for k in unmapped_keys])
        self.unmapped += len(unmapped_keys)
        self.fields_total += len(fields)
        c["raw"].append(raw.decode("utf-8"))

    def _plan(self, keyset: tuple):
        present = set(keyset)
        fp = hashlib.blake2b("\x1f".join(keyset).encode(), digest_size=6).hexdigest()
        if fp not in self.schemas and len(self.schemas) >= 2000:  # bound memory for very irregular sources
            fp = "overflow"
        self.schemas.setdefault(fp, [0, list(keyset) if fp != "overflow" else []])
        picks = [(col, next((k for k in keys if k in present), None)) for col, keys in self.aliases.items()]
        time_keys = [k for k in self.time_keys if k in present]
        unmapped_keys = tuple(k for k in keyset if k not in self.mapped)
        plan = (fp, picks, time_keys, unmapped_keys)
        if len(self._plans) < 5000:
            self._plans[keyset] = plan
        return plan

    def table(self) -> pa.Table:
        arrays = []
        for field in SCHEMA:
            data = self.cols[field.name]
            if field.name == "event_date":
                arrays.append(pa.array(data, pa.int32()).cast(pa.date32()))
            else:
                arrays.append(pa.array(data, field.type))
        return pa.Table.from_arrays(arrays, schema=SCHEMA)
