"""Convert Sigma rules (https://github.com/SigmaHQ/sigma) into TrustGate rules.

Sigma rules are untrusted YAML data: parsed with yaml.safe_load, never executed. Each converted
rule keeps its Sigma id, title, author, level, ATT&CK tags and license, and is compiled to the
same bound-parameter DuckDB SQL as native rules. Anything that cannot be translated faithfully
(aggregations, correlation rules, base64/utf16 value transforms, field references) is skipped
with a reason instead of being approximated.
"""
import re

from .rules import Rule

LEVEL = {"low": "low", "medium": "medium", "high": "high", "critical": "critical"}
TACTIC = {"reconnaissance": "reconnaissance", "resource_development": "resource-development", "initial_access": "initial-access",
          "execution": "execution", "persistence": "persistence", "privilege_escalation": "privilege-escalation",
          "defense_evasion": "defense-evasion", "credential_access": "credential-access", "discovery": "discovery",
          "lateral_movement": "lateral-movement", "collection": "collection", "command_and_control": "command-and-control",
          "exfiltration": "exfiltration", "impact": "impact",
          # newer ATT&CK splits Defense Evasion into Stealth and Defense Impairment; the 14-tactic view keeps one column
          "stealth": "defense-evasion", "defense_impairment": "defense-evasion"}
# Sigma field names that correspond to TrustGate's vendor-neutral columns; everything else stays a raw field
FIELD_MAP = {"eventid": "event_code", "targetusername": "user", "subjectusername": "user", "user": "user", "username": "user",
             "accountname": "user", "ipaddress": "src_ip", "sourceip": "src_ip", "src_ip": "src_ip", "c-ip": "src_ip",
             "clientip": "src_ip", "destinationip": "dst_ip", "dst_ip": "dst_ip", "destinationport": "dst_port",
             "dst_port": "dst_port", "sourceport": "src_port", "computer": "device", "computername": "device",
             "message": "message", "protocol": "protocol", "action": "action", "severity": "severity"}
_FIELD = re.compile(r"^[A-Za-z_][\w.\-]{0,63}$")
UNSUPPORTED_MODS = {"base64", "base64offset", "utf16", "utf16le", "utf16be", "wide", "fieldref", "expand", "cased"}


class Skip(Exception):
    pass


def _field(name: str) -> str:
    if name == "":  # Sigma "|contains" with no field: search the whole original record
        return "raw"
    if name.lower() in FIELD_MAP:
        return FIELD_MAP[name.lower()]
    if not _FIELD.match(name):
        raise Skip(f"unusable field name {name!r}")
    return f"attr.{name}"


def _values(v):
    return v if isinstance(v, list) else [v]


def _windash(vals):
    out = []
    for v in vals:
        out.append(v)
        if isinstance(v, str):
            for a, b in (("-", "/"), ("/", "-")):
                alt = re.sub(rf"(^|\s){re.escape(a)}(\w)", rf"\1{b}\2", v)
                if alt != v:
                    out.append(alt)
    return out


def _field_cond(key: str, value, raw_fields: set) -> dict:
    name, *mods = key.split("|")
    mods = [m.lower() for m in mods]
    if bad := set(mods) & UNSUPPORTED_MODS:
        raise Skip(f"modifier {sorted(bad)[0]} not supported")
    f = _field(name)
    if f.startswith("attr."):
        raw_fields.add(name)
    vals = _values(value)
    if "windash" in mods:
        vals = _windash(vals)
    if "exists" in mods:
        return {f: {"exists": bool(vals[0])}}
    if any(v is None for v in vals):
        rest = [v for v in vals if v is not None]
        cond = {f: {"exists": False}}
        return cond if not rest else {"any": [cond, _field_cond(key, rest, raw_fields)]}
    if "cidr" in mods:
        return {f: {"cidr": [str(v) for v in vals]}}
    if "re" in mods:
        flags = "(?i)" if "i" in mods else ""
        return {"any": [{f: {"regex": flags + str(v)}} for v in vals]} if len(vals) > 1 else {f: {"regex": flags + str(vals[0])}}
    for op in ("gt", "gte", "lt", "lte"):
        if op in mods:
            return {f: {op: vals[0]}}
    op = "icontains" if "contains" in mods else "istartswith" if "startswith" in mods else "iendswith" if "endswith" in mods else None
    vals = [str(v).lower() if isinstance(v, bool) else str(v) for v in vals]
    if op is None:  # plain value: case-insensitive equality, or glob when it has Sigma wildcards
        globs = [v for v in vals if re.search(r"(?<!\\)[*?]", v)]
        exact = [v for v in vals if v not in globs]
        parts = ([{f: {"ieq": exact}}] if exact else []) + ([{f: {"iglob": globs}}] if globs else [])
        if "all" in mods:
            return {"all": [{f: {"ieq": [v]}} if v in exact else {f: {"iglob": [v]}} for v in vals]}
        return parts[0] if len(parts) == 1 else {"any": parts}
    vals = [v.replace("\\*", "*").replace("\\?", "?") for v in vals]
    if "all" in mods:
        return {"all": [{f: {op: [v]}} for v in vals]}
    return {f: {op: vals}}


def _selection(sel, raw_fields: set) -> dict:
    if isinstance(sel, dict):
        return {"all": [_field_cond(k, v, raw_fields) for k, v in sel.items()]}
    if isinstance(sel, list):
        if all(isinstance(x, dict) for x in sel):
            return {"any": [_selection(x, raw_fields) for x in sel]}
        if all(isinstance(x, (str, int)) for x in sel):  # keywords: search the message text
            return {"message": {"icontains": [str(x).replace("*", "") for x in sel]}}
    if isinstance(sel, (str, int)):
        return {"message": {"icontains": [str(sel)]}}
    raise Skip("unsupported selection shape")


_TOK = re.compile(r"\s*(\(|\)|\b(?:and|or|not)\b|1 of [\w*]+|all of [\w*]+|[\w*]+)", re.I)


def _condition(cond: str, sels: dict) -> dict:
    if "|" in cond or re.search(r"\b(count|min|max|avg|sum|near)\s*\(", cond, re.I):
        raise Skip("aggregation conditions are not supported")
    toks, pos = [], 0
    cond = cond.strip()
    while pos < len(cond):
        m = _TOK.match(cond, pos)
        if not m or m.end() == pos:
            raise Skip(f"cannot parse condition near {cond[pos:pos + 20]!r}")
        toks.append(m.group(1))
        pos = m.end()
    i = 0

    def names(pat):
        if pat == "them":
            return list(sels)
        rx = re.compile("^" + re.escape(pat).replace("\\*", ".*") + "$")
        out = [n for n in sels if rx.match(n)]
        if not out:
            raise Skip(f"condition refers to unknown selection {pat}")
        return out

    def atom():
        nonlocal i
        t = toks[i]
        i += 1
        low = t.lower()
        if low == "not":
            return {"not": atom()}
        if t == "(":
            e = expr()
            if i >= len(toks) or toks[i] != ")":
                raise Skip("unbalanced parentheses")
            i += 1
            return e
        if low.startswith("1 of "):
            return {"any": [sels[n] for n in names(t[5:])]}
        if low.startswith("all of "):
            return {"all": [sels[n] for n in names(t[7:])]}
        if t not in sels:
            raise Skip(f"condition refers to unknown selection {t}")
        return sels[t]

    def conj():
        nonlocal i
        parts = [atom()]
        while i < len(toks) and toks[i].lower() == "and":
            i += 1
            parts.append(atom())
        return parts[0] if len(parts) == 1 else {"all": parts}

    def expr():
        nonlocal i
        parts = [conj()]
        while i < len(toks) and toks[i].lower() == "or":
            i += 1
            parts.append(conj())
        return parts[0] if len(parts) == 1 else {"any": parts}

    out = expr()
    if i != len(toks):
        raise Skip("trailing tokens in condition")
    return out


def convert(doc: dict, path: str, release: str) -> dict:
    """One Sigma document -> TrustGate rule dict (validated), or raise Skip."""
    if not isinstance(doc, dict) or "detection" not in doc:
        raise Skip("not a detection rule (correlation, filter or collection)")
    status = str(doc.get("status", "")).lower()
    if status in ("deprecated", "unsupported"):
        raise Skip(f"status {status}")
    level = str(doc.get("level", "")).lower()
    if level not in LEVEL:
        raise Skip(f"level {level or 'missing'} (informational rules are not imported)")
    det = dict(doc["detection"])
    cond = det.pop("condition", None)
    det.pop("timeframe", None)
    if isinstance(cond, list):
        if len(cond) != 1:
            raise Skip("multiple conditions")
        cond = cond[0]
    if not isinstance(cond, str):
        raise Skip("missing condition")
    raw_fields: set = set()
    sels = {k: _selection(v, raw_fields) for k, v in det.items()}
    where = _condition(cond, sels)
    # Sigma tags use attack.privilege_escalation (older) or attack.privilege-escalation (current)
    tags = [str(t).lower().replace("-", "_") for t in doc.get("tags", []) or []]
    tactics = [TACTIC[t[7:]] for t in tags if t.startswith("attack.") and t[7:] in TACTIC]
    techs = sorted({t[7:].upper() for t in tags if re.match(r"^attack\.t\d{4}(\.\d{3})?$", t)})
    sid = str(doc.get("id", ""))
    if not re.match(r"^[0-9a-fA-F-]{8,}$", sid):
        raise Skip("missing or invalid Sigma id")
    rule = {
        "id": "SIG-" + sid.replace("-", "")[:10].upper(),
        "version": 1,
        "title": str(doc.get("title", "Sigma rule"))[:140],
        "type": "event",
        "severity": LEVEL[level],
        "stage": tactics[0] if tactics else "unmapped",
        "tactics": sorted(set(tactics)) or None,
        "attack": [{"id": t, "name": t} for t in techs],
        "where": where,
        "group_by": ["actor"],
        "bucket": "1d",
        "requires_fields": sorted(raw_fields) or None,
        "source": {"kind": "sigma", "sigma_id": sid, "path": path, "author": str(doc.get("author", ""))[:200], "status": status,
                   "level": level, "release": release, "license": "DRL-1.1",
                   "attack_tags": [t for t in tags if t.startswith("attack.") and not re.match(r"^attack\.[tgs]\d", t)],
                   "logsource": {k: v for k, v in (doc.get("logsource") or {}).items() if k in ("product", "category", "service")}},
    }
    if not raw_fields and _keyword_only(where):
        # free-text rules (no fields) would match any product's logs; they stay off until that product is loaded
        rule["enabled"] = False
        rule["source"]["disabled_reason"] = (f"keyword-only rule for {rule['source']['logsource'].get('product', 'unspecified')} logs; "
                                             "enable when those logs are in the case")
    Rule(**rule)  # validates fields and compiles the where clause
    return rule


def _keyword_only(where) -> bool:
    """True when every field the rule reads is free text (message/raw), i.e. it has no structured anchor."""
    fields = set()

    def walk(w):
        for k, v in w.items():
            if k in ("any", "all"):
                for x in v:
                    walk(x)
            elif k == "not":
                walk(v)
            else:
                fields.add(k)
    walk(where)
    return fields <= {"message", "raw"}
