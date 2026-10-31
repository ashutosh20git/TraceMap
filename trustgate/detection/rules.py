"""YAML rule schema, validation and compilation to DuckDB SQL.

Values from YAML are always bound as SQL parameters; only field names from a
fixed registry (or a validated attr.<name>) are interpolated.
"""
import hashlib
import re
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

CANONICAL = {"event_uid", "event_time", "device", "event_type", "event_subtype", "event_code", "category", "activity",
             "severity", "action", "outcome", "user", "target_account", "src_ip", "src_port", "src_zone", "src_country",
             "dst_ip", "dst_port", "dst_zone", "protocol", "app", "rule_name", "message", "session_id", "bytes_out",
             "bytes_in", "time_quality", "schema_fp", "raw"}
DERIVED = {
    "src_net24": r"regexp_extract(src_ip, '^(\d+\.\d+\.\d+)\.', 1) || '.0/24'",
    # device wall-clock hour; for sources whose epoch is already local time (time_quality=epoch_is_local_wallclock)
    "local_hour": "hour(event_time)",
    # who did it: account, else source address, else device (groups imported single-event rules per actor)
    "actor": "coalesce(user, src_ip, device, 'unknown')",
}
_ATTR = re.compile(r"^attr\.([A-Za-z_][\w.\-]{0,63})$")
_DUR = re.compile(r"^(\d+)(s|m|h|d)$")
_UNITS = {"s": "SECOND", "m": "MINUTE", "h": "HOUR", "d": "DAY"}
OPS = {"eq": "=", "ne": "<>", "gt": ">", "gte": ">=", "lt": "<", "lte": "<=", "like": "LIKE", "ilike": "ILIKE",
       "not_like": "NOT LIKE", "not_ilike": "NOT ILIKE"}


def field_sql(name: str) -> str:
    if name in CANONICAL:
        return name
    if name in DERIVED:
        return f"({DERIVED[name]})"
    m = _ATTR.match(name)
    if m:
        return f"attrs['{m.group(1)}']"
    raise ValueError(f"unknown field {name!r}")


def interval_sql(d: str) -> str:
    m = _DUR.match(d)
    if not m:
        raise ValueError(f"bad duration {d!r}; use e.g. 30s, 10m, 6h, 1d")
    return f"INTERVAL {int(m.group(1))} {_UNITS[m.group(2)]}"


def _ipv4_int(expr: str) -> str:
    return (f"(TRY_CAST(split_part({expr}, '.', 1) AS BIGINT) * 16777216 + TRY_CAST(split_part({expr}, '.', 2) AS BIGINT) * 65536"
            f" + TRY_CAST(split_part({expr}, '.', 3) AS BIGINT) * 256 + TRY_CAST(split_part({expr}, '.', 4) AS BIGINT))")


def _cidr_sql(f: str, nets, params: list) -> str:
    import ipaddress
    parts = []
    for n in nets if isinstance(nets, list) else [nets]:
        net = ipaddress.ip_network(str(n), strict=False)
        if net.version != 4:
            continue
        params.extend([int(net.network_address), int(net.broadcast_address)])
        parts.append(f"{_ipv4_int(f)} BETWEEN ? AND ?")
    return "(" + (" OR ".join(parts) or "FALSE") + ")"


# case-insensitive string operators (Sigma semantics); a list value means "any of"
_ISTR = {"ieq": "lower(CAST({f} AS VARCHAR)) = lower(?)", "icontains": "contains(lower(CAST({f} AS VARCHAR)), lower(?))",
         "istartswith": "starts_with(lower(CAST({f} AS VARCHAR)), lower(?))",
         "iendswith": "ends_with(lower(CAST({f} AS VARCHAR)), lower(?))", "iglob": "lower(CAST({f} AS VARCHAR)) GLOB lower(?)"}


def where_sql(where: dict, params: list) -> str:
    """{field: scalar | [list] | {op: value}} AND-ed together; `any: [where, ...]` OR-ed,
    `all: [where, ...]` AND-ed, `not: where` negated."""
    parts = []
    for name, cond in where.items():
        if name == "any":
            parts.append("(" + (" OR ".join(where_sql(w, params) for w in cond) or "FALSE") + ")")
            continue
        if name == "all":
            parts.append("(" + (" AND ".join(where_sql(w, params) for w in cond) or "TRUE") + ")")
            continue
        if name == "not":
            parts.append(f"NOT coalesce(({where_sql(cond, params)}), FALSE)")
            continue
        f = field_sql(name)
        if isinstance(cond, dict) and any(op in _ISTR or op in ("cidr", "exists") for op in cond):
            sub = []
            for op, v in cond.items():
                if op in _ISTR:
                    vals = v if isinstance(v, list) else [v]
                    params.extend(str(x) for x in vals)
                    sub.append("(" + " OR ".join(_ISTR[op].format(f=f) for _ in vals) + ")")
                elif op == "cidr":
                    sub.append(_cidr_sql(f, v, params))
                elif op == "exists":
                    sub.append(f"{f} IS {'NOT ' if v else ''}NULL")
                else:
                    sub.append(where_sql({name: {op: v}}, params))
            parts.append("(" + " AND ".join(sub) + ")")
            continue
        if isinstance(cond, list):
            params.extend(cond)
            parts.append(f"{f} IN ({', '.join('?' * len(cond))})")
        elif isinstance(cond, dict):
            for op, v in cond.items():
                if op == "in" or op == "not_in":
                    params.extend(v)
                    parts.append(f"{f} {'NOT ' if op == 'not_in' else ''}IN ({', '.join('?' * len(v))})")
                elif op == "between":
                    params.extend(v)
                    parts.append(f"{f} BETWEEN ? AND ?")
                elif op == "regex":
                    params.append(v)
                    parts.append(f"regexp_matches({f}, ?)")
                elif op == "is_null":
                    parts.append(f"{f} IS {'' if v else 'NOT '}NULL")
                elif op in OPS:
                    params.append(v)
                    parts.append(f"{f} {OPS[op]} ?")
                else:
                    raise ValueError(f"unknown operator {op!r}")
        else:
            params.append(cond)
            parts.append(f"{f} = ?")
    return " AND ".join(parts) or "TRUE"


class Technique(BaseModel):
    id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    name: str


class Threshold(BaseModel):
    count: int | None = None
    distinct: str | None = None
    sum: str | None = None
    value: float | None = None

    @model_validator(mode="after")
    def one_kind(self):
        if (self.count is None) == (self.distinct is None and self.sum is None):
            raise ValueError("threshold needs exactly one of count, or distinct/sum with value")
        if (self.distinct or self.sum) and self.value is None:
            raise ValueError("distinct/sum threshold needs value")
        return self


class Step(BaseModel):
    name: str
    key: str
    where: dict[str, Any]
    min_count: int = 1


class Periodic(BaseModel):
    """Beaconing: per key and bucket, at least min_count events whose gaps vary little (stddev/mean <= max_cv)."""
    min_count: int = 12
    max_cv: float = 0.15
    min_interval: str = "30s"


# the 14 ATT&CK enterprise tactics, plus "unmapped" for imported rules without a tactic tag
TACTICS = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation",
           "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection", "command-and-control",
           "exfiltration", "impact"]
STAGES = set(TACTICS) | {"unmapped"}
_OLD_STAGES = {"reconnaissance", "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion",
          "credential-access", "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration",
          "impact"}


class Rule(BaseModel):
    id: str = Field(pattern=r"^[A-Z0-9][A-Z0-9-]{2,40}$")
    version: int
    title: str
    type: Literal["event", "threshold", "sequence", "periodic"]
    severity: Literal["low", "medium", "high", "critical"]
    stage: str
    attack: list[Technique] = []
    where: dict[str, Any] = {}
    group_by: list[str] = []
    bucket: str | None = None
    window: str | None = None
    threshold: Threshold | None = None
    within: str | None = None
    steps: list[Step] = []
    periodic: Periodic | None = None
    requires: list[str] | None = None  # event categories this rule needs; absent in the data -> "not applicable"
    source: dict[str, Any] | None = None  # provenance for imported rules (e.g. Sigma id, path, author, license)
    tactics: list[str] | None = None  # every ATT&CK tactic the rule maps to (defaults to [stage])
    requires_fields: list[str] | None = None  # raw source fields the rule reads; none present in the data -> not applicable
    enabled: bool = True

    @field_validator("stage")
    @classmethod
    def known_stage(cls, v):
        if v not in STAGES:
            raise ValueError(f"stage must be one of {sorted(STAGES)}")
        return v

    @model_validator(mode="after")
    def shape(self):
        for f in self.group_by:
            field_sql(f)
        where_sql(self.where, [])
        if self.type == "threshold":
            if not (self.window and self.threshold and self.group_by):
                raise ValueError("threshold rule needs window, threshold and group_by")
            interval_sql(self.window)
            for f in (self.threshold.distinct, self.threshold.sum):
                if f:
                    field_sql(f)
        if self.type == "periodic":
            if not (self.periodic and self.group_by and self.bucket):
                raise ValueError("periodic rule needs periodic, group_by and bucket")
            interval_sql(self.periodic.min_interval)
        if self.type == "sequence":
            if len(self.steps) < 2 or not self.within:
                raise ValueError("sequence rule needs >= 2 steps and within")
            interval_sql(self.within)
            for s in self.steps:
                field_sql(s.key)
                where_sql(s.where, [])
        if self.bucket:
            interval_sql(self.bucket)
        return self

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.model_dump_json().encode()).hexdigest()[:12]


class RuleSet(BaseModel):
    attack_version: str
    rules: list[Rule]

    @model_validator(mode="after")
    def unique(self):
        ids = [r.id for r in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate rule id")
        return self

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256("".join(r.fingerprint for r in self.rules).encode()).hexdigest()[:12]


def lookback_parts(ruleset: RuleSet) -> tuple[int, int]:
    """(longest window/sequence span, longest grouping bucket) in seconds. Windows reach back from the
    batch; buckets only back to the start of the bucket the batch begins in."""
    def sec(d):
        m = _DUR.match(d)
        return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    w = max([sec(d) for r in ruleset.rules if r.enabled for d in (r.window, r.within) if d] or [0])
    b = max([sec(r.bucket) for r in ruleset.rules if r.enabled and r.bucket] or [0])
    return w, b


def max_lookback_seconds(ruleset: RuleSet) -> int:
    """Longest window/sequence span any rule needs: an incremental run must re-read this much history."""
    secs = 0
    for r in ruleset.rules:
        for d in (r.window, r.within, r.bucket):
            if d:
                m = _DUR.match(d)
                secs = max(secs, int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)])
    return secs


def load_rules(*paths) -> RuleSet:
    """Files or directories (every *.yaml inside, sorted)."""
    import glob as _glob
    import os as _os
    files = []
    for p in paths:
        files += sorted(_glob.glob(_os.path.join(p, "*.yaml"))) if _os.path.isdir(p) else [p]
    rules, version = [], None
    for p in files:
        with open(p, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        version = version or doc.get("attack_version")
        rules.extend(doc.get("rules", []))
    return RuleSet(attack_version=version or "unspecified", rules=rules)


def required_categories(rule: Rule) -> set[str] | None:
    """Event categories a rule can only match within (None = could match anything)."""
    if rule.requires is not None:
        return set(rule.requires)
    cats = set()
    for w in [rule.where] + [st.where for st in rule.steps]:
        c = w.get("category")
        if c is None:
            return None
        cats |= set(c if isinstance(c, list) else [c] if isinstance(c, str) else c.get("in", []))
    return cats or None
