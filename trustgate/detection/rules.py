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
             "bytes_in", "time_quality", "schema_fp"}
DERIVED = {
    "src_net24": r"regexp_extract(src_ip, '^(\d+\.\d+\.\d+)\.', 1) || '.0/24'",
    # device wall-clock hour; for sources whose epoch is already local time (time_quality=epoch_is_local_wallclock)
    "local_hour": "hour(event_time)",
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


def where_sql(where: dict, params: list) -> str:
    """{field: scalar | [list] | {op: value}} AND-ed together; `any: [where, ...]` OR-ed."""
    parts = []
    for name, cond in where.items():
        if name == "any":
            parts.append("(" + " OR ".join(where_sql(w, params) for w in cond) + ")")
            continue
        f = field_sql(name)
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


STAGES = {"reconnaissance", "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion",
          "credential-access", "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration",
          "impact"}


class Rule(BaseModel):
    id: str = Field(pattern=r"^[A-Z0-9][A-Z0-9-]{2,40}$")
    version: int
    title: str
    type: Literal["event", "threshold", "sequence"]
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


def load_rules(*paths) -> RuleSet:
    rules, version = [], None
    for p in paths:
        with open(p, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        version = version or doc.get("attack_version")
        rules.extend(doc.get("rules", []))
    return RuleSet(attack_version=version or "unspecified", rules=rules)
