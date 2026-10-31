"""Durable workspace state in DynamoDB (single table, pk/sk).

  SOURCE#<id> / META   one uploaded file: status, S3 key, fingerprints, manifest summary
  RUN#<id>    / META   one "Process" click: per-step progress, sources included, revision published
  WS#<ws>     / HEAD   published snapshot pointer (revision, S3 key); only advanced forward, conditionally
  WS#<ws>     / LOCK   analysis lease: one analysis per workspace at a time

All transitions use conditional writes so duplicate or reordered queue
messages cannot double-count or roll a published revision backwards.
"""
import contextvars
import datetime as dt
import os
import re
import time
import uuid
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Attr, Key

# The current case (workspace). Set per API request and per queue message, so concurrent work for
# different cases never shares sources, runs, published heads or locks.
_ws = contextvars.ContextVar("trustgate_case", default=os.environ.get("TRUSTGATE_WORKSPACE", "default"))
_CASE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,40}$")


def ws() -> str:
    return _ws.get()


def use_case(case_id: str):
    if not _CASE_ID.match(case_id or ""):
        raise ValueError("invalid case id")
    _ws.set(case_id)


def _env(name):
    v = os.environ.get(name)
    if v:
        return v
    from pathlib import Path
    p = Path(__file__).resolve().parents[2] / ".env.aws"
    if p.exists():
        for line in p.read_text().splitlines():
            if line.startswith(name + "="):
                return line.split("=", 1)[1].strip()
    raise RuntimeError(f"{name} not configured")


def table():
    return boto3.resource("dynamodb", region_name=_env("AWS_REGION")).Table(_env("TRUSTGATE_META_TABLE"))


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _plain(o):
    if isinstance(o, list):
        return [_plain(x) for x in o]
    if isinstance(o, dict):
        return {k: _plain(v) for k, v in o.items()}
    if isinstance(o, Decimal):
        return int(o) if o == o.to_integral_value() else float(o)
    return o


def new_id(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------- cases
def put_case(case_id: str, name: str):
    table().put_item(Item={"pk": f"CASE#{case_id}", "sk": "META", "gsi1pk": "CASES", "gsi1sk": now(),
                           "case_id": case_id, "name": name[:80], "created_at": now()},
                     ConditionExpression="attribute_not_exists(pk)")


def list_cases():
    r = table().query(IndexName="gsi1", KeyConditionExpression=Key("gsi1pk").eq("CASES"))
    return [_plain(i) for i in r.get("Items", [])]


# ---------------------------------------------------------------- sources
def put_source(item: dict):
    table().put_item(Item={"pk": f"SOURCE#{item['source_id']}", "sk": "META", "gsi1pk": f"WS#{ws()}#SOURCES",
                           "gsi1sk": item["created_at"], **item})


def get_source(sid):
    r = table().get_item(Key={"pk": f"SOURCE#{sid}", "sk": "META"}).get("Item")
    return _plain(r) if r else None


def list_sources():
    r = table().query(IndexName="gsi1", KeyConditionExpression=Key("gsi1pk").eq(f"WS#{ws()}#SOURCES"))
    return [_plain(i) for i in r.get("Items", [])]


def update_source(sid, expected_status=None, **fields):
    names = {f"#{k}": k for k in fields}
    values = {f":{k}": v for k, v in fields.items()}
    kw = {}
    if expected_status:
        kw["ConditionExpression"] = Attr("status").is_in(expected_status if isinstance(expected_status, list) else [expected_status])
    table().update_item(Key={"pk": f"SOURCE#{sid}", "sk": "META"},
                        UpdateExpression="SET " + ", ".join(f"#{k} = :{k}" for k in fields),
                        ExpressionAttributeNames=names, ExpressionAttributeValues=values, **kw)


# ---------------------------------------------------------------- runs
def put_run(item: dict):
    table().put_item(Item={"pk": f"RUN#{item['run_id']}", "sk": "META", "gsi1pk": f"WS#{ws()}#RUNS",
                           "gsi1sk": item["created_at"], **item})


def get_run(rid):
    r = table().get_item(Key={"pk": f"RUN#{rid}", "sk": "META"}).get("Item")
    return _plain(r) if r else None


def latest_run():
    r = table().query(IndexName="gsi1", KeyConditionExpression=Key("gsi1pk").eq(f"WS#{ws()}#RUNS"),
                      ScanIndexForward=False, Limit=1)
    items = r.get("Items", [])
    return _plain(items[0]) if items else None


def update_run(rid, **fields):
    table().update_item(Key={"pk": f"RUN#{rid}", "sk": "META"},
                        UpdateExpression="SET " + ", ".join(f"#{k} = :{k}" for k in fields),
                        ExpressionAttributeNames={f"#{k}": k for k in fields},
                        ExpressionAttributeValues={f":{k}": v for k, v in fields.items()})


def finish_ingest(rid, sid) -> int:
    """Record one source as done for a run; returns how many are still pending.
    Idempotent: a redelivered message for the same source does not decrement twice."""
    try:
        r = table().update_item(
            Key={"pk": f"RUN#{rid}", "sk": "META"},
            UpdateExpression="ADD done_sources :s SET pending = pending - :one",
            ConditionExpression="NOT contains(done_sources, :sid)",
            ExpressionAttributeValues={":s": {sid}, ":sid": sid, ":one": 1}, ReturnValues="ALL_NEW")
        return int(r["Attributes"]["pending"])
    except table().meta.client.exceptions.ConditionalCheckFailedException:
        return int(get_run(rid)["pending"])


# ---------------------------------------------------------------- published head + analysis lease
def get_head():
    r = table().get_item(Key={"pk": f"WS#{ws()}", "sk": "HEAD"}).get("Item")
    return _plain(r) if r else None


def advance_head(revision: int, snapshot_key: str, run_id: str, sources: list):
    """Only moves forward: an older or duplicate analysis can never overwrite a newer head."""
    table().put_item(
        Item={"pk": f"WS#{ws()}", "sk": "HEAD", "revision": revision, "snapshot_key": snapshot_key, "run_id": run_id,
              "sources": sources, "published_at": now()},
        ConditionExpression="attribute_not_exists(revision) OR revision < :r", ExpressionAttributeValues={":r": revision})


def acquire_lock(owner: str, lease_s=900) -> bool:
    t = int(time.time())
    try:
        table().put_item(Item={"pk": f"WS#{ws()}", "sk": "LOCK", "owner": owner, "expires_at": t + lease_s},
                         ConditionExpression="attribute_not_exists(pk) OR expires_at < :t OR #o = :o",
                         ExpressionAttributeNames={"#o": "owner"}, ExpressionAttributeValues={":t": t, ":o": owner})
        return True
    except table().meta.client.exceptions.ConditionalCheckFailedException:
        return False


def release_lock(owner: str):
    try:
        table().delete_item(Key={"pk": f"WS#{ws()}", "sk": "LOCK"}, ConditionExpression="#o = :o",
                            ExpressionAttributeNames={"#o": "owner"}, ExpressionAttributeValues={":o": owner})
    except table().meta.client.exceptions.ConditionalCheckFailedException:
        pass
