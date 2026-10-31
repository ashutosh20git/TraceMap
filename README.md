# TrustGate

Security-log ingestion → canonical Parquet → DuckDB analytics (→ Neo4j relationship graph, next).

## Ingestion (FR-1)

```
pip install -r requirements.txt
python -m trustgate.cli ingest <file | s3://bucket/key> <out-dir | s3://bucket/prefix>
python -m trustgate.profile "<out>/events/*.parquet"
```

- **Format is detected from content, never the extension**: FortiGate/generic `key=value`, JSONL (nested objects flattened, arrays kept as JSON), CEF, LEEF 1.0/2.0, RFC 5424/3164 syslog (payload re-parsed as CEF/LEEF/JSON/kv), CSV/TSV. JSON arrays are rejected with a conversion hint rather than loaded whole.
- **Compression detected by magic bytes**: zstd, gzip, bz2, streamed. Offsets then refer to the decompressed stream (`offset_space` in the manifest).
- **Bounded streaming**: the parent frames newline-aligned 64 MiB chunks; workers parse/normalize and write one closed Parquet segment each (`seg-NNNNNN`, retry-safe). In-flight chunks are bounded (backpressure).
- **Nothing is silently dropped**: bad UTF-8, parse failures, NUL bytes and oversized records go to `quarantine/` with locator, reason and a 4 KiB prefix. The manifest proves `nonempty_records == normalized + quarantined`.
- **Provenance per event**: `line_no`, `byte_offset`, `byte_length`, `record_hash` (exact-duplicate detection), `raw` bytes, unmapped fields in `attrs`.
- **Time honesty**: `event_time_text` keeps the source value; `time_quality` labels `ok`, `wallclock_only`, `missing`, `conflict_wallclock`, or `epoch_is_local_wallclock` (epoch field equals local wall-clock read as UTC — true of the hackathon FortiGate data).

Canonical columns: see `trustgate/ingest/normalize.py` (`SCHEMA`, `ALIASES`). Adding a new source vendor is an alias-table change.

## AWS

`infra/aws/trustgate-core.yaml` (CloudFormation, `infra/aws/deploy.sh`): raw + lake S3 buckets, DynamoDB metadata, SQS ingest/maintenance/report queues with DLQs, Glue/Iceberg database, VPC with S3/DynamoDB gateway endpoints, SSM-only EC2 worker. Raw logs are uploaded with `scripts/upload_raw.py` (streamed zstd + SHA-256 manifest of the original bytes).

Stop the worker when idle: `aws ec2 stop-instances --instance-ids <id>`.

## Tests

`python -m pytest -q tests` — every format, compressed inputs and offsets, CRLF/blank/malformed/bad-UTF-8 rows, chunk-boundary integrity, truncated record + NUL padding, JSON-array rejection.

## Detection (FR-2/3, B-4) and graph (FR-4/5)

```
python -m trustgate.cli detect "<events glob>" <findings-dir> [--rules config/rules/*.yaml]
python -m trustgate.cli graph  "<events glob>" <findings-dir> --snapshot <graph.json>   # NEO4J_PASSWORD, NEO4J_URI
```

- Rules are YAML (`config/rules/core.yaml`), validated with Pydantic and compiled to DuckDB SQL with bound parameters. Types: `event`, `threshold` (true sliding RANGE windows across all files/segments; count / distinct / sum), `sequence` (ordered steps joined on per-step keys within a time limit). Every rule carries ATT&CK techniques and a kill-chain stage.
- Exact duplicate deliveries are counted once. Findings whose evidence sits on a stalled clock are flagged `time_reliability=degraded_clock_stall`.
- The graph expands only entities that appear in findings. `AUTH`, `FLOW` and `CONFIGURED` edges are `observed` aggregates carrying sample evidence IDs. Finding-to-finding `RELATED` edges carry basis, claim, checks, missing inputs, time gap and version. Hub entities (the firewall's own management IP, or usernames sprayed by brute force) are never used to merge findings. `Incident` nodes are `candidate` groupings with explained risk factors.
- Neo4j: `infra/neo4j/docker-compose.yml` on the EC2 worker. Reach it with SSM port-forwards for ports 7474 and 7687.

## Analyst UI (FR-5/FR-7)

```
aws s3 cp s3://<lake>/graph/source=firex/snapshot.json data/snapshot.json   # published snapshot
cd apps/web && npm ci && npm run build && cd ../..
python -m uvicorn trustgate.api.app:app --port 8000      # serves API + built UI at http://localhost:8000
# dev mode with hot reload: run uvicorn as above, then `cd apps/web && npm run dev` (proxies /api)
```

The API serves the published snapshot only and never scans the corpus per request. Routes: `/api/summary`, `/api/incidents`, `/api/incidents/{id}` (graph nodes/edges + evidence events), `/api/events/{uid}` (exact raw record + byte provenance), `/api/findings`, `/api/rules`, and OpenAPI docs at `/docs`.

The UI has a risk-ranked candidate-incident list, a React Flow + ELK graph (findings, IPs, accounts, device; observed vs contextual edges), a zoomable time-scaled timeline with per-source lanes and finding spans, a virtualized chronological event list, and an inspector showing claim/checks/missing evidence and the escaped raw record. Selecting anything in one view highlights it in the others.

## Reports (B-2): BullMQ + Jinja2 + WeasyPrint

```
cp .env.example .env            # GEMINI_API_KEY=..., GEMINI_MODEL=gemini-3.1-flash-lite (optional)
docker compose up -d --build    # redis :6380, Bull Board :3001, report worker
python -m uvicorn trustgate.api.app:app --port 8000
```

- **Flow:** UI "Generate PDF report" → `POST /api/incidents/{id}/reports` (202) → BullMQ `reports` queue in Redis → Python worker (`trustgate/reports/worker.py`) runs `building_story → building_assets → rendering → validating → stored`. Poll `GET /api/reports/{id}` and download from `/api/reports/{id}/download`. The queue dashboard is Bull Board at http://localhost:3001/admin/queues.
- **Idempotent and immutable:** the report ID hashes the incident, snapshot SHA-256, template bundle, LLM model and renderer. A repeated request reuses the stored artifact (`reports/<id>/report.pdf`, `story.json`, `graph.svg`, `timeline.svg`, `manifest.json`).
- **Story:** the deterministic StoryComposer (`trustgate/reports/story.py`) produces numbered claims (C1…). Each claim carries its sentence, ATT&CK techniques, decision, limitations and the raw source log lines it rests on. Relationships keep their decision label (contextual or pivot). Gaps and limitations are mandatory.
- **AI narrative:** optional, via Gemini (`trustgate/reports/llm.py`). It is given only structured facts, never raw logs. Its output is accepted only if it cites every claim and nothing else, names no IP outside the incident, and avoids overclaiming words (confirmed, unauthorized, malicious, compromised). Otherwise the report uses the deterministic summary and records why. Transient model errors fail the job, so BullMQ retries it (3 attempts with exponential backoff); only the final attempt falls back.
- **Rendering safety:** Jinja2 with `autoescape=True` and `StrictUndefined`; log text is never marked safe. WeasyPrint runs in a killable child process with a timeout and a memory limit. Its URL fetcher serves only `asset://report.css|logo.png|graph.svg|timeline.svg` and refuses everything else. Template: `report_templates/incident-detailed/v1/`, with the logo top right, and "CONFIDENTIAL" plus "Page X of Y" in every footer.

## Upload → Process → board (live workflow)

- **Data sources page:** drag and drop any log files. The browser fingerprints each file (SHA-256 of its first and last MiB plus size) and uploads it **straight to S3** in 64 MiB multipart parts using presigned URLs: 4 parts in flight per file, 2 files at a time, each part retried. The API never handles file bytes.
- **Duplicates:** the same bytes uploaded twice, even concurrently, are linked to the first source. After ingest, the full content SHA-256 is compared too, and an identical file's canonical copy is dropped.
- **Process:** creates a run (DynamoDB) and sends one SQS `ingest` message per new file. If the EC2 worker is stopped, the API starts it; the worker stops itself after 30 idle minutes.
- **Parsing vs analysis:** files are parsed in parallel. When the last one finishes, a single `analyze` runs detection and graph building over **all** ingested sources together, so windows and sequences that cross file boundaries are evaluated once.
- **Locking and publishing:** a DynamoDB lease allows one analysis at a time. A run that arrives mid-analysis waits, then publishes the next revision. Each snapshot is written as `graph/ws=default/rev-N.json`, and only then does the head pointer move forward (conditional write, never backwards).
- **What the board shows:** the published head, or an empty board if nothing has been published yet.
- **Related sources** (shared device or overlapping time range) are listed in the snapshot's `sources`.

## Schema changes and unknown vendors

- `trustgate/ingest/semantics.py` assigns every event a vendor-neutral **category / activity / outcome / zone**. It uses known vendor IDs (FortiGate `logid`, Windows `EventID`), then category words, then message patterns. All rules in `config/rules/core.yaml` match only these fields.
- **Unknown field names:** canonical fields that no alias covers are inferred per source from field-name tokens and value shapes (IP-like, parseable time, account-like). The result is recorded in `manifest.schema.inferred_mappings`.
- **Mid-file changes:** a change of field layout or record format halfway through a file is handled. Records are parsed by whichever parser fits, and chunks with new layouts re-infer their own mappings. The manifest reports layout fingerprints, `drift`, per-segment inferred mappings, field coverage and the unmapped-field ratio.
- `tests/test_schemas.py` runs one attack in FortiGate, Windows Security, sshd syslog, CEF and an unknown JSON layout, plus a mid-file format change, and expects identical detections.

## Equal and stalled timestamps

- Equal timestamps mean **order unknown**. Ordering comes only from content constraints (create → use → delete, session IDs) or, within one file, recorded log position, labelled as unverified. Order is never compared across files.
- Counts, distinct counts and graph aggregates don't depend on order and stay valid.
- A pivot (target later became source) requires a strictly positive gap and reliable clocks. Otherwise the link is `order_unresolved` and never merges incidents.
- Timestamps shared by ≥1,000 events are flagged as clock stalls (`time_reliability=degraded_clock_stall`). Each finding shows a warning and the risk score is reduced. The timeline shows tied events as one cluster with a count.

## Cases: many files, separate or connected

- A **case** is one investigation. Its files, processing runs, published revisions, incidents, graph and reports are all separate from other cases (`?case=<id>` on every API call; DynamoDB keys `WS#<case>`; lake prefixes `findings/ws=<case>/`, `graph/ws=<case>/`; queue messages carry the case). Put unrelated logs in different cases so they never mix.
- **Inside a case, all files are analyzed together.** Parsing is per file, but detection and graph building run over the union of every parsed file. A window, sequence or shared entity that crosses files is found once, and a record present in two files is counted once.
- **Provenance:** every incident lists the files its evidence came from. Incidents with more than one are marked "spans N files", and flowchart cards show their file. The Checks page lists how the files relate (shared device, overlapping time).
- **Connections across cases** are never merged automatically; a shared IP or account is context, not proof.
- **Reports** pin the case and revision when requested (`data/snapshots/<case>/rev-N.json`), so a later revision never changes an existing report.

## Incremental knowledge base (batches arriving over time)

Each new file in a case (for example the next 5 GB export) becomes one **revision**. It is parsed alone and then joined to everything already known (`trustgate/kb/incremental.py`):

- **Detection:** reads only the new batch plus a lookback equal to the longest rule window, extended back to the start of any detection that is still open. A brute force that starts in one file and ends in the next keeps its detection ID and fires once, with all its events. Late events move the lookback back to cover them. A changed rule set triggers a full recompute.
- **Knowledge base:** stored in `findings/ws=<case>/rev-N/kb/`:
  - `entities.parquet`: tracked IPs and accounts, with first/last seen, counts and `first_rev`;
  - `edges.parquet`: login, flow and config-change relationships, with count, interval, evidence and `first_rev`;
  - `sources.parquet`: per-file time range and devices.

  New files are scanned for all tracked entities. Older files are scanned only for entities that became tracked in this revision, so every event is counted exactly once.
- **Graph and incidents:** built from the knowledge base and merged into Neo4j. Every node, edge, detection and incident carries the revision it first appeared in. An incident is marked **grew** when it ties earlier detections to new data, or when one of its detections continued into the new batch.
- **Seeing it:**
  - the Checks page has a "How the knowledge base grew" panel with per-revision totals and additions;
  - the entity graph has a revision slider and **Replay growth**, where new nodes get a green ring and new links animate;
  - incidents show "grew in rev N".
- **Proof:** `tests/test_incremental.py` processes 4 batches whose boundaries cut through attacks. It asserts the result equals one full run, including relationship counts, and that the cross-batch incident is marked as grown.
- **Demo:** `python scripts/make_synthetic.py out.jsonl key.md <batch-dir>` writes 4 batch files. `python scripts/stream_batches.py "<case>" <batch files...>` uploads and processes them one at a time through the API.
- **Entity index per file:** after parsing, each source gets `canonical/source=<id>/entity_index.parquet`, a sorted list of every IP and account with the segment files that mention it (`trustgate/kb/index.py`; `python -m trustgate.cli index <glob>...` for files parsed earlier). When an entity first becomes relevant, its history is read only from those segments, not from every older file. Files without an index fall back to a full scan. Tracked entities are never dropped, so history is never counted twice.
- **Deleting a case:** the "Delete" button in the top bar, or `DELETE /api/cases/<id>`, removes its records, published snapshots, detections, knowledge base, parsed events and uploaded files (every stored version). It is refused while a run is in progress; the first case cannot be deleted.

## Detection rules and ATT&CK coverage

- **TrustGate rules: 24** (`config/rules/core.yaml`, `tactics.yaml`). They cover 13 of the 14 ATT&CK tactics, using vendor-neutral fields only. Resource development leaves no trace in host or network logs. Rule types: `event`, `threshold`, `sequence` and `periodic` (beaconing: regular intervals, low variation). `tests/test_scenarios.py` requires every rule to fire exactly on its planted synthetic scenario and nowhere else.
- **Sigma rules: 3,289** imported from SigmaHQ `r2026-07-01` (`trustgate/detection/sigma.py`, `scripts/sigma_import.py`). Supported: the full condition grammar (and/or/not, parentheses, `1 of`/`all of`, `them`) and the modifiers contains, startswith, endswith, all, re, cidr, windash, exists and gt/lt, plus wildcards. Aggregation and correlation rules, base64/utf16 transforms and field references are skipped with a reason (13 rules). Free-text keyword rules (68) are imported disabled, because they would match any product's logs. Newer ATT&CK tags Stealth and Defense Impairment are shown under Defense Evasion.
- **Applicability:** a rule is *not applicable* when the data has none of the event categories or raw fields it needs, so it is skipped without scanning. This keeps 3,313 rules fast. Each rule's status (fired / no match / not applicable / error) is merged across revisions, shown on the **Rules & coverage** page (14 tactic columns), and served by `/api/coverage`.
- **Mixed-layout files:** field inference runs per field layout, so a file mixing firewall flows and renamed Windows events maps each layout's own time, account and address fields.
