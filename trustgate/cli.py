import argparse
import json
import os
import sys


def main(argv=None):
    ap = argparse.ArgumentParser(prog="trustgate")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ing = sub.add_parser("ingest", help="Parse any supported log source into canonical Parquet")
    ing.add_argument("source", help="local path or s3://bucket/key (format and compression are auto-detected)")
    ing.add_argument("out", help="output dir or s3://bucket/prefix")
    ing.add_argument("--source-id")
    ing.add_argument("--workers", type=int)
    ing.add_argument("--chunk-mib", type=int, default=64)
    det = sub.add_parser("detect", help="Run YAML rules over canonical Parquet")
    det.add_argument("events", help="events glob, e.g. s3://lake/canonical/source=x/events/*.parquet")
    det.add_argument("out", help="findings output dir (local or s3://)")
    det.add_argument("--rules", nargs="+", default=["config/rules"])
    det.add_argument("--temp-dir")
    gr = sub.add_parser("graph", help="Build the relationship graph and load Neo4j")
    gr.add_argument("events")
    gr.add_argument("findings", help="findings dir written by `detect`")
    gr.add_argument("--snapshot", help="also write a JSON graph snapshot here")
    gr.add_argument("--neo4j-uri", default=os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    gr.add_argument("--neo4j-user", default=os.environ.get("NEO4J_USER", "neo4j"))
    gr.add_argument("--no-load", action="store_true", help="build and snapshot only")
    ix = sub.add_parser("index", help="Build the entity index for parsed sources (history lookups read only matching segments)")
    ix.add_argument("events", nargs="+", help="events glob(s), e.g. s3://lake/canonical/source=<id>/events/*.parquet")
    args = ap.parse_args(argv)

    if args.cmd == "index":
        from .detection import engine
        from .kb.index import build_entity_index
        con = engine.connect(temp_dir="/data/duckdb-spill" if os.path.isdir("/data/duckdb-spill") else None)
        if any(g.startswith("s3://") for g in args.events):
            engine._enable_s3(con, os.environ.get("AWS_REGION", "ap-south-1"))
        for g in args.events:
            print(build_entity_index(con, g), flush=True)
        return 0

    if args.cmd == "detect":
        from .detection import engine
        from .detection.rules import load_rules
        rs = load_rules(*args.rules)
        con = engine.connect(temp_dir=args.temp_dir)
        print(json.dumps(engine.run(rs, args.events, args.out, con=con, log=lambda s: print(s, flush=True)), indent=2))
        return 0

    if args.cmd == "graph":
        from .graph import build as g
        graph = g.build(args.events, args.findings)
        print(json.dumps({k: len(v) for k, v in graph.items()}), "hubs:", graph["hubs"][:5], flush=True)
        if args.snapshot:
            g.write_snapshot(graph, args.snapshot)
        if not args.no_load:
            print(json.dumps(g.load(graph, args.neo4j_uri, args.neo4j_user, os.environ["NEO4J_PASSWORD"])))
        for inc in graph["incidents"][:15]:
            print(f"{inc['id']} risk={inc['risk']} {inc['first'][:19]}..{inc['last'][:19]} stages={inc['stages']} rules={inc['rules']} n={len(inc['finding_ids'])}")
        return 0

    if args.cmd == "ingest":
        from .ingest.pipeline import IngestConfig, ingest
        cfg = IngestConfig(chunk_bytes=args.chunk_mib << 20)
        if args.workers:
            cfg.workers = args.workers
        m = ingest(args.source, args.out, args.source_id, cfg, log=lambda s: print(s, flush=True))
        print(json.dumps({k: m[k] for k in ("format", "compression", "accounting", "event_time_range", "elapsed_s")},
                         indent=2, default=str))
        return 0 if m["accounting"]["balanced"] else 1


if __name__ == "__main__":
    sys.exit(main())
