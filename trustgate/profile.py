"""Profile canonical Parquet with DuckDB: counts, duplicates, time quality,
clock anomalies and top entities. Writes profile.json next to the events."""
import json
import sys

import duckdb


def profile(events_glob: str, region: str = "ap-south-1") -> dict:
    con = duckdb.connect()
    con.execute("SET memory_limit='3GB'; SET preserve_insertion_order=false; SET TimeZone='UTC'")
    if events_glob.startswith("s3://"):
        con.execute("INSTALL httpfs; LOAD httpfs; INSTALL aws; LOAD aws")
        con.execute(f"CREATE SECRET (TYPE s3, PROVIDER credential_chain, REGION '{region}')")
    con.execute(f"CREATE VIEW ev AS SELECT * EXCLUDE (raw) FROM read_parquet('{events_glob}')")

    def rows(sql):
        cur = con.execute(sql)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    out = {
        "totals": rows("""SELECT count(*) events, count(DISTINCT record_hash) distinct_records,
                          count(*) - count(DISTINCT record_hash) exact_duplicates,
                          min(event_time)::VARCHAR first_time, max(event_time)::VARCHAR last_time,
                          count(DISTINCT device) devices, count(DISTINCT user) users,
                          count(DISTINCT src_ip) src_ips, count(DISTINCT dst_ip) dst_ips FROM ev""")[0],
        "by_type": rows("""SELECT event_type, event_subtype, count(*) n FROM ev GROUP BY ALL ORDER BY n DESC"""),
        "time_quality": rows("SELECT time_quality, count(*) n FROM ev GROUP BY ALL ORDER BY n DESC"),
        # many records sharing one exact nanosecond timestamp indicates a stalled/clamped source clock
        "clock_stalls": rows("""SELECT event_time::VARCHAR t, count(*) n FROM ev GROUP BY event_time
                                HAVING count(*) > 1000 ORDER BY n DESC LIMIT 10"""),
        "events_per_day": rows("SELECT event_date::VARCHAR d, count(*) n FROM ev GROUP BY ALL ORDER BY d"),
        "top_codes": rows("""SELECT event_code, any_value(message) sample_message, count(*) n FROM ev
                             GROUP BY event_code ORDER BY n DESC LIMIT 25"""),
        "failed_admin_logins_top_src": rows("""SELECT src_ip, count(*) n, count(DISTINCT user) users FROM ev
                             WHERE event_code='0100032002' GROUP BY src_ip ORDER BY n DESC LIMIT 15"""),
        "utm_rules_top": rows("""SELECT event_subtype, rule_name, action, count(*) n FROM ev
                             WHERE event_type='utm' AND rule_name IS NOT NULL GROUP BY ALL ORDER BY n DESC LIMIT 25"""),
    }
    return out


if __name__ == "__main__":
    print(json.dumps(profile(sys.argv[1]), indent=2, default=str))
