"""Per-file entity index: which segment files of a parsed source mention each IP / account.

Written once per source (sorted by value, small row groups), so a later revision that needs the
history of a few newly relevant entities reads the index and then only the segments that contain
them, instead of rescanning every older file.

    canonical/source=<id>/entity_index.parquet   kind, value, segs (list of segment files), events
"""


def index_path(events_glob: str) -> str:
    return events_glob.replace("/events/*.parquet", "/entity_index.parquet")


def build_entity_index(con, events_glob: str, out: str | None = None) -> str:
    out = out or index_path(events_glob)
    src = f"read_parquet('{events_glob}', filename=true)"
    con.execute(f"""COPY (
        SELECT kind, value, list(DISTINCT seg ORDER BY seg) AS segs, count(*) AS events FROM (
            SELECT 'ip' AS kind, src_ip AS value, filename AS seg FROM {src} WHERE src_ip IS NOT NULL
            UNION ALL SELECT 'ip', dst_ip, filename FROM {src} WHERE dst_ip IS NOT NULL
            UNION ALL SELECT 'user', user, filename FROM {src} WHERE user IS NOT NULL)
        GROUP BY kind, value ORDER BY kind, value)
        TO '{out}' (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 65536)""")
    return out


def segments_for(con, events_glob: str, ip_table: str, user_table: str) -> list[str] | None:
    """Segment files of one source that mention any of the given entities; None if it has no index."""
    import duckdb
    try:
        rows = con.execute(f"""SELECT DISTINCT unnest(segs) FROM read_parquet('{index_path(events_glob)}')
            WHERE (kind = 'ip' AND value IN (SELECT ip FROM {ip_table}))
               OR (kind = 'user' AND value IN (SELECT u FROM {user_table}))""").fetchall()
    except duckdb.Error:
        return None
    return sorted(r[0] for r in rows)
