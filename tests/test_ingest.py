import gzip
import json

import duckdb
import pytest
import zstandard

from trustgate.ingest.pipeline import IngestConfig, ingest
from trustgate.ingest.sniff import UnsupportedFormat

FGT = (b'date=2026-10-23 time=08:49:08 eventtime=1792745348000000000 tz="+0530" devname="FGT60F" logid="0100032002" '
       b'type="event" subtype="system" level="alert" logdesc="Admin login failed" user="terri" srcip=45.74.28.219 '
       b'dstip=10.10.99.1 action="login" status="failed" msg="Administrator terri login failed"')
SAMPLES = {
    "kv": [FGT, FGT.replace(b"terri", b"admin"), b'date=2026-10-23 time=08:49:09 eventtime=1792745349000000000 tz="+0530" type="traffic" srcip=10.0.0.1 srcport=5000 dstport=443 sentbyte=10 rcvdbyte=20'],
    "jsonl": [b'{"@timestamp":"2026-10-23T03:19:08Z","host":{"name":"h1"},"user":{"name":"bob"},"source":{"ip":"1.2.3.4","port":22},"event":{"category":["authentication"],"outcome":"failure"}}'] * 3,
    "cef": [b'<134>Oct 23 08:49:08 fw1 CEF:0|Acme|FW|1.0|100|Port scan detected|7|src=10.0.0.5 dst=10.0.0.9 dpt=22 suser=alice msg=scan of many ports rt=1792745348000'] * 3,
    "leef": [b'LEEF:1.0|IBM|QRadar|1.0|4625|src=10.1.1.1\tdst=10.1.1.2\tusrName=carol\tdevTime=2026-10-23T03:19:08+00:00'] * 3,
    "syslog": [b'<34>1 2026-10-23T03:19:08.123Z host1 sshd 991 ID47 - Failed password for root from 1.2.3.4 port 22',
               b'<34>Oct 23 08:49:08 host2 sshd[22]: user=root srcip=1.2.3.4 action=deny'] * 2,
    "csv": [b"timestamp,src_ip,dst_ip,user,action", b"2026-10-23T03:19:08Z,1.1.1.1,2.2.2.2,dave,allow", b"2026-10-23T03:19:09Z,1.1.1.1,2.2.2.3,dave,deny"],
}


def run(tmp_path, data: bytes, name="src.log", **cfg):
    p = tmp_path / name
    p.write_bytes(data)
    out = tmp_path / "out"
    m = ingest(str(p), str(out), "test", IngestConfig(workers=1, **cfg), log=lambda *_: None)
    return m, out


@pytest.mark.parametrize("fmt", list(SAMPLES))
def test_formats_detected_by_content_and_balanced(tmp_path, fmt):
    m, out = run(tmp_path, b"\n".join(SAMPLES[fmt]) + b"\n", name="mislabelled.json")
    assert m["format"] == fmt
    assert m["accounting"]["balanced"]
    rows = duckdb.sql(f"select count(*), count(event_time) from '{out}/events/*.parquet'").fetchall()[0]
    assert rows[0] == m["accounting"]["normalized"] > 0
    # RFC 3164 timestamps carry no year, so those rows honestly have no event_time
    assert rows[1] == (rows[0] // 2 if fmt == "syslog" else rows[0])


def test_fortigate_fields_and_time(tmp_path):
    m, out = run(tmp_path, b"\n".join(SAMPLES["kv"]) + b"\n")
    r = duckdb.sql(f"select user, src_ip, outcome, device, event_code, time_quality, event_time, attrs['tz'] "
                   f"from '{out}/events/*.parquet' order by line_no limit 1").fetchall()[0]
    assert r[:6] == ("terri", "45.74.28.219", "failure", "FGT60F", "0100032002", "epoch_is_local_wallclock")
    assert r[6].astimezone(__import__('datetime').timezone.utc).isoformat().startswith("2026-10-23T08:49:08")  # eventtime kept; tz mismatch is labelled
    assert r[7] == "+0530"


def test_compressed_inputs_and_offsets(tmp_path):
    body = b"\n".join(SAMPLES["kv"]) + b"\n"
    for name, data in (("a.zst", zstandard.ZstdCompressor().compress(body)), ("a.gz", gzip.compress(body))):
        m, out = run(tmp_path, data, name=name)
        assert m["offset_space"] == "decompressed" and m["accounting"]["normalized"] == 3
        offs = duckdb.sql(f"select byte_offset, byte_length from '{out}/events/*.parquet' order by line_no").fetchall()
        for off, ln in offs:
            assert body[off:off + ln].startswith(b"date=")


def test_framing_edge_cases(tmp_path):
    # CRLF, blank lines, malformed row, bad utf-8, no trailing newline
    data = SAMPLES["kv"][0] + b"\r\n\r\n   \n" + b"garbage line\n" + b"user=\xff\xfe srcip=1.1.1.1 x=1\n" + SAMPLES["kv"][2]
    m, out = run(tmp_path, data)
    a = m["accounting"]
    assert a["balanced"] and a["normalized"] == 2 and a["quarantined"] == 2 and a["blank_lines"] == 2
    assert set(a["reasons"]) == {"kv_parse_error", "bad_utf8"}


def test_chunk_boundaries_do_not_split_records(tmp_path):
    lines = [SAMPLES["kv"][i % 3].replace(b"srcip=", b"seq=%d srcip=" % i) for i in range(500)]
    m, out = run(tmp_path, b"\n".join(lines) + b"\n", chunk_bytes=1000)  # far smaller than total
    assert m["accounting"]["normalized"] == 500 and len(m["segments"]) > 10
    seqs = duckdb.sql(f"select attrs['seq']::int s from '{out}/events/*.parquet' order by line_no").fetchall()
    assert [s[0] for s in seqs] == list(range(500))


def test_truncated_record_with_nul_padding_is_quarantined(tmp_path):
    # mirrors firex-50G: last record cut off and followed by a long NUL run with no newline
    data = b"\n".join(SAMPLES["kv"]) + b"\n" + FGT[:80] + b"\x00" * 300_000
    m, out = run(tmp_path, data, chunk_bytes=4096, max_record_bytes=65536)
    a = m["accounting"]
    assert a["balanced"] and a["normalized"] == 3 and a["reasons"] == {"oversize": 1}
    q = json.loads((out / "quarantine" / "oversize.jsonl").read_text())
    assert q["byte_offset"] == len(b"\n".join(SAMPLES["kv"]) + b"\n") and q["byte_length"] == 80 + 300_000


def test_json_array_rejected_with_guidance(tmp_path):
    with pytest.raises(UnsupportedFormat, match="jq"):
        run(tmp_path, b'[{"a":1},\n{"a":2}]\n')
