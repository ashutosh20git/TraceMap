"""Content-based detection of compression and record format (never the extension)."""
import bz2
import csv
import gzip
import io
import re
from dataclasses import dataclass

import zstandard

from .parsers import PARSERS, CsvParser, ParseError

MAGIC = {b"\x28\xb5\x2f\xfd": "zstd", b"\x1f\x8b": "gzip", b"BZh": "bz2"}
_KV_PAIR = re.compile(rb'[A-Za-z_][\w.\-]*=(?:"[^"]*"|\S+)')


class UnsupportedFormat(ValueError):
    pass


@dataclass
class Detected:
    compression: str  # none | zstd | gzip | bz2
    format: str  # jsonl | kv | cef | leef | syslog | csv | tsv
    csv_header: bytes | None = None

    def parser(self):
        if self.format in ("csv", "tsv"):
            return CsvParser(self.csv_header, "," if self.format == "csv" else "\t")
        return PARSERS[self.format]


def detect_compression(head: bytes) -> str:
    for magic, name in MAGIC.items():
        if head.startswith(magic):
            return name
    return "none"


def open_decompressed(raw: io.BufferedIOBase, compression: str):
    if compression == "zstd":
        return zstandard.ZstdDecompressor().stream_reader(raw, read_across_frames=True)
    if compression == "gzip":
        return gzip.GzipFile(fileobj=raw)
    if compression == "bz2":
        return bz2.BZ2File(raw)
    return raw


def detect_format(sample: bytes, at_eof: bool = False) -> tuple[str, bytes | None]:
    """Decide from the first nonempty lines of decompressed text. Unless the
    sample reaches EOF, its last line may be cut off and is ignored."""
    parts = sample.split(b"\n")
    lines = [l.rstrip(b"\r") for l in (parts if at_eof else parts[:-1]) if l.strip(b" \r\t\x00")][:50]
    if not lines:
        raise UnsupportedFormat("no complete nonempty record in the first 1 MiB")
    first = lines[0].lstrip(b"\xef\xbb\xbf \t")
    if first[:1] == b"[":
        raise UnsupportedFormat("JSON array input: convert to one object per line (e.g. `jq -c '.[]'`) and resubmit")
    candidates = []
    if first[:1] == b"{":
        candidates.append("jsonl")
    if b"CEF:" in first[:200]:
        candidates.append("cef")
    if b"LEEF:" in first[:200]:
        candidates.append("leef")
    if first[:1] == b"<":
        candidates.append("syslog")
    if len(_KV_PAIR.findall(first)) >= 3:
        candidates.append("kv")
    best, best_ok = None, 0
    for fmt in candidates:
        ok = 0
        for l in lines:
            try:
                PARSERS[fmt](l)
                ok += 1
            except (ParseError, UnicodeDecodeError):
                pass
        if ok > best_ok:
            best, best_ok = fmt, ok
    if best and best_ok * 2 >= len(lines):  # bad rows are quarantined later, not used to reject the source
        return best, None
    try:
        dialect = csv.Sniffer().sniff(first.decode("utf-8"), delimiters=",\t")
    except (csv.Error, UnicodeDecodeError):
        raise UnsupportedFormat("unrecognized record format") from None
    widths = {len(next(csv.reader([l.decode("utf-8", "replace")], delimiter=dialect.delimiter))) for l in lines}
    if len(widths) == 1 and widths.pop() > 1:
        return ("tsv" if dialect.delimiter == "\t" else "csv"), lines[0]
    raise UnsupportedFormat("unrecognized record format")
