"""Per-record parsers. Each takes one record's bytes (no newline) and returns a
flat dict[str, str] of source fields, or raises ParseError. Values stay strings;
typing happens in normalize so the parsers stay format-only."""
import csv
import re

import orjson


class ParseError(ValueError):
    pass


# key=value / key="quoted value" (FortiGate, generic kv syslog payloads)
_KV = re.compile(r'([A-Za-z_][\w.\-]*)=(?:"((?:[^"\\]|\\.)*)"|(\S*))')
# CEF extension: values may contain spaces; a value ends where the next "key=" starts
_CEF_EXT = re.compile(rb'([A-Za-z_][\w.\-\[\]]*)=((?:[^=\\]|\\.)*?)(?=\s+[A-Za-z_][\w.\-\[\]]*=|\s*$)')
_RFC5424 = re.compile(rb'^<(\d{1,3})>(\d{1,2}) (\S+) (\S+) (\S+) (\S+) (\S+) (?:-|(?:\[.*?\])+) ?(.*)$', re.S)
_RFC3164 = re.compile(rb'^<(\d{1,3})>([A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (\S+) ([^:\[\s]+)(?:\[(\d+)\])?: ?(.*)$', re.S)
_PRI_ONLY = re.compile(rb'^<(\d{1,3})>(.*)$', re.S)


def _d(b: bytes) -> str:
    return b.decode("utf-8", "strict")


def parse_kv(line: bytes) -> dict:
    text = line.decode("utf-8")  # one strict decode per record; raises UnicodeDecodeError
    pairs = _KV.findall(text)
    if len(pairs) < 2:
        raise ParseError("kv: fewer than two key=value pairs")
    if "\\" in text:
        return {k: (q.replace('\\"', '"') if q else b) for k, q, b in pairs}
    return {k: q or b for k, q, b in pairs}


def _flatten(obj, prefix, out):
    for k, v in obj.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            _flatten(v, key + ".", out)
        elif isinstance(v, list):
            out[key] = orjson.dumps(v).decode()  # arrays preserved as JSON text
        elif v is None:
            continue
        else:
            out[key] = v if isinstance(v, str) else orjson.dumps(v).decode()
    return out


def parse_jsonl(line: bytes) -> dict:
    try:
        obj = orjson.loads(line)
    except orjson.JSONDecodeError as e:
        raise ParseError(f"json: {e}") from None
    if not isinstance(obj, dict):
        raise ParseError("json: record is not an object")
    return _flatten(obj, "", {})


def _cef_unescape(b: bytes) -> str:
    return _d(b).replace("\\=", "=").replace("\\|", "|").replace("\\\\", "\\").replace("\\n", "\n").strip()


def parse_cef(line: bytes) -> dict:
    i = line.find(b"CEF:")
    if i < 0:
        raise ParseError("cef: no CEF header")
    out = _syslog_header(line[:i]) if i else {}
    parts = re.split(rb"(?<!\\)\|", line[i + 4:], maxsplit=7)
    if len(parts) < 8:
        raise ParseError("cef: header has fewer than 8 fields")
    for name, v in zip(("cef_version", "vendor", "product", "product_version", "signature_id", "name", "severity"), parts):
        out[name] = _cef_unescape(v)
    for k, v in _CEF_EXT.findall(parts[7]):
        out[_d(k)] = _cef_unescape(v)
    return out


def parse_leef(line: bytes) -> dict:
    i = line.find(b"LEEF:")
    if i < 0:
        raise ParseError("leef: no LEEF header")
    out = _syslog_header(line[:i]) if i else {}
    parts = line[i + 5:].split(b"|")
    if len(parts) < 6:
        raise ParseError("leef: header has fewer than 6 fields")
    out.update(leef_version=_d(parts[0]), vendor=_d(parts[1]), product=_d(parts[2]),
               product_version=_d(parts[3]), signature_id=_d(parts[4]))
    delim, ext = b"\t", b"|".join(parts[5:])
    if parts[0].startswith(b"2") and len(parts) >= 7:  # LEEF 2.0 declares its delimiter
        d = parts[5]
        delim = bytes([int(d[2:], 16)]) if d[:2].lower() == b"0x" else (d or b"\t")
        ext = b"|".join(parts[6:])
    for item in ext.split(delim):
        if b"=" in item:
            k, v = item.split(b"=", 1)
            out[_d(k.strip())] = _d(v)
    return out


def _syslog_header(prefix: bytes) -> dict:
    prefix = prefix.strip()
    if not prefix:
        return {}
    m = _PRI_ONLY.match(prefix)
    return {"syslog_pri": _d(m.group(1))} if m else {"syslog_prefix": _d(prefix)}


def parse_syslog(line: bytes) -> dict:
    m = _RFC5424.match(line)
    if m:
        pri, _, ts, host, app, procid, msgid, msg = m.groups()
        out = {"syslog_pri": _d(pri), "syslog_time": _d(ts), "syslog_host": _d(host), "syslog_app": _d(app),
               "syslog_procid": _d(procid), "syslog_msgid": _d(msgid)}
    else:
        m = _RFC3164.match(line)
        if m:
            pri, ts, host, tag, pid, msg = m.groups()
            out = {"syslog_pri": _d(pri), "syslog_time": _d(ts), "syslog_host": _d(host), "syslog_app": _d(tag)}
            if pid:
                out["syslog_procid"] = _d(pid)
        else:
            m = _PRI_ONLY.match(line)
            if not m:
                raise ParseError("syslog: no <PRI> header")
            out, msg = {"syslog_pri": _d(m.group(1))}, m.group(2)
    msg = msg.strip()
    if msg.startswith(b"\xef\xbb\xbf"):
        msg = msg[3:]
    if b"CEF:" in msg[:200]:
        out.update(parse_cef(msg))
    elif b"LEEF:" in msg[:200]:
        out.update(parse_leef(msg))
    elif msg[:1] == b"{":
        out.update(parse_jsonl(msg))
    else:
        # free text is the message; any key=value pairs inside it are extra structured fields
        out["message"] = _d(msg)
        try:
            out.update({k: v for k, v in parse_kv(msg).items() if k != "message"})
        except ParseError:
            pass
    return out


class CsvParser:
    """Header taken from the source's first line. Quoted embedded newlines are
    not supported by line framing and surface as field-count errors."""

    def __init__(self, header: bytes, delimiter: str):
        self.delimiter = delimiter
        self.columns = next(csv.reader([_d(header)], delimiter=delimiter))
        self.header = header

    def __call__(self, line: bytes) -> dict:
        if line == self.header:
            raise ParseError("csv: header row")
        row = next(csv.reader([_d(line)], delimiter=self.delimiter))
        if len(row) != len(self.columns):
            raise ParseError(f"csv: expected {len(self.columns)} fields, got {len(row)}")
        return {k: v for k, v in zip(self.columns, row) if v != ""}


PARSERS = {"jsonl": parse_jsonl, "kv": parse_kv, "cef": parse_cef, "leef": parse_leef, "syslog": parse_syslog}
