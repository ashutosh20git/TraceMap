"""Generate a synthetic multi-source security log with planted attacks and an answer key.

Deliberately NOT FortiGate: Windows-Security-style JSON events mixed with firewall flows, IDS
alerts, VPN and configuration events in one JSON-lines file. Halfway through, the Windows
events switch to different field names (schema drift); a few malformed lines and exact
duplicate deliveries are included. All addresses are RFC 5737 documentation ranges or private
ranges; zone fields mark which side of the firewall a record came from.

    python scripts/make_synthetic.py <out.jsonl> [answer-key.md]
"""
import datetime as dt
import json
import random
import sys

R = random.Random(7)
T0 = dt.datetime(2026, 10, 25, 6, 0, tzinfo=dt.timezone.utc)
DRIFT_AT = dt.datetime(2026, 10, 26, 0, 0, tzinfo=dt.timezone.utc)  # Windows field names change here
END = dt.datetime(2026, 10, 26, 20, 0, tzinfo=dt.timezone.utc)
FIRST = ["a", "b", "c", "d", "k", "m", "n", "p", "r", "s", "t", "v"]
LAST = ["sharma", "mehta", "iyer", "rao", "kapoor", "shah", "nair", "das", "joshi", "menon", "verma", "pillai"]
USERS = sorted({f"{f}.{l}" for f in FIRST for l in LAST})[:120]
HOSTS = [f"10.20.{R.randint(1, 7)}.{R.randint(10, 250)}" for _ in range(300)]
SERVERS = [f"10.20.8.{i}" for i in range(1, 21)]
DMZ = ["10.30.1.10", "10.30.1.11", "10.30.1.12"]
INTERNET = [f"198.18.{R.randint(0, 255)}.{R.randint(1, 254)}" for _ in range(400)]  # benchmark range, never real hosts
events = []


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def win(t, event_id, user, ip, zone, msg, logon_type=None, subject=None, computer="DC01"):
    """Windows Security event; field names change after DRIFT_AT (schema drift)."""
    if t < DRIFT_AT:
        e = {"TimeCreated": iso(t), "EventID": event_id, "Computer": computer, "TargetUserName": user,
             "IpAddress": ip, "SourceZone": zone, "Message": msg}
        if subject:
            e["SubjectUserName"] = subject
    else:
        e = {"time_created": iso(t), "EventID": event_id, "host": computer, "account_name": user,
             "client_address": ip, "SourceZone": zone, "Message": msg}
        if subject:
            e["actor_name"] = subject
    if logon_type:
        e["LogonType"] = logon_type
    events.append((t, e))


def rand_time(start=T0, end=END, work_hours=True):
    while True:
        t = start + dt.timedelta(seconds=R.uniform(0, (end - start).total_seconds()))
        if not work_hours or 6 <= t.hour < 22:  # benign activity stays out of 00:00-05:59
            return t


# ---------------------------------------------------------------- benign background
for _ in range(6000):
    win(rand_time(), 4624, R.choice(USERS), R.choice(HOSTS), "internal", "An account was successfully logged on.", logon_type=R.choice([2, 3, 10]))
for _ in range(400):
    win(rand_time(), 4625, R.choice(USERS), R.choice(HOSTS), "internal", "An account failed to log on.", logon_type=3)
for _ in range(25000):
    t = rand_time()
    src = R.choice(HOSTS)
    if R.random() < 0.06:
        dst, port, dz = R.choice(SERVERS[:3]), 445, "internal"  # normal file-share use: few servers per host
    else:
        dst, port, dz = R.choice(INTERNET), R.choice([443, 443, 443, 80, 53]), "external"
    events.append((t, {"ts": iso(t), "event_type": "traffic", "device": "edge-fw-01", "src_ip": src, "src_port": R.randint(20000, 65000),
                       "dst_ip": dst, "dst_port": port, "proto": "tcp", "action": "allow", "bytes_out": R.randint(200, 90000),
                       "bytes_in": R.randint(200, 900000), "SourceZone": "internal", "DestinationZone": dz}))
for _ in range(150):
    t = rand_time(work_hours=False)
    events.append((t, {"ts": iso(t), "event_type": "ids", "device": "ids-01", "src_ip": R.choice(INTERNET), "dst_ip": R.choice(DMZ),
                       "dst_port": 443, "signature": R.choice(["HTTP.Suspicious.UserAgent", "Scanner.Nmap.Probe", "TLS.Weak.Cipher"]),
                       "severity": "low", "action": "detected", "SourceZone": "external", "DestinationZone": "dmz"}))
for _ in range(200):
    t = rand_time()
    u = R.choice(USERS)
    events.append((t, {"ts": iso(t), "event_type": "vpn", "device": "vpn-gw-01", "user": u, "src_ip": f"198.18.200.{R.randint(1, 254)}",
                       "src_country": "India", "action": "tunnel-up", "status": "success", "message": f"SSL VPN tunnel up for user {u}",
                       "SourceZone": "external"}))
for _ in range(20):
    t = rand_time()
    events.append((t, {"ts": iso(t), "event_type": "config", "device": "edge-fw-01", "user": R.choice(["a.shah", "k.nair"]),
                       "src_ip": "10.20.3.9", "message": f"Attribute 'description' of object 'addr-grp-{R.randint(1, 40)}' changed",
                       "SourceZone": "internal"}))

# ---------------------------------------------------------------- planted scenarios
key = []
t = dt.datetime(2026, 10, 25, 10, 0, tzinfo=dt.timezone.utc)
spray = [f"203.0.113.{i}" for i in range(10, 16)]
for ip in spray:
    for _ in range(15):
        win(t + dt.timedelta(seconds=R.uniform(0, 5400)), 4625, R.choice(USERS + ["administrator", "admin", "backup"]), ip, "external",
            "An account failed to log on.", logon_type=3)
key.append(("S1 password spray from one /24", "2026-10-25 10:00-11:30", "TG-AUTH-002", "203.0.113.0/24 (6 addresses x 15 failures, many usernames)"))

bf = "198.51.100.23"
t = dt.datetime(2026, 10, 25, 13, 0, tzinfo=dt.timezone.utc)
for i in range(40):
    win(t + dt.timedelta(seconds=9 * i), 4625, "j.mehta", bf, "external", "An account failed to log on.", logon_type=10)
win(dt.datetime(2026, 10, 25, 13, 7, 10, tzinfo=dt.timezone.utc), 4624, "j.mehta", bf, "external", "An account was successfully logged on.", logon_type=10)
key.append(("S2 brute force, then success for the same account", "2026-10-25 13:00-13:07", "TG-AUTH-001, TG-AUTH-003, TG-AUTH-004", "198.51.100.23 -> j.mehta"))

win(dt.datetime(2026, 10, 25, 13, 15, tzinfo=dt.timezone.utc), 4720, "helpdesk_tmp", bf, "external", "A user account was created.", subject="j.mehta")
win(dt.datetime(2026, 10, 25, 13, 20, tzinfo=dt.timezone.utc), 4624, "helpdesk_tmp", bf, "external", "An account was successfully logged on.", logon_type=10)
win(dt.datetime(2026, 10, 25, 13, 40, tzinfo=dt.timezone.utc), 4726, "helpdesk_tmp", bf, "external", "A user account was deleted.", subject="j.mehta")
key.append(("S3 account created, used, deleted", "2026-10-25 13:15-13:40", "TG-PERS-001, TG-PERS-002, TG-AUTH-004", "j.mehta creates helpdesk_tmp; login from 198.51.100.23"))

win(dt.datetime(2026, 10, 25, 13, 45, tzinfo=dt.timezone.utc), 1102, "j.mehta", bf, "external", "The audit log was cleared.", subject="j.mehta")
key.append(("S4 security log cleared", "2026-10-25 13:45", "TG-EVAS-001", "j.mehta"))

t = dt.datetime(2026, 10, 25, 14, 30, tzinfo=dt.timezone.utc)
for i, srv in enumerate(SERVERS[:8]):
    for j in range(6):
        tt = t + dt.timedelta(minutes=10 * i + j)
        events.append((tt, {"ts": iso(tt), "event_type": "traffic", "device": "core-fw-02", "src_ip": "10.20.5.17", "src_port": R.randint(40000, 60000),
                            "dst_ip": srv, "dst_port": 445, "proto": "tcp", "action": "allow", "bytes_out": R.randint(2000, 9000),
                            "bytes_in": R.randint(200000, 2000000), "SourceZone": "internal", "DestinationZone": "internal"}))
key.append(("S5 SMB fan-out from one workstation", "2026-10-25 14:30-15:50", "TG-LAT-001", "10.20.5.17 -> 10.20.8.1-8 port 445"))

win(dt.datetime(2026, 10, 26, 3, 12, tzinfo=dt.timezone.utc), 4624, "svc_backup", "10.20.9.4", "internal", "An account was successfully logged on.", logon_type=3)
key.append(("S6 login at 03:12 (after the schema change)", "2026-10-26 03:12", "TG-AUTH-005", "svc_backup from 10.20.9.4"))

t = dt.datetime(2026, 10, 26, 9, 10, tzinfo=dt.timezone.utc)
for i in range(15):
    tt = t + dt.timedelta(seconds=80 * i)
    events.append((tt, {"ts": iso(tt), "event_type": "ids", "device": "ids-01", "src_ip": "192.0.2.66", "dst_ip": "10.30.1.10", "dst_port": 443,
                        "signature": R.choice(["HTTP.URI.SQL.Injection", "HTTP.Path.Traversal"]), "severity": "high", "action": "blocked",
                        "SourceZone": "external", "DestinationZone": "dmz"}))
key.append(("S7 repeated exploit attempts on a DMZ server", "2026-10-26 09:10-09:30", "TG-WEB-001", "192.0.2.66 -> 10.30.1.10"))

for when, ip, country in ((dt.datetime(2026, 10, 26, 11, 0, tzinfo=dt.timezone.utc), "198.51.100.40", "Germany"),
                          (dt.datetime(2026, 10, 26, 11, 35, tzinfo=dt.timezone.utc), "203.0.113.77", "Brazil")):
    events.append((when, {"ts": iso(when), "event_type": "vpn", "device": "vpn-gw-01", "user": "r.kapoor", "src_ip": ip, "src_country": country,
                          "action": "tunnel-up", "status": "success", "message": "SSL VPN tunnel up for user r.kapoor", "SourceZone": "external"}))
key.append(("S8 one VPN account from two countries in 35 min", "2026-10-26 11:00-11:35", "TG-VPN-001", "r.kapoor: Germany, then Brazil"))

for minute, msg in ((0, "Audit logging changed from 'enable' to 'disable'"), (20, "Firewall policy rules purged"),
                    (40, "Audit logging changed from 'disable' to 'enable'")):
    when = dt.datetime(2026, 10, 26, 15, minute, tzinfo=dt.timezone.utc)
    events.append((when, {"ts": iso(when), "event_type": "config", "device": "edge-fw-01", "user": "a.shah", "src_ip": "10.20.3.9",
                          "message": msg, "SourceZone": "internal"}))
key.append(("S9 logging off, policies purged, logging on", "2026-10-26 15:00-15:40", "TG-EVAS-001, TG-EVAS-002, TG-EVAS-003", "a.shah from 10.20.3.9"))

# ---------------------------------------------------------------- scenarios for the remaining ATT&CK tactics
def flow(t, src, dst, port, sz, dz, bytes_out=900, bytes_in=1200, action="allow"):
    events.append((t, {"ts": iso(t), "event_type": "traffic", "device": "edge-fw-01", "src_ip": src, "src_port": R.randint(20000, 65000),
                       "dst_ip": dst, "dst_port": port, "proto": "tcp", "action": action, "bytes_out": bytes_out, "bytes_in": bytes_in,
                       "SourceZone": sz, "DestinationZone": dz}))


t = dt.datetime(2026, 10, 25, 8, 30, tzinfo=dt.timezone.utc)
for i, port in enumerate(R.sample(range(1, 1024), 25)):
    flow(t + dt.timedelta(seconds=10 * i), "203.0.113.200", "10.30.1.11", port, "external", "dmz", 60, 0, "deny")
for i in range(40):
    flow(t + dt.timedelta(minutes=20, seconds=6 * i), "203.0.113.201", f"10.30.1.{20 + i}", 443, "external", "dmz", 60, 0, "deny")
key.append(("S10 external port scan and host sweep", "2026-10-25 08:30-08:55", "TG-RECON-001, TG-RECON-002", "203.0.113.200 -> 10.30.1.11 (25 ports); 203.0.113.201 -> 40 DMZ hosts"))

win(dt.datetime(2026, 10, 25, 13, 30, tzinfo=dt.timezone.utc), 4732, "Administrators", bf, "external",
    "A member was added to a security-enabled local group.", subject="j.mehta")
key.append(("S11 account added to Administrators", "2026-10-25 13:30", "TG-PRIV-001", "j.mehta adds helpdesk_tmp"))

t = dt.datetime(2026, 10, 25, 13, 35, tzinfo=dt.timezone.utc)
events.append((t, {"TimeCreated": iso(t), "EventID": 4688, "Computer": "WS-17", "SubjectUserName": "j.mehta",
                   "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                   "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
                   "SourceZone": "internal", "Message": "A new process has been created."}))
key.append(("S12 encoded, hidden PowerShell", "2026-10-25 13:35", "TG-EXEC-001", "j.mehta on WS-17"))

t = dt.datetime(2026, 10, 25, 14, 10, tzinfo=dt.timezone.utc)
for i in range(30):
    flow(t + dt.timedelta(seconds=10 * i), "10.20.5.17", f"10.20.{R.randint(1, 7)}.{200 + i}", 135, "internal", "internal", 60, 0)
for i, port in enumerate(R.sample(range(1, 1024), 25)):
    flow(t + dt.timedelta(minutes=6, seconds=8 * i), "10.20.5.17", "10.20.8.9", port, "internal", "internal", 60, 0)
key.append(("S13 internal sweep and port scan", "2026-10-25 14:10-14:20", "TG-DISC-001, TG-DISC-002", "10.20.5.17 -> 30 hosts; -> 10.20.8.9 (25 ports)"))

t = dt.datetime(2026, 10, 25, 16, 0, tzinfo=dt.timezone.utc)
for i in range(20):
    flow(t + dt.timedelta(minutes=2 * i), "10.20.5.17", "10.20.8.3", 445, "internal", "internal", 4000, 40_000_000)
key.append(("S14 bulk pull from a file server", "2026-10-25 16:00-16:40", "TG-COLL-001", "10.20.5.17 <- 10.20.8.3, ~800 MB"))

t = dt.datetime(2026, 10, 25, 15, 0, tzinfo=dt.timezone.utc)
for i in range(108):
    flow(t + dt.timedelta(seconds=300 * i + R.uniform(-4, 4)), "10.20.5.17", "198.51.100.99", 443, "internal", "external", 512, 256)
key.append(("S15 beaconing every 5 minutes", "2026-10-25 15:00-23:59", "TG-C2-001", "10.20.5.17 -> 198.51.100.99:443"))

t = dt.datetime(2026, 10, 26, 2, 0, tzinfo=dt.timezone.utc)
for i in range(8):
    flow(t + dt.timedelta(minutes=3 * i), "10.20.5.17", "198.51.100.99", 443, "internal", "external", 300_000_000, 4000)
key.append(("S16 2.4 GB sent out in 25 minutes", "2026-10-26 02:00-02:25", "TG-EXFIL-001", "10.20.5.17 -> 198.51.100.99"))

t = dt.datetime(2026, 10, 26, 16, 30, tzinfo=dt.timezone.utc)
for i in range(12):
    win(t + dt.timedelta(seconds=20 * i), 4726, f"{R.choice(USERS)}", "10.20.3.9", "internal", "A user account was deleted.", subject="a.shah")
for i, svc in enumerate(["Volume Shadow Copy", "Windows Backup", "SQL Server (MSSQLSERVER)", "Windows Defender Antivirus Service",
                         "Veeam Backup Service", "Print Spooler"]):
    win(t + dt.timedelta(minutes=10, seconds=30 * i), 7036, "SYSTEM", "10.20.8.1", "internal",
        f"The {svc} service entered the stopped state.", computer="FS-01")
key.append(("S17 mass account deletion and services stopped", "2026-10-26 16:30-16:43", "TG-IMP-001, TG-IMP-002", "DC01: 12 deletions by a.shah; FS-01: 6 services"))

# ---------------------------------------------------------------- write
events.sort(key=lambda x: x[0])
lines = [json.dumps(e, separators=(",", ":")) for _, e in events]
for i in R.sample(range(len(lines)), 5):  # exact duplicate deliveries
    lines.insert(i, lines[i])
for bad in ('{"TimeCreated":"2026-10-25T12:00:00.000Z","EventID":4624,"TargetUserName":"x"', "\x00\x01garbage-binary-line\x02",
            '{"ts": not json at all}'):
    lines.insert(R.randrange(len(lines)), bad)

out = sys.argv[1]
with open(out, "w", encoding="utf-8", newline="\n") as f:
    f.write("\n".join(lines) + "\n")
print(f"wrote {len(lines):,} lines to {out}")

if len(sys.argv) > 2:
    with open(sys.argv[2], "w", encoding="utf-8") as f:
        f.write("# TrustGate synthetic test log: answer key\n\n")
        f.write(f"File: `{out.split(chr(92))[-1].split('/')[-1]}` · {len(lines):,} lines · JSON lines · times in UTC\n\n")
        f.write("Mixed event types in one file: Windows Security logons/accounts, firewall flows, IDS alerts, VPN and config events.\n\n")
        f.write("Built-in traps the pipeline should handle:\n\n")
        f.write("- **Schema change at 2026-10-26 00:00:** Windows events rename `TimeCreated` to `time_created`, `TargetUserName` to `account_name`, `IpAddress` to `client_address`, `Computer` to `host` and `SubjectUserName` to `actor_name`. Scenarios S6 to S9 are after the change.\n")
        f.write("- **Records to set aside:** 3 malformed lines (truncated JSON, binary garbage, invalid JSON).\n")
        f.write("- **Exact duplicates:** 5 duplicate deliveries, each to be counted once.\n")
        f.write("- **Background noise:** about 31,000 benign events that should not trigger rules.\n\n")
        f.write("| Scenario | When (UTC) | Expected rules | Entities |\n|---|---|---|---|\n")
        for k in key:
            f.write("| " + " | ".join(k) + " |\n")
        f.write("\nExpected result: exactly one detection per listed rule per scenario, except TG-AUTH-004 (twice: S2 and S3) "
                "and TG-EVAS-001 (twice: S4 and S9), and no detections from the background noise. TG-AUTH-001 must not fire "
                "on the S1 spray addresses (15 failures each, spread over 90 minutes).\n")


def write_batches(directory: str):
    """Split the same events into 4 time-ordered files, with boundaries placed inside attacks
    (S2's brute force and S8's two VPN logins each straddle two files), as a stream of batches would."""
    import os
    cuts = [dt.datetime(2026, 10, 25, 13, 3, 30, tzinfo=dt.timezone.utc), dt.datetime(2026, 10, 25, 22, 0, tzinfo=dt.timezone.utc),
            dt.datetime(2026, 10, 26, 11, 20, tzinfo=dt.timezone.utc)]
    os.makedirs(directory, exist_ok=True)
    buckets = [[], [], [], []]
    for t, e in events:
        buckets[sum(t >= c for c in cuts)].append(json.dumps(e, separators=(",", ":")))
    paths = []
    for i, b in enumerate(buckets, 1):
        p = os.path.join(directory, f"trustgate-batch-{i}.jsonl")
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(b) + "\n")
        paths.append(p)
        print(f"batch {i}: {len(b):,} events -> {p}")
    return paths


if len(sys.argv) > 3:
    write_batches(sys.argv[3])
