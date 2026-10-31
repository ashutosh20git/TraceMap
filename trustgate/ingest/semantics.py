"""Vendor-neutral meaning for every event: category, activity, outcome, zones
and the account being acted on. Detection rules match these, never vendor
event IDs or message wording, so a different log schema still fires them.

Order of evidence: explicit vendor IDs we know (FortiGate logid, Windows
EventID) -> source category/action words -> message text patterns. Anything
unrecognized stays category "other"; nothing is guessed into an attack class.
"""
import ipaddress
import re
from functools import lru_cache

# Known vendor event IDs -> (category, activity, outcome or None)
EVENT_IDS = {
    # FortiGate
    "0100032001": ("authentication", "login", "success"),
    "0100032002": ("authentication", "login", "failure"),
    "0101039947": ("vpn", "login", "success"),
    "0101039424": ("vpn", "login", "failure"),
    "0000000013": ("network", "flow", None),
    # Windows Security / System
    "4624": ("authentication", "login", "success"),
    "4625": ("authentication", "login", "failure"),
    "4648": ("authentication", "login", None),
    "4720": ("account_management", "create", "success"),
    "4726": ("account_management", "delete", "success"),
    "4728": ("account_management", "modify", "success"),
    "4732": ("account_management", "modify", "success"),
    "4719": ("configuration", "disable_logging", None),
    "1102": ("configuration", "clear_logs", "success"),
    "104": ("configuration", "clear_logs", "success"),
    "4688": ("process", "start", None),
}
SUBTYPE_CATEGORY = {"ips": "intrusion", "virus": "malware", "webfilter": "web", "dns": "dns", "app-ctrl": "application",
                    "vpn": "vpn", "forward": "network", "traffic": "network", "ids": "intrusion", "malware": "malware",
                    "authentication": "authentication", "network": "network", "intrusion_detection": "intrusion"}

_P = lambda s: re.compile(s, re.I)
TEXT_RULES = [  # (pattern, category, activity, outcome)
    (_P(r"(log|audit)\w*.{0,40}(changed from .?enable.? to .?disable|disabled|stopped|turned off)"), "configuration", "disable_logging", "success"),
    (_P(r"(log|audit)\w*.{0,40}(changed from .?disable.? to .?enable|re-?enabled)"), "configuration", "enable_logging", "success"),
    (_P(r"(audit )?log\w* (was )?cleared|clear(ed)? (the )?(event|security) log"), "configuration", "clear_logs", "success"),
    (_P(r"(polic(y|ies)|rules?|ruleset).{0,30}(purged|flushed|deleted|removed)"), "configuration", "delete_policy", "success"),
    (_P(r"^delete system\.admin|\b(delete|deleted|removed|userdel)\b.{0,25}\b(admin|user|account)\b"), "account_management", "delete", "success"),
    (_P(r"^add system\.admin|\b(add|create|created|added|new)\b.{0,25}\b(admin|user|account)\b|\buseradd\b"), "account_management", "create", "success"),
    (_P(r"(failed|failure|invalid|incorrect|bad).{0,40}(login|log ?in|logon|password|authenticat)|authentication failure|login failed"), "authentication", "login", "failure"),
    (_P(r"(accepted|successful(ly)?|succeeded).{0,40}(login|log ?in|logon|password|publickey|authenticat)|logged in successfully"
        r"|(login|log ?in|logon|authenticat\w*).{0,20}(succeeded|successful|accepted|granted|ok\b)"), "authentication", "login", "success"),
    (_P(r"tunnel (is )?up|vpn.{0,20}(connected|established)"), "vpn", "login", "success"),
    (_P(r"attribute .* changed|configur(ed|ation) (changed|modified)|objects? .* (edited|modified)"), "configuration", "modify", "success"),
]
OUTCOME_WORDS = {
    "success": "success", "succeeded": "success", "successful": "success", "accept": "success", "accepted": "success",
    "allow": "success", "allowed": "success", "pass": "success", "permit": "success", "ok": "success",
    "failed": "failure", "failure": "failure", "fail": "failure", "deny": "failure", "denied": "failure",
    "block": "failure", "blocked": "failure", "reject": "failure", "rejected": "failure", "dropped": "failure",
    "invalid": "failure", "0xc000006d": "failure",
}
ZONE_WORDS = {"wan": "external", "untrust": "external", "untrusted": "external", "outside": "external",
              "internet": "external", "external": "external", "lan": "internal", "trust": "internal",
              "inside": "internal", "internal": "internal", "dmz": "dmz"}
_ACCOUNT_IN_TEXT = re.compile(r"system\.admin\s+(\S+)|\b(?:user|account|admin)\s*[=:]?\s*['\"]?([A-Za-z0-9._@\\-]{2,64})", re.I)


@lru_cache(maxsize=65536)
def zone_of_ip(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        a = ipaddress.ip_address(ip.strip("[]"))
    except ValueError:
        return None
    return "internal" if (a.is_private or a.is_loopback or a.is_link_local) else "external"


def zone(word: str | None, ip: str | None) -> str | None:
    if word:
        z = ZONE_WORDS.get(word.strip().lower())
        if z:
            return z
    return zone_of_ip(ip)


def classify(code, etype, esub, action, outcome_raw, message) -> tuple[str, str | None, str | None]:
    """Returns (category, activity, outcome)."""
    cat = act = out = None
    if code and str(code).strip() in EVENT_IDS:
        cat, act, out = EVENT_IDS[str(code).strip()]
    text = " ".join(x for x in (message, action) if x)
    if text and (cat is None or cat in ("configuration", "network") or act is None):
        for pat, c, a, o in TEXT_RULES:
            if pat.search(text):
                # a specific text meaning refines a generic id meaning (e.g. config change -> log disabled)
                if cat is None or c == cat or cat == "configuration":
                    cat, act, out = c, a, out or o
                break
    if cat is None:
        for w in (esub, etype):
            if w and (c := SUBTYPE_CATEGORY.get(str(w).lower())):
                cat = c
                break
    if cat in ("intrusion", "malware") and act is None:
        act = "alert"
    if outcome_raw:
        out = OUTCOME_WORDS.get(str(outcome_raw).strip().lower(), out)
    elif out is None and action:
        out = OUTCOME_WORDS.get(str(action).strip().lower())
    return cat or "other", act, out


def target_account(category, activity, fields: dict, message: str | None):
    if category != "account_management":
        return None
    for k in ("TargetUserName", "target_user", "target.user.name", "user.target.name", "object", "duser"):
        if fields.get(k):
            return fields[k]
    if message and (m := _ACCOUNT_IN_TEXT.search(message)):
        return m.group(1) or m.group(2)
    return None
