"""
Parsers for each supported log source. Every parser is a generator that
yields plain dicts matching the Event schema fields in models.py. Nothing
here touches the DB directly -- ingest.py is responsible for persisting.

Add a new source: write a `parse_<source>(path_or_line) -> Iterator[dict]`
function and register it in SOURCE_PARSERS at the bottom of this file.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Iterator

from .models import SourceType

# ---------------------------------------------------------------------------
# Linux auth.log / secure log (SSH, sudo, etc.)
# ---------------------------------------------------------------------------

_AUTH_LINE_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[\w.\-/]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)

_SSH_FAILED_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
_SSH_ACCEPTED_RE = re.compile(
    r"Accepted (password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
_SUDO_RE = re.compile(r"(?P<user>\S+) : .*COMMAND=(?P<cmd>.*)")


def parse_auth_log(path: str, current_year: int | None = None) -> Iterator[dict]:
    current_year = current_year or datetime.now().year
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = _AUTH_LINE_RE.match(line)
            if not m:
                continue
            gd = m.groupdict()
            try:
                ts = datetime.strptime(f"{current_year} {gd['ts']}", "%Y %b %d %H:%M:%S")
            except ValueError:
                ts = datetime.now()

            base = {
                "timestamp": ts,
                "source_type": SourceType.AUTH_LOG,
                "host": gd["host"],
                "message": gd["msg"],
                "raw": {"line": line},
            }

            fm = _SSH_FAILED_RE.search(gd["msg"])
            if fm:
                yield {
                    **base,
                    "event_type": "auth_failure",
                    "user": fm.group("user"),
                    "src_ip": fm.group("ip"),
                    "src_port": int(fm.group("port")),
                    "process_name": "sshd",
                }
                continue

            am = _SSH_ACCEPTED_RE.search(gd["msg"])
            if am:
                yield {
                    **base,
                    "event_type": "auth_success",
                    "user": am.group("user"),
                    "src_ip": am.group("ip"),
                    "src_port": int(am.group("port")),
                    "process_name": "sshd",
                }
                continue

            sm = _SUDO_RE.search(gd["msg"])
            if sm and gd["proc"] == "sudo":
                yield {
                    **base,
                    "event_type": "privilege_use",
                    "user": sm.group("user"),
                    "process_name": "sudo",
                    "process_cmdline": sm.group("cmd"),
                }
                continue

            # Fallback: keep it as a generic auth-source event so nothing is dropped
            yield {
                **base,
                "event_type": "auth_log_generic",
                "process_name": gd["proc"],
            }


# ---------------------------------------------------------------------------
# Suricata EVE JSON (network IDS alerts)
# ---------------------------------------------------------------------------

def parse_suricata_eve(path: str) -> Iterator[dict]:
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            ts_raw = rec.get("timestamp")
            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")) if ts_raw else datetime.now()
            except ValueError:
                ts = datetime.now()

            event_type = rec.get("event_type", "unknown")
            alert = rec.get("alert", {})

            yield {
                "timestamp": ts,
                "source_type": SourceType.SURICATA,
                "host": rec.get("host", "unknown"),
                "event_type": f"suricata_{event_type}",
                "src_ip": rec.get("src_ip"),
                "dst_ip": rec.get("dest_ip"),
                "src_port": rec.get("src_port"),
                "dst_port": rec.get("dest_port"),
                "message": alert.get("signature") or rec.get("proto", ""),
                "raw": rec,
            }


# ---------------------------------------------------------------------------
# Generic syslog (routers, network devices) -- RFC3164-ish
# ---------------------------------------------------------------------------

_SYSLOG_RE = re.compile(
    r"^<?\d*>?(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<msg>.*)$"
)


def parse_syslog(path: str, current_year: int | None = None) -> Iterator[dict]:
    current_year = current_year or datetime.now().year
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = _SYSLOG_RE.match(line)
            if not m:
                continue
            gd = m.groupdict()
            try:
                ts = datetime.strptime(f"{current_year} {gd['ts']}", "%Y %b %d %H:%M:%S")
            except ValueError:
                ts = datetime.now()

            ip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", gd["msg"])

            yield {
                "timestamp": ts,
                "source_type": SourceType.ROUTER,
                "host": gd["host"],
                "event_type": "router_log",
                "src_ip": ip_match.group(1) if ip_match else None,
                "message": gd["msg"],
                "raw": {"line": line},
            }


# ---------------------------------------------------------------------------
# Windows Event Log -- via evtx export (JSON/XML) since pywin32 only works
# on an actual Windows host. Point this at a JSON export (e.g. from
# `python-evtx` or Windows' own "Save filtered log as JSON").
# ---------------------------------------------------------------------------

# Common Windows Security event IDs worth mapping to a readable event_type
_WINDOWS_EVENT_ID_MAP = {
    "4624": "auth_success",
    "4625": "auth_failure",
    "4672": "privilege_use",       # special privileges assigned to new logon
    "4688": "process_create",
    "4720": "user_account_created",
    "4732": "user_added_to_privileged_group",
    "1102": "audit_log_cleared",
}


def parse_windows_event_json(path: str) -> Iterator[dict]:
    """
    Expects a JSON file containing a list of event records with at least:
    {"TimeCreated": "...", "EventID": "4625", "Computer": "...",
     "Data": {"IpAddress": "...", "TargetUserName": "...", ...}}
    This is the shape you get from `Get-WinEvent | ConvertTo-Json` or
    python-evtx's JSON output -- adjust field names if your export differs.
    """
    with open(path, "r", errors="replace") as f:
        records = json.load(f)
    if isinstance(records, dict):
        records = [records]

    for rec in records:
        eid = str(rec.get("EventID", ""))
        data = rec.get("Data", {}) or {}
        ts_raw = rec.get("TimeCreated")
        try:
            ts = datetime.fromisoformat(ts_raw) if ts_raw else datetime.now()
        except ValueError:
            ts = datetime.now()

        yield {
            "timestamp": ts,
            "source_type": SourceType.WINDOWS_EVENT,
            "host": rec.get("Computer", "unknown"),
            "event_type": _WINDOWS_EVENT_ID_MAP.get(eid, f"windows_event_{eid}"),
            "src_ip": data.get("IpAddress"),
            "user": data.get("TargetUserName") or data.get("SubjectUserName"),
            "process_name": data.get("NewProcessName"),
            "process_cmdline": data.get("CommandLine"),
            "parent_process": data.get("ParentProcessName"),
            "message": rec.get("Message", f"EventID {eid}"),
            "raw": rec,
        }


SOURCE_PARSERS = {
    SourceType.AUTH_LOG: parse_auth_log,
    SourceType.SURICATA: parse_suricata_eve,
    SourceType.ROUTER: parse_syslog,
    SourceType.SYSLOG: parse_syslog,
    SourceType.WINDOWS_EVENT: parse_windows_event_json,
}
