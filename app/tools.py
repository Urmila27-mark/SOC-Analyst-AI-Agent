"""
Read-only investigation tools for the triage agent. Every function here
takes a SQLAlchemy session plus tool-specific args and returns a plain
dict (JSON-serializable) -- that dict becomes the tool_result content
sent back to Claude.

IMPORTANT: these are all read-only / side-effect-free by design. Nothing
in this file can block an IP, kill a process, or change any state --
that's deliberately kept separate in actions.py, which is gated by the
AUTO/CONFIRM tier logic. Triage should never be able to accidentally
cause a side effect just because the model decided to.
"""

from __future__ import annotations

import ipaddress
from datetime import timedelta

from sqlalchemy.orm import Session

from .models import Asset, Event

# ---------------------------------------------------------------------------
# Tool schemas (Anthropic Messages API "tools" format)
# ---------------------------------------------------------------------------

TRIAGE_TOOLS = [
    {
        "name": "query_logs",
        "description": (
            "Search normalized events in the log database. Use this to pull "
            "surrounding context for an alert -- e.g. what else did this IP "
            "do, what happened on this host around the same time, has this "
            "user had other unusual activity."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "src_ip": {"type": "string", "description": "Filter by source IP"},
                "host": {"type": "string", "description": "Filter by hostname"},
                "user": {"type": "string", "description": "Filter by username"},
                "event_type": {"type": "string", "description": "Filter by event type, e.g. auth_failure"},
                "minutes_before": {
                    "type": "integer",
                    "description": "How many minutes before the alert's earliest event to search (default 30)",
                },
                "minutes_after": {
                    "type": "integer",
                    "description": "How many minutes after the alert's latest event to search (default 30)",
                },
                "limit": {"type": "integer", "description": "Max rows to return (default 50)"},
            },
        },
    },
    {
        "name": "enrich_ip",
        "description": (
            "Get reputation/context info for an IP address: whether it's "
            "private/internal, how many times it's appeared across other "
            "alerts in this environment, and (if configured) external "
            "threat-intel lookups."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"ip": {"type": "string", "description": "IP address to look up"}},
            "required": ["ip"],
        },
    },
    {
        "name": "get_process_tree",
        "description": (
            "Get the process ancestry/lineage around a given host and time "
            "window, based on process_create-type events (parent -> child). "
            "Useful for judging whether a process launch looks like normal "
            "admin activity or a living-off-the-land attack pattern."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "around_timestamp": {
                    "type": "string",
                    "description": "ISO timestamp to center the window on (usually the alert's event time)",
                },
                "minutes_window": {"type": "integer", "description": "Minutes before/after to include (default 10)"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "check_asset_criticality",
        "description": (
            "Look up how important a given host is (criticality 1-5, asset "
            "type, notes). A brute-force attempt against a throwaway VM is "
            "very different from one against your NAS or main dev box."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"hostname": {"type": "string"}},
            "required": ["hostname"],
        },
    },
    {
        "name": "submit_triage",
        "description": (
            "Finalize your triage of this alert. Call this exactly once, "
            "when you're done investigating, to record your conclusion. "
            "This is how you deliver your result -- plain text responses "
            "without calling this tool will NOT be recorded."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "2-4 sentence plain-language summary of what happened and why it matters.",
                },
                "severity_assessment": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"],
                    "description": "Your assessed severity, which may differ from the rule's default severity.",
                },
                "confidence": {
                    "type": "number",
                    "description": "0.0-1.0 confidence that this is a genuine security concern (not a false positive).",
                },
                "reasoning": {
                    "type": "string",
                    "description": "Your full investigation reasoning -- what you checked, what you found, why you reached this conclusion. Shown to the human analyst.",
                },
                "is_false_positive": {"type": "boolean"},
                "recommended_actions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Concrete next steps, e.g. 'block_ip:45.142.212.61' or 'no action needed'. Don't execute anything -- just recommend.",
                },
            },
            "required": ["summary", "severity_assessment", "confidence", "reasoning", "is_false_positive", "recommended_actions"],
        },
    },
]


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def tool_query_logs(session: Session, alert_window: tuple, **kwargs) -> dict:
    earliest, latest = alert_window
    minutes_before = kwargs.get("minutes_before", 30)
    minutes_after = kwargs.get("minutes_after", 30)
    limit = min(kwargs.get("limit", 50), 200)

    q = session.query(Event).filter(
        Event.timestamp >= earliest - timedelta(minutes=minutes_before),
        Event.timestamp <= latest + timedelta(minutes=minutes_after),
    )
    if kwargs.get("src_ip"):
        q = q.filter(Event.src_ip == kwargs["src_ip"])
    if kwargs.get("host"):
        q = q.filter(Event.host == kwargs["host"])
    if kwargs.get("user"):
        q = q.filter(Event.user == kwargs["user"])
    if kwargs.get("event_type"):
        q = q.filter(Event.event_type == kwargs["event_type"])

    rows = q.order_by(Event.timestamp.asc()).limit(limit).all()
    return {
        "count": len(rows),
        "events": [
            {
                "timestamp": e.timestamp.isoformat(),
                "source_type": e.source_type.value,
                "event_type": e.event_type,
                "host": e.host,
                "src_ip": e.src_ip,
                "dst_ip": e.dst_ip,
                "user": e.user,
                "process_name": e.process_name,
                "message": e.message,
            }
            for e in rows
        ],
    }


# A tiny local seed list so the demo produces meaningful output without
# network access. In production, replace the body of this function with
# real calls to AbuseIPDB / GreyNoise / VirusTotal (see comment below).
_KNOWN_BAD_IP_PREFIXES = ("45.142.", "103.211.")


def tool_enrich_ip(session: Session, ip: str) -> dict:
    result = {"ip": ip}
    try:
        addr = ipaddress.ip_address(ip)
        result["is_private"] = addr.is_private
        result["is_reserved"] = addr.is_reserved
    except ValueError:
        result["is_private"] = None
        result["is_reserved"] = None

    # How many other alerts in this environment involve this IP -- repeat
    # offenders against your own infra are a strong signal on their own.
    prior_event_count = session.query(Event).filter(Event.src_ip == ip).count()
    result["prior_event_count_in_this_db"] = prior_event_count

    # --- Local heuristic threat-intel stand-in ---
    # Replace this block with a real lookup once you have API keys and
    # network egress to threat-intel providers, e.g.:
    #
    #   resp = requests.get(
    #       "https://api.abuseipdb.com/api/v2/check",
    #       params={"ipAddress": ip}, headers={"Key": ABUSEIPDB_KEY},
    #   )
    #   result["abuse_confidence_score"] = resp.json()["data"]["abuseConfidenceScore"]
    #
    if ip.startswith(_KNOWN_BAD_IP_PREFIXES):
        result["threat_intel"] = "heuristic_match: seen in known scanning/brute-force ranges (local seed list, not live intel)"
        result["heuristic_risk"] = "high"
    else:
        result["threat_intel"] = "no local match (live threat-intel lookup not configured)"
        result["heuristic_risk"] = "unknown"

    return result


def tool_get_process_tree(session: Session, host: str, around_timestamp: str | None, minutes_window: int = 10) -> dict:
    from datetime import datetime as _dt

    q = session.query(Event).filter(Event.host == host, Event.event_type == "process_create")
    if around_timestamp:
        center = _dt.fromisoformat(around_timestamp)
        q = q.filter(
            Event.timestamp >= center - timedelta(minutes=minutes_window),
            Event.timestamp <= center + timedelta(minutes=minutes_window),
        )

    rows = q.order_by(Event.timestamp.asc()).all()
    if not rows:
        return {
            "note": "No process_create events found for this host/window. "
                     "Process-tree visibility requires Sysmon or equivalent on the endpoint.",
            "processes": [],
        }

    return {
        "processes": [
            {
                "timestamp": e.timestamp.isoformat(),
                "process": e.process_name,
                "parent": e.parent_process,
                "cmdline": e.process_cmdline,
                "user": e.user,
            }
            for e in rows
        ]
    }


def tool_check_asset_criticality(session: Session, hostname: str) -> dict:
    asset = session.query(Asset).filter_by(hostname=hostname).one_or_none()
    if asset is None:
        return {"hostname": hostname, "found": False, "note": "Unknown asset -- not in inventory, criticality unknown."}
    return {
        "hostname": hostname,
        "found": True,
        "criticality": asset.criticality,
        "asset_type": asset.asset_type,
        "ip_address": asset.ip_address,
        "notes": asset.notes,
    }


def dispatch_tool(session: Session, tool_name: str, tool_input: dict, alert_window: tuple) -> dict:
    if tool_name == "query_logs":
        return tool_query_logs(session, alert_window, **tool_input)
    if tool_name == "enrich_ip":
        return tool_enrich_ip(session, tool_input["ip"])
    if tool_name == "get_process_tree":
        return tool_get_process_tree(
            session,
            tool_input["host"],
            tool_input.get("around_timestamp"),
            tool_input.get("minutes_window", 10),
        )
    if tool_name == "check_asset_criticality":
        return tool_check_asset_criticality(session, tool_input["hostname"])
    return {"error": f"Unknown tool: {tool_name}"}
