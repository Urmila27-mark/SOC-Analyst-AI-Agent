"""
Mock triage agent -- no API key, no cost, no network call.

This is NOT just canned text. It calls the exact same read-only tools
(tool_enrich_ip, tool_check_asset_criticality) that the real agent uses
in agent.py -- so it's doing genuine investigation against your actual
database. The only thing replaced is the "brain": instead of Claude
reasoning over the tool results, a small set of explicit rules decides
severity/confidence/recommended actions.

Use this for:
  - Demos, screenshots, portfolio walkthroughs, CTF presentations
  - Proving the pipeline end-to-end without spending API credits
  - A sanity check that your detection rules produce sensible input
    before you spend real money triaging with the live model

Swap to real triage (agent.py's triage_alert) any time -- same Alert
schema, same downstream response layer, same dashboard. Nothing else
in the pipeline needs to know which one produced the result.
"""

from __future__ import annotations

from collections import Counter

from sqlalchemy.orm import Session

from .models import Alert, AlertStatus, Severity
from .tools import tool_check_asset_criticality, tool_enrich_ip


def _most_common_src_ip(events) -> str | None:
    ips = [e.src_ip for e in events if e.src_ip]
    if not ips:
        return None
    return Counter(ips).most_common(1)[0][0]


def mock_triage_alert(session: Session, alert: Alert) -> dict:
    events = [link.event for link in alert.event_links]
    if not events:
        raise ValueError(f"Alert {alert.id} has no linked events -- nothing to investigate.")

    events.sort(key=lambda e: e.timestamp)
    hosts = {e.host for e in events if e.host}
    primary_host = next(iter(hosts), None)
    primary_ip = _most_common_src_ip(events)

    investigation_notes = []

    ip_intel = None
    if primary_ip:
        ip_intel = tool_enrich_ip(session, primary_ip)
        investigation_notes.append(
            f"enrich_ip({primary_ip}) -> heuristic_risk={ip_intel['heuristic_risk']}, "
            f"prior_event_count_in_this_db={ip_intel['prior_event_count_in_this_db']}, "
            f"is_private={ip_intel['is_private']}"
        )

    asset_info = None
    if primary_host:
        asset_info = tool_check_asset_criticality(session, primary_host)
        crit = asset_info.get("criticality", "unknown") if asset_info.get("found") else "unknown (not in inventory)"
        investigation_notes.append(f"check_asset_criticality({primary_host}) -> criticality={crit}")

    # --- Rule-based decision logic, keyed off which detection rule fired ---
    rule = alert.rule_name
    high_risk_ip = bool(ip_intel and ip_intel.get("heuristic_risk") == "high")
    event_count = len(events)

    if rule == "auth-success-after-failures-001":
        severity = "critical"
        confidence = 0.9 if high_risk_ip else 0.75
        is_fp = False
        summary = (
            f"A successful authentication from {primary_ip} followed a burst of failed attempts "
            f"from the same source against {primary_host}. This pattern is consistent with a "
            f"brute-force or credential-stuffing attempt that succeeded."
        )
        recommended = [f"isolate_host:{primary_host}", "disable_user:" + (events[-1].user or "unknown")]

    elif rule == "ssh-brute-force-001":
        if high_risk_ip:
            severity, confidence = "high", 0.85
        else:
            severity, confidence = "medium", 0.6
        is_fp = False
        summary = (
            f"{event_count} failed SSH authentication attempts from {primary_ip} against "
            f"{primary_host} in a short window -- consistent with automated password guessing. "
            f"No successful login was observed from this source in the same window."
        )
        recommended = [f"block_ip:{primary_ip}:60"]

    elif rule == "suricata-alert-passthrough-001":
        if high_risk_ip:
            severity, confidence = "medium", 0.7
            recommended = [f"monitor_closely:{primary_ip}"]
        else:
            severity, confidence = "low", 0.4
            recommended = [f"monitor_closely:{primary_ip}"]
        is_fp = False
        summary = (
            f"Network IDS signature matched traffic involving {primary_ip}. "
            f"No corroborating host-level activity found in this pass -- treating as "
            f"noteworthy but not yet confirmed malicious."
        )

    else:
        severity, confidence = "low", 0.3
        is_fp = True
        summary = f"Unrecognized rule '{rule}' -- no scripted logic for this alert type in mock mode."
        recommended = ["no action needed"]

    reasoning = (
        f"[MOCK AGENT -- rule-based, not a live LLM call]\n"
        f"Investigation steps taken:\n  " + "\n  ".join(investigation_notes) + "\n\n"
        f"Decision: rule={rule}, high_risk_ip={high_risk_ip}, event_count={event_count} "
        f"-> severity={severity}, confidence={confidence}"
    )

    result = {
        "summary": summary,
        "severity_assessment": severity,
        "confidence": confidence,
        "reasoning": reasoning,
        "is_false_positive": is_fp,
        "recommended_actions": recommended,
    }

    alert.agent_summary = result["summary"]
    alert.agent_confidence = result["confidence"]
    alert.agent_reasoning = result["reasoning"]
    alert.agent_recommended_actions = result["recommended_actions"]
    alert.severity = Severity(result["severity_assessment"])
    alert.status = AlertStatus.FALSE_POSITIVE if is_fp else AlertStatus.TRIAGED

    return result
