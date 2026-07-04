"""
Verifies the agent's tool-use loop mechanics (message construction, tool
dispatch, final write-back to the Alert row) using a mocked Anthropic
client -- no API key or network needed. This does NOT test triage
*quality* (that needs a real model) -- just that the plumbing is correct.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, "..")

from app import agent
from app.db import session_scope, setup
from app.models import Alert, AlertStatus, Event, SourceType, Severity


def _block(type_, **kwargs):
    return SimpleNamespace(type=type_, **kwargs)


def make_fake_client():
    """Simulates: enrich_ip -> check_asset_criticality -> submit_triage."""
    call_count = {"n": 0}

    def fake_create(**kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return SimpleNamespace(content=[
                _block("tool_use", id="t1", name="enrich_ip", input={"ip": "45.142.212.61"})
            ])
        elif call_count["n"] == 2:
            return SimpleNamespace(content=[
                _block("tool_use", id="t2", name="check_asset_criticality", input={"hostname": "homelab"})
            ])
        else:
            return SimpleNamespace(content=[
                _block("tool_use", id="t3", name="submit_triage", input={
                    "summary": "Brute force from known-bad IP against low-criticality host.",
                    "severity_assessment": "high",
                    "confidence": 0.85,
                    "reasoning": "8 failed logins from 45.142.212.61 in under 30s, IP matches heuristic bad range.",
                    "is_false_positive": False,
                    "recommended_actions": ["block_ip:45.142.212.61"],
                })
            ])

    client = MagicMock()
    client.messages.create.side_effect = fake_create
    return client


def main():
    setup("sqlite:///:memory:")
    with session_scope() as session:
        ev = Event(
            timestamp=__import__("datetime").datetime.utcnow(),
            source_type=SourceType.AUTH_LOG,
            host="homelab",
            event_type="auth_failure",
            src_ip="45.142.212.61",
            message="Failed password for invalid user admin",
        )
        session.add(ev)
        session.flush()

        alert = Alert(
            rule_name="ssh-brute-force-001",
            rule_source="sigma",
            severity=Severity.HIGH,
            status=AlertStatus.NEW,
            title="SSH Brute Force (src_ip=45.142.212.61, count=8)",
            description="test",
        )
        session.add(alert)
        session.flush()

        from app.models import AlertEvent
        session.add(AlertEvent(alert_id=alert.id, event_id=ev.id))
        session.flush()
        session.refresh(alert)

        with patch("anthropic.Anthropic", return_value=make_fake_client()):
            result = agent.triage_alert(session, alert)

        assert alert.agent_summary == result["summary"]
        assert alert.agent_confidence == 0.85
        assert alert.status == AlertStatus.TRIAGED
        assert alert.severity == Severity.HIGH
        print("PASS: agent loop plumbing works correctly.")
        print(f"  final status:   {alert.status}")
        print(f"  final severity: {alert.severity}")
        print(f"  summary:        {alert.agent_summary}")


if __name__ == "__main__":
    main()
