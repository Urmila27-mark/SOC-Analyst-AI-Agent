"""
Verifies: AUTO-tier actions execute immediately (dry-run), CONFIRM-tier
actions stay PROPOSED until approved, rejection works, and re-processing
an already-processed alert doesn't duplicate actions.
"""

from __future__ import annotations

import sys
from datetime import datetime

sys.path.insert(0, "..")

from app.actions import DryRunExecutor, approve_action, process_alert_actions, reject_action
from app.db import session_scope, setup
from app.models import Alert, AlertStatus, ActionStatus, ActionTier, Severity


def main():
    setup("sqlite:///:memory:")
    executor = DryRunExecutor()

    with session_scope() as session:
        alert = Alert(
            rule_name="ssh-brute-force-001",
            rule_source="sigma",
            severity=Severity.HIGH,
            status=AlertStatus.TRIAGED,
            title="SSH Brute Force test",
            description="test",
            agent_recommended_actions=[
                "block_ip:45.142.212.61:30",
                "isolate_host:homelab",
                "no action needed",  # should be ignored, not a real action type
            ],
        )
        session.add(alert)
        session.flush()

        created = process_alert_actions(session, alert, executor)
        assert len(created) == 2, f"expected 2 actions, got {len(created)}"

        block_action = next(a for a in created if a.action_type == "block_ip")
        isolate_action = next(a for a in created if a.action_type == "isolate_host")

        assert block_action.tier == ActionTier.AUTO
        assert block_action.status == ActionStatus.EXECUTED
        assert block_action.duration_minutes == 30
        assert "45.142.212.61" in block_action.result

        assert isolate_action.tier == ActionTier.CONFIRM
        assert isolate_action.status == ActionStatus.PROPOSED
        assert isolate_action.result is None
        print("PASS: AUTO action executed immediately, CONFIRM action left pending.")

        # Re-processing the same alert should not duplicate actions
        created_again = process_alert_actions(session, alert, executor)
        assert created_again == []
        print("PASS: re-processing an alert does not duplicate actions.")

        # Approve the pending isolate_host action
        approve_action(session, isolate_action, executor)
        assert isolate_action.status == ActionStatus.EXECUTED
        assert "homelab" in isolate_action.result
        print("PASS: approving a CONFIRM action executes it.")

    with session_scope() as session:
        alert2 = Alert(
            rule_name="test-002", rule_source="sigma", severity=Severity.MEDIUM,
            status=AlertStatus.TRIAGED, title="test2", description="",
            agent_recommended_actions=["disable_user:baduser"],
        )
        session.add(alert2)
        session.flush()
        created2 = process_alert_actions(session, alert2, executor)
        reject_action(session, created2[0])
        assert created2[0].status == ActionStatus.REJECTED
        print("PASS: rejecting a CONFIRM action marks it REJECTED without executing.")


if __name__ == "__main__":
    main()
