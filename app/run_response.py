"""
Process recommended actions for all TRIAGED alerts: create Action rows,
execute AUTO-tier ones immediately (dry-run by default), leave CONFIRM-tier
ones pending for approval via the dashboard.

Usage:
    python -m app.run_response [--db sqlite:///soc_agent.db]
"""

from __future__ import annotations

import argparse
import logging

from .actions import DryRunExecutor, process_alert_actions
from .db import session_scope, setup
from .models import Alert, AlertStatus

logging.basicConfig(level=logging.INFO, format="%(message)s")


def main():
    ap = argparse.ArgumentParser(description="Process actions for triaged alerts")
    ap.add_argument("--db", default="sqlite:///soc_agent.db")
    args = ap.parse_args()

    setup(args.db)
    executor = DryRunExecutor()

    with session_scope() as session:
        triaged = session.query(Alert).filter(Alert.status == AlertStatus.TRIAGED).all()
        if not triaged:
            print("No triaged alerts pending action processing.")
            return

        for alert in triaged:
            created = process_alert_actions(session, alert, executor)
            if not created:
                continue
            print(f"\n=== Alert #{alert.id}: {alert.title} ===")
            for action in created:
                print(f"  [{action.tier.value:7}] {action.action_type} -> {action.target} : {action.status.value}")
                if action.result:
                    print(f"           {action.result}")


if __name__ == "__main__":
    main()
