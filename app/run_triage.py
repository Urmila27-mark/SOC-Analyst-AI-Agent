"""
Triage every NEW alert in the DB using the agent.

Usage:
    export ANTHROPIC_API_KEY=sk-...
    python -m app.run_triage [--db sqlite:///soc_agent.db] [--model claude-sonnet-5]

    # Or, for a zero-cost demo using rule-based logic instead of a live
    # LLM call (still runs real investigation tools against your data):
    python -m app.run_triage --mock
"""

from __future__ import annotations

import argparse
import os
import sys

from .agent import triage_alert
from .db import session_scope, setup
from .mock_agent import mock_triage_alert
from .models import Alert, AlertStatus


def main():
    ap = argparse.ArgumentParser(description="Triage pending alerts with the agent")
    ap.add_argument("--db", default="sqlite:///soc_agent.db")
    ap.add_argument("--model", default=os.environ.get("SOC_AGENT_MODEL", "claude-sonnet-5"))
    ap.add_argument(
        "--mock",
        action="store_true",
        help="Use rule-based triage instead of a live Claude API call. No API key or cost required.",
    )
    args = ap.parse_args()

    if not args.mock and not os.environ.get("ANTHROPIC_API_KEY"):
        print("ANTHROPIC_API_KEY is not set. Export it before running triage, or pass --mock for a free demo run.", file=sys.stderr)
        sys.exit(1)

    setup(args.db)

    with session_scope() as session:
        pending = session.query(Alert).filter(Alert.status == AlertStatus.NEW).all()
        if not pending:
            print("No NEW alerts to triage.")
            return

        mode_label = "MOCK (rule-based, no API call)" if args.mock else f"LIVE ({args.model})"
        print(f"Triage mode: {mode_label}")

        for alert in pending:
            print(f"\n=== Triaging alert #{alert.id}: {alert.title} ===")
            try:
                if args.mock:
                    result = mock_triage_alert(session, alert)
                else:
                    result = triage_alert(session, alert, model=args.model)
            except Exception as e:
                print(f"  FAILED: {e}")
                continue

            print(f"  Severity:   {result['severity_assessment']}")
            print(f"  Confidence: {result['confidence']}")
            print(f"  FP?:        {result['is_false_positive']}")
            print(f"  Summary:    {result['summary']}")
            print(f"  Recommended actions: {result['recommended_actions']}")


if __name__ == "__main__":
    main()

