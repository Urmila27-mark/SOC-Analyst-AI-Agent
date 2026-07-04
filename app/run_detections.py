"""
Run all detection rules against current Event data.

Usage:
    python -m app.run_detections [--db sqlite:///soc_agent.db]
"""

from __future__ import annotations

import argparse

from .db import session_scope, setup
from .detection import run_detections


def main():
    ap = argparse.ArgumentParser(description="Run SOC agent detection rules")
    ap.add_argument("--db", default="sqlite:///soc_agent.db")
    args = ap.parse_args()

    setup(args.db)

    with session_scope() as session:
        created = run_detections(session)
        if not created:
            print("No new alerts.")
        for alert in created:
            print(f"[{alert.severity.value.upper():8}] {alert.title}")


if __name__ == "__main__":
    main()
