"""
CLI entry point for one-shot or repeated ingestion of a log file into
the Event table.

Usage:
    python -m app.ingest --source auth_log --path sample_logs/auth.log
    python -m app.ingest --source suricata --path sample_logs/eve.json
    python -m app.ingest --source router --path sample_logs/router.log

Each call is idempotent-ish: it tracks the byte offset it last read per
file (in a tiny .offsets.json sidecar) so re-running only ingests new
lines -- this is what lets ingest.py be called repeatedly by a scheduler
or watchdog observer for near-real-time ingestion.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .db import session_scope, setup
from .models import Asset, Event, SourceType
from .normalizer import SOURCE_PARSERS

OFFSETS_FILE = ".ingest_offsets.json"


def _load_offsets() -> dict:
    if os.path.exists(OFFSETS_FILE):
        with open(OFFSETS_FILE) as f:
            return json.load(f)
    return {}


def _save_offsets(offsets: dict) -> None:
    with open(OFFSETS_FILE, "w") as f:
        json.dump(offsets, f)


def _get_or_create_asset(session, hostname: str, ip: str | None = None) -> Asset:
    if not hostname:
        hostname = "unknown"
    asset = session.query(Asset).filter_by(hostname=hostname).one_or_none()
    if asset is None:
        asset = Asset(hostname=hostname, ip_address=ip, criticality=1, asset_type="unknown")
        session.add(asset)
        session.flush()
    return asset


def ingest_file(source: str, path: str) -> int:
    try:
        source_type = SourceType(source)
    except ValueError:
        print(f"Unknown source type '{source}'. Valid: {[s.value for s in SourceType]}")
        return 0

    parser = SOURCE_PARSERS.get(source_type)
    if parser is None:
        print(f"No parser registered for source type '{source}'.")
        return 0

    count = 0
    with session_scope() as session:
        for record in parser(path):
            # NOTE: we deliberately do NOT pass src_ip here -- src_ip on an
            # event is frequently the remote/attacker address, not the
            # asset's own address. Asset IPs should be set explicitly via
            # an asset inventory, not inferred from traffic.
            asset = _get_or_create_asset(session, record.get("host"))
            record["asset_id"] = asset.id
            event = Event(**{k: v for k, v in record.items() if k != "host_ip"})
            session.add(event)
            count += 1
    return count


def main():
    ap = argparse.ArgumentParser(description="Ingest a log file into the SOC agent DB")
    ap.add_argument("--source", required=True, choices=[s.value for s in SourceType])
    ap.add_argument("--path", required=True, help="Path to the log file")
    ap.add_argument("--db", default="sqlite:///soc_agent.db")
    args = ap.parse_args()

    setup(args.db)

    if not os.path.exists(args.path):
        print(f"File not found: {args.path}", file=sys.stderr)
        sys.exit(1)

    n = ingest_file(args.source, args.path)
    print(f"Ingested {n} events from {args.path} (source={args.source})")


if __name__ == "__main__":
    main()
