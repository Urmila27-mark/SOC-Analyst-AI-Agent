"""
Detection engine.

Rules live as YAML files in sigma_rules/. Two rule shapes are supported:

  1. THRESHOLD rules (the common case):
       detection:
         event_type: auth_failure
         group_by: src_ip
         window_minutes: 5
         threshold: 5
     -> fires when N-or-more matching events sharing the same value of
        `group_by` occur within `window_minutes`.

  2. SEQUENCE rules (cross-event-type correlation):
       detection:
         type: sequence
         group_by: src_ip
         window_minutes: 10
         first:  {event_type: auth_failure, min_count: 3}
         then:   {event_type: auth_success}
     -> fires when `first` happens min_count+ times for a group_by value,
        AND `then` happens for the SAME value afterward, within the window.

This isn't a full Sigma implementation (no field-level EQL-style logic
yet) but the YAML shape is deliberately close to Sigma so it's easy to
extend or eventually swap in pySigma if you want real Sigma rule feeds.

Dedup: we don't want to re-alert on the same brute-force burst every
time detection runs. Before creating an Alert we check whether an open
Alert already exists for the same rule_id + group value within the
rule's window; if so we just attach the new supporting events to it
instead of creating a duplicate.
"""

from __future__ import annotations

import glob
import os
from datetime import timedelta
from typing import Optional

import yaml
from sqlalchemy import func
from sqlalchemy.orm import Session

from .models import Alert, AlertEvent, AlertStatus, Event, Severity

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "sigma_rules")


def load_rules(rules_dir: str = RULES_DIR) -> list[dict]:
    rules = []
    for path in sorted(glob.glob(os.path.join(rules_dir, "*.yml"))):
        with open(path) as f:
            rule = yaml.safe_load(f)
            rule["_path"] = path
            rules.append(rule)
    return rules


def _group_field_column(field: str):
    """Map a group_by field name in YAML to the actual Event column."""
    mapping = {
        "src_ip": Event.src_ip,
        "dst_ip": Event.dst_ip,
        "user": Event.user,
        "host": Event.host,
    }
    if field not in mapping:
        raise ValueError(f"Unsupported group_by field: {field}")
    return mapping[field]


def _existing_open_alert(session: Session, rule_id: str, group_value: str, window_start) -> Optional[Alert]:
    return (
        session.query(Alert)
        .filter(
            Alert.rule_name == rule_id,
            Alert.status.in_([AlertStatus.NEW, AlertStatus.TRIAGED, AlertStatus.ESCALATED]),
            Alert.created_at >= window_start,
            Alert.title.like(f"%{group_value}%"),
        )
        .order_by(Alert.created_at.desc())
        .first()
    )


def _attach_events(session: Session, alert: Alert, events: list[Event]) -> None:
    existing_event_ids = {link.event_id for link in alert.event_links}
    for ev in events:
        if ev.id not in existing_event_ids:
            session.add(AlertEvent(alert_id=alert.id, event_id=ev.id))


def _run_threshold_rule(session: Session, rule: dict, now) -> list[Alert]:
    det = rule["detection"]
    window = timedelta(minutes=det["window_minutes"])
    window_start = now - window
    group_col = _group_field_column(det["group_by"])

    q = (
        session.query(group_col, func.count(Event.id).label("cnt"))
        .filter(
            Event.event_type == det["event_type"],
            Event.timestamp >= window_start,
            group_col.isnot(None),
        )
        .group_by(group_col)
        .having(func.count(Event.id) >= det["threshold"])
    )

    created = []
    for group_value, cnt in q.all():
        matching_events = (
            session.query(Event)
            .filter(
                Event.event_type == det["event_type"],
                Event.timestamp >= window_start,
                group_col == group_value,
            )
            .all()
        )

        existing = _existing_open_alert(session, rule["id"], group_value, window_start)
        if existing:
            _attach_events(session, existing, matching_events)
            continue

        alert = Alert(
            rule_name=rule["id"],
            rule_source="sigma",
            severity=Severity(rule.get("severity", "medium")),
            status=AlertStatus.NEW,
            title=f"{rule['title']} ({det['group_by']}={group_value}, count={cnt})",
            description=rule.get("description", "").strip(),
        )
        session.add(alert)
        session.flush()
        _attach_events(session, alert, matching_events)
        created.append(alert)

    return created


def _run_sequence_rule(session: Session, rule: dict, now) -> list[Alert]:
    det = rule["detection"]
    window = timedelta(minutes=det["window_minutes"])
    window_start = now - window
    group_col = _group_field_column(det["group_by"])
    first_spec = det["first"]
    then_spec = det["then"]

    # Find groups with enough "first" events in the window
    first_q = (
        session.query(group_col, func.count(Event.id).label("cnt"))
        .filter(
            Event.event_type == first_spec["event_type"],
            Event.timestamp >= window_start,
            group_col.isnot(None),
        )
        .group_by(group_col)
        .having(func.count(Event.id) >= first_spec.get("min_count", 1))
    )

    created = []
    for group_value, first_cnt in first_q.all():
        # earliest matching "first" event, to anchor the "then must come after" check
        earliest_first = (
            session.query(Event)
            .filter(
                Event.event_type == first_spec["event_type"],
                Event.timestamp >= window_start,
                group_col == group_value,
            )
            .order_by(Event.timestamp.asc())
            .first()
        )

        then_events = (
            session.query(Event)
            .filter(
                Event.event_type == then_spec["event_type"],
                Event.timestamp >= earliest_first.timestamp,
                Event.timestamp >= window_start,
                group_col == group_value,
            )
            .all()
        )

        if not then_events:
            continue

        first_events = (
            session.query(Event)
            .filter(
                Event.event_type == first_spec["event_type"],
                Event.timestamp >= window_start,
                group_col == group_value,
            )
            .all()
        )
        all_events = first_events + then_events

        existing = _existing_open_alert(session, rule["id"], group_value, window_start)
        if existing:
            _attach_events(session, existing, all_events)
            continue

        alert = Alert(
            rule_name=rule["id"],
            rule_source="sigma",
            severity=Severity(rule.get("severity", "medium")),
            status=AlertStatus.NEW,
            title=f"{rule['title']} ({det['group_by']}={group_value})",
            description=rule.get("description", "").strip(),
        )
        session.add(alert)
        session.flush()
        _attach_events(session, alert, all_events)
        created.append(alert)

    return created


def run_detections(session: Session, now=None, rules_dir: str = RULES_DIR) -> list[Alert]:
    """Load all rules and evaluate them against current Event data. Returns newly created Alerts."""
    from datetime import datetime as _dt

    now = now or _dt.utcnow()
    all_created: list[Alert] = []

    for rule in load_rules(rules_dir):
        det = rule.get("detection", {})
        if det.get("type") == "sequence":
            all_created.extend(_run_sequence_rule(session, rule, now))
        else:
            all_created.extend(_run_threshold_rule(session, rule, now))

    return all_created
