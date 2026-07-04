"""
SOC Agent Dashboard.

Run with:
    streamlit run app/dashboard.py

Shows:
  - Live alert feed with severity/status/confidence
  - Agent's reasoning trace per alert (expandable)
  - Pending CONFIRM-tier actions, with Approve/Reject buttons
  - Executed action history
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st

from app.actions import DryRunExecutor, approve_action, reject_action
from app.db import session_scope, setup
from app.models import Action, ActionStatus, ActionTier, Alert, AlertStatus, Severity

st.set_page_config(page_title="SOC Agent Dashboard", layout="wide")

DB_PATH = os.environ.get("SOC_AGENT_DB", "sqlite:///soc_agent.db")
setup(DB_PATH)
executor = DryRunExecutor()

SEVERITY_COLOR = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

STATUS_LABEL = {
    AlertStatus.NEW: "🆕 New (untriaged)",
    AlertStatus.TRIAGED: "✅ Triaged",
    AlertStatus.ESCALATED: "⬆️ Escalated",
    AlertStatus.ACTION_PROPOSED: "⏳ Action proposed",
    AlertStatus.ACTION_PENDING_APPROVAL: "⏳ Pending approval",
    AlertStatus.RESOLVED: "✔️ Resolved",
    AlertStatus.FALSE_POSITIVE: "🚫 False positive",
}

st.title("🛡️ SOC Agent Dashboard")

tab_alerts, tab_actions, tab_assets = st.tabs(["Alerts", "Pending Actions", "Assets"])

# ---------------------------------------------------------------------------
# Alerts tab
# ---------------------------------------------------------------------------
with tab_alerts:
    with session_scope() as session:
        alerts = session.query(Alert).order_by(Alert.created_at.desc()).all()

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total alerts", len(alerts))
        col2.metric("Untriaged", sum(1 for a in alerts if a.status == AlertStatus.NEW))
        col3.metric("Critical/High", sum(1 for a in alerts if a.severity in (Severity.CRITICAL, Severity.HIGH)))
        col4.metric("False positives", sum(1 for a in alerts if a.status == AlertStatus.FALSE_POSITIVE))

        st.divider()

        if not alerts:
            st.info("No alerts yet. Run `python -m app.run_detections` after ingesting some logs.")

        for alert in alerts:
            icon = SEVERITY_COLOR.get(alert.severity, "⚪")
            header = f"{icon} **{alert.severity.value.upper()}** — {alert.title}"
            with st.expander(header, expanded=(alert.status == AlertStatus.NEW)):
                st.caption(f"Rule: `{alert.rule_name}` · Created: {alert.created_at} · Status: {STATUS_LABEL.get(alert.status, alert.status.value)}")
                st.write(alert.description)

                if alert.agent_summary:
                    st.markdown("**Agent summary:**")
                    st.write(alert.agent_summary)
                    if alert.agent_confidence is not None:
                        st.progress(alert.agent_confidence, text=f"Confidence: {alert.agent_confidence:.0%}")

                    with st.popover("View full agent reasoning"):
                        st.write(alert.agent_reasoning)

                    if alert.agent_recommended_actions:
                        st.markdown("**Recommended actions:**")
                        for rec in alert.agent_recommended_actions:
                            st.code(rec, language=None)
                else:
                    st.warning("Not yet triaged. Run `python -m app.run_triage`.")

                events = [link.event for link in alert.event_links]
                events.sort(key=lambda e: e.timestamp)
                st.markdown(f"**Supporting events ({len(events)}):**")
                st.dataframe(
                    [
                        {
                            "timestamp": e.timestamp,
                            "source": e.source_type.value,
                            "type": e.event_type,
                            "host": e.host,
                            "src_ip": e.src_ip,
                            "user": e.user,
                            "message": e.message,
                        }
                        for e in events
                    ],
                    use_container_width=True,
                    hide_index=True,
                )

# ---------------------------------------------------------------------------
# Pending Actions tab
# ---------------------------------------------------------------------------
with tab_actions:
    with session_scope() as session:
        pending = (
            session.query(Action)
            .filter(Action.tier == ActionTier.CONFIRM, Action.status == ActionStatus.PROPOSED)
            .order_by(Action.created_at.desc())
            .all()
        )

        st.subheader(f"⏳ Awaiting your approval ({len(pending)})")
        if not pending:
            st.success("Nothing pending. All CONFIRM-tier actions are resolved.")

        for action in pending:
            with st.container(border=True):
                c1, c2 = st.columns([4, 1])
                with c1:
                    st.markdown(f"**{action.action_type}** → `{action.target}`")
                    st.caption(action.justification)
                    if action.alert:
                        st.caption(f"From alert: {action.alert.title}")
                with c2:
                    approve_col, reject_col = st.columns(2)
                    if approve_col.button("✅ Approve", key=f"approve_{action.id}"):
                        approve_action(session, action, executor)
                        st.rerun()
                    if reject_col.button("❌ Reject", key=f"reject_{action.id}"):
                        reject_action(session, action)
                        st.rerun()

        st.divider()
        st.subheader("Action history")
        with session_scope() as session2:
            history = session2.query(Action).order_by(Action.created_at.desc()).limit(50).all()
            st.dataframe(
                [
                    {
                        "created": a.created_at,
                        "type": a.action_type,
                        "target": a.target,
                        "tier": a.tier.value,
                        "status": a.status.value,
                        "result": a.result,
                    }
                    for a in history
                ],
                use_container_width=True,
                hide_index=True,
            )

# ---------------------------------------------------------------------------
# Assets tab
# ---------------------------------------------------------------------------
with tab_assets:
    from app.models import Asset

    with session_scope() as session:
        assets = session.query(Asset).all()
        st.subheader("Known assets")
        st.caption("Criticality is used by the agent to weigh how seriously to treat an alert against each host. Edit directly in the DB or extend this tab with an editor.")
        st.dataframe(
            [
                {
                    "hostname": a.hostname,
                    "ip_address": a.ip_address,
                    "criticality": a.criticality,
                    "asset_type": a.asset_type,
                    "notes": a.notes,
                }
                for a in assets
            ],
            use_container_width=True,
            hide_index=True,
        )
