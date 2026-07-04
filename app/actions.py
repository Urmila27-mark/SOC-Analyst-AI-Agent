"""
Response layer.

Turns an alert's agent_recommended_actions (strings like "block_ip:1.2.3.4")
into Action rows, and executes them according to tier:

  AUTO    -- low blast-radius, reversible, timeboxed. Executed immediately.
             e.g. a temporary IP block: worst case if wrong is a short,
             self-expiring false-positive block.
  CONFIRM -- high blast-radius or hard-to-reverse. Created as PROPOSED and
             left for a human to approve/reject via the dashboard. Never
             auto-executed, no matter how confident the agent is.

The actual "doing" is behind an ActionExecutor interface. The default
DryRunExecutor only logs what it *would* do -- this ships safe by default.
To wire up real enforcement (e.g. iptables on your gateway, a router API,
EDR isolation), implement a new Executor subclass; the tier gating and
approval logic don't change.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from .models import Action, ActionStatus, ActionTier, Alert

logger = logging.getLogger("soc_agent.actions")

# Which tier each action type belongs to. This is the single place that
# decides what's allowed to happen automatically -- keep it conservative.
ACTION_TIERS: dict[str, ActionTier] = {
    "block_ip": ActionTier.AUTO,
    "rate_limit_ip": ActionTier.AUTO,
    "monitor_closely": ActionTier.AUTO,   # no-op action, just flags for extra logging
    "isolate_host": ActionTier.CONFIRM,
    "disable_user": ActionTier.CONFIRM,
    "kill_process": ActionTier.CONFIRM,
    "reset_credentials": ActionTier.CONFIRM,
}

DEFAULT_BLOCK_DURATION_MINUTES = 60


# ---------------------------------------------------------------------------
# Executors
# ---------------------------------------------------------------------------

class ActionExecutor:
    """Base interface. Every method returns a human-readable result string."""

    def block_ip(self, ip: str, duration_minutes: int) -> str:
        raise NotImplementedError

    def rate_limit_ip(self, ip: str, duration_minutes: int) -> str:
        raise NotImplementedError

    def isolate_host(self, hostname: str) -> str:
        raise NotImplementedError

    def disable_user(self, username: str) -> str:
        raise NotImplementedError

    def kill_process(self, target: str) -> str:
        raise NotImplementedError

    def reset_credentials(self, username: str) -> str:
        raise NotImplementedError

    def monitor_closely(self, target: str) -> str:
        raise NotImplementedError


class DryRunExecutor(ActionExecutor):
    """
    Default, safe-by-default executor. Logs what it would do without
    touching any real system. Use this until you've deliberately wired
    up a real backend (see the commented example below).
    """

    def block_ip(self, ip: str, duration_minutes: int) -> str:
        msg = f"[DRY RUN] Would block {ip} for {duration_minutes} minutes."
        logger.info(msg)
        return msg

    def rate_limit_ip(self, ip: str, duration_minutes: int) -> str:
        msg = f"[DRY RUN] Would rate-limit {ip} for {duration_minutes} minutes."
        logger.info(msg)
        return msg

    def isolate_host(self, hostname: str) -> str:
        msg = f"[DRY RUN] Would isolate host {hostname} from the network."
        logger.info(msg)
        return msg

    def disable_user(self, username: str) -> str:
        msg = f"[DRY RUN] Would disable user account {username}."
        logger.info(msg)
        return msg

    def kill_process(self, target: str) -> str:
        msg = f"[DRY RUN] Would kill process {target}."
        logger.info(msg)
        return msg

    def reset_credentials(self, username: str) -> str:
        msg = f"[DRY RUN] Would force credential reset for {username}."
        logger.info(msg)
        return msg

    def monitor_closely(self, target: str) -> str:
        msg = f"[DRY RUN] Flagged {target} for closer monitoring (no system change)."
        logger.info(msg)
        return msg


# Example of a REAL executor for a Linux gateway using iptables. Not used
# by default -- you'd opt into this explicitly (see run_response.py
# --executor flag) once you've tested DryRunExecutor's output and are
# confident in what it would have done.
#
# class IPTablesExecutor(ActionExecutor):
#     def block_ip(self, ip: str, duration_minutes: int) -> str:
#         import subprocess
#         subprocess.run(["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=True)
#         # you'd also need a scheduled job (at/cron/systemd-timer) to remove
#         # the rule after duration_minutes, to keep this genuinely reversible
#         return f"Blocked {ip} via iptables for {duration_minutes} minutes."


# ---------------------------------------------------------------------------
# Parsing + orchestration
# ---------------------------------------------------------------------------

def parse_action_string(raw: str) -> tuple[str, str, int | None] | None:
    """
    Parses strings like "block_ip:45.142.212.61" or
    "block_ip:45.142.212.61:120" (explicit duration in minutes).
    Returns None for non-actionable strings like "no action needed".
    """
    parts = raw.strip().split(":")
    action_type = parts[0].strip().lower().replace(" ", "_")
    if action_type not in ACTION_TIERS:
        return None
    target = parts[1].strip() if len(parts) > 1 else ""
    duration = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None
    if not target:
        return None
    return action_type, target, duration


def _execute(executor: ActionExecutor, action: Action) -> str:
    duration = action.duration_minutes or DEFAULT_BLOCK_DURATION_MINUTES
    if action.action_type == "block_ip":
        return executor.block_ip(action.target, duration)
    if action.action_type == "rate_limit_ip":
        return executor.rate_limit_ip(action.target, duration)
    if action.action_type == "isolate_host":
        return executor.isolate_host(action.target)
    if action.action_type == "disable_user":
        return executor.disable_user(action.target)
    if action.action_type == "kill_process":
        return executor.kill_process(action.target)
    if action.action_type == "reset_credentials":
        return executor.reset_credentials(action.target)
    if action.action_type == "monitor_closely":
        return executor.monitor_closely(action.target)
    raise ValueError(f"No executor method for action_type={action.action_type}")


def process_alert_actions(session: Session, alert: Alert, executor: ActionExecutor) -> list[Action]:
    """
    Reads alert.agent_recommended_actions, creates an Action row for each
    actionable recommendation, and executes AUTO-tier ones immediately.
    CONFIRM-tier actions are created as PROPOSED and left for a human.
    Idempotent-ish: skips creating duplicates if actions already exist
    for this alert.
    """
    # Query directly rather than relying on alert.actions -- that relationship
    # attribute can be stale within the same session if actions were added
    # via alert_id= rather than through the relationship itself.
    existing = session.query(Action).filter(Action.alert_id == alert.id).count()
    if existing:
        return []  # already processed

    recs = alert.agent_recommended_actions or []
    created: list[Action] = []

    for raw in recs:
        parsed = parse_action_string(raw)
        if parsed is None:
            continue
        action_type, target, duration = parsed
        tier = ACTION_TIERS[action_type]

        action = Action(
            alert_id=alert.id,
            action_type=action_type,
            target=target,
            tier=tier,
            status=ActionStatus.PROPOSED,
            justification=f"Agent recommendation from alert #{alert.id}: {alert.title}",
            duration_minutes=duration,
        )
        session.add(action)
        session.flush()
        created.append(action)

        if tier == ActionTier.AUTO:
            execute_action(session, action, executor)

    return created


def execute_action(session: Session, action: Action, executor: ActionExecutor) -> Action:
    try:
        result = _execute(executor, action)
        action.status = ActionStatus.EXECUTED
        action.result = result
        action.executed_at = datetime.now(timezone.utc)
    except Exception as e:
        action.status = ActionStatus.FAILED
        action.result = f"Execution failed: {e}"
    return action


def approve_action(session: Session, action: Action, executor: ActionExecutor) -> Action:
    """Human approves a CONFIRM-tier action -- now it actually runs."""
    if action.tier != ActionTier.CONFIRM:
        raise ValueError("approve_action is only for CONFIRM-tier actions.")
    action.status = ActionStatus.APPROVED
    return execute_action(session, action, executor)


def reject_action(session: Session, action: Action) -> Action:
    action.status = ActionStatus.REJECTED
    action.result = "Rejected by human analyst."
    return action
