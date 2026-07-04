# SOC Agent

An AI-powered SOC (Security Operations Center) analyst pipeline: ingest logs from
multiple sources → detect suspicious patterns with Sigma-style rules → triage
alerts using an LLM agent that actually investigates before concluding → gate
any response actions behind a human-approval tier for anything risky → review
everything in a dashboard.

Built to work either as a real home-network monitoring tool or as a portfolio/
CTF project you can demo without spending anything.

---

## Architecture

```
Log files (auth.log, Suricata EVE JSON, syslog/router, Windows Event JSON)
        │
        ▼
  normalizer.py   -- parses each source into one common Event schema
        │
        ▼
  ingest.py        -- writes normalized Events into SQLite
        │
        ▼
  detection.py      -- Sigma-style YAML rules run against Events, produce Alerts
        │                (threshold rules: "5+ failures from one IP in 5 min"
        │                 sequence rules: "failures THEN success from same IP")
        ▼
  agent.py / mock_agent.py
        -- investigates each Alert using read-only tools (query_logs, enrich_ip,
           get_process_tree, check_asset_criticality), then writes back a
           structured verdict: summary, severity, confidence, reasoning,
           recommended_actions
        │
        ▼
  actions.py        -- turns recommended_actions into Action rows
                        AUTO tier   (block_ip, rate_limit_ip, monitor_closely)
                                    → executed immediately (dry-run by default)
                        CONFIRM tier (isolate_host, disable_user, kill_process,
                                     reset_credentials)
                                    → held as PROPOSED until a human approves
        │
        ▼
  dashboard.py       -- Streamlit UI: alert feed, agent reasoning, pending
                         approvals with Approve/Reject buttons, action history
```

Everything is stored in one SQLite file (`soc_agent.db`), created automatically
the first time you run anything.

### Two triage modes

| Mode | Command | Cost | What it does |
|---|---|---|---|
| **Mock** | `python -m app.run_triage --mock` | Free | Runs the *real* investigation tools (real IP checks, real asset lookups, real event data) against your DB, but a rule-based decision layer stands in for the LLM. Genuinely investigates your data — just doesn't reason like Claude. |
| **Live** | `python -m app.run_triage` | ~cents per run | Claude actually investigates each alert with tool calls and writes real reasoning. Requires `ANTHROPIC_API_KEY`. |

Use mock mode for iterating on the pipeline, demos, and screenshots. Switch to
live mode once — e.g. for a demo video or hackathon submission — to show real
agent reasoning.

---

## Project layout

```
soc-agent/
├── app/
│   ├── models.py          # SQLAlchemy schema: Asset, Event, Alert, AlertEvent, Action
│   ├── normalizer.py      # Parsers: auth_log, suricata, router/syslog, windows_event
│   ├── db.py               # Session management
│   ├── ingest.py           # CLI: ingest a log file into the DB
│   ├── detection.py        # Sigma-style rule engine (threshold + sequence rules)
│   ├── run_detections.py   # CLI: run all detection rules
│   ├── tools.py            # Agent's read-only investigation tools
│   ├── agent.py            # Live triage agent (Claude API tool-use loop)
│   ├── mock_agent.py       # Free rule-based triage (no API key needed)
│   ├── run_triage.py       # CLI: triage all NEW alerts (--mock or live)
│   ├── actions.py          # AUTO/CONFIRM tier response layer + DryRunExecutor
│   ├── run_response.py     # CLI: process actions for all TRIAGED alerts
│   └── dashboard.py        # Streamlit dashboard
├── sigma_rules/             # YAML detection rules
│   ├── ssh_brute_force.yml
│   ├── suricata_passthrough.yml
│   └── auth_success_after_failures.yml
├── sample_logs/             # Generated test data
│   ├── auth.log
│   └── eve.json
├── tests/                   # Plumbing tests (mocked, no API key needed)
│   ├── test_agent_mock.py
│   └── test_actions.py
├── generate_sample_logs.py  # Regenerates sample logs anchored to "now"
└── requirements.txt
```

---

## Setup

### 1. Extract and create a virtual environment

**Windows (Command Prompt — recommended over PowerShell to avoid script-execution restrictions):**
```cmd
tar -xzf soc-agent.tar.gz
cd soc-agent
python -m venv venv
venv\Scripts\activate.bat
pip install -r requirements.txt
```

**Windows (PowerShell alternative):**
```powershell
tar -xzf soc-agent.tar.gz
cd soc-agent
python -m venv venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
venv\Scripts\activate
pip install -r requirements.txt
```

**Mac/Linux:**
```bash
tar -xzf soc-agent.tar.gz
cd soc-agent
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

If `python` isn't recognized on Windows, try `py` instead in every command.

### 2. (Optional, only for live triage) Set your Anthropic API key

Get a key from [console.anthropic.com](https://console.anthropic.com) → Settings → API Keys.
Check **Settings → Plans & Billing** first — new accounts often have free trial
credit, which is more than enough for testing (a few alerts costs cents).

**Windows (cmd):**
```cmd
set ANTHROPIC_API_KEY=sk-ant-your-key-here
```

**Windows (PowerShell):**
```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-your-key-here"
```

**Mac/Linux:**
```bash
export ANTHROPIC_API_KEY="sk-ant-your-key-here"
```

This only lasts for the current terminal session — re-run it each time you open
a new one. Skip this step entirely if you're only using `--mock` mode.

---

## Running the pipeline

Run these in order, every time you want a fresh demo run:

```bash
# 1. Generate sample logs anchored to right now
#    (detection windows are 1-15 min, so stale timestamps won't trigger alerts —
#    always regenerate before a fresh test pass)
python generate_sample_logs.py

# 2. Ingest both sample sources into the DB
python -m app.ingest --source auth_log --path sample_logs/auth.log
python -m app.ingest --source suricata --path sample_logs/eve.json

# 3. Run detection rules against what's now in the DB
python -m app.run_detections

# 4. Triage the resulting alerts
python -m app.run_triage --mock      # free, rule-based
# --- or, for real LLM reasoning ---
python -m app.run_triage             # requires ANTHROPIC_API_KEY

# 5. Turn recommendations into actions (AUTO tier executes as dry-run,
#    CONFIRM tier waits for approval in the dashboard)
python -m app.run_response
```

Expected output after step 3: 4 alerts — one CRITICAL (credential-stuffing
success), one HIGH (SSH brute force), two MEDIUM (Suricata IDS matches).

### 6. Launch the dashboard

```bash
streamlit run app/dashboard.py
```

Opens automatically at `http://localhost:8501`. Three tabs:
- **Alerts** — full feed with severity, agent summary, confidence, expandable
  reasoning trace, and supporting event tables
- **Pending Actions** — CONFIRM-tier actions awaiting your approval (Approve/
  Reject buttons), plus full action history
- **Assets** — your asset inventory (criticality ratings the agent uses to
  weigh alerts)

### Starting over

Delete the database and offset tracker before a clean re-run:
```bash
rm soc_agent.db .ingest_offsets.json      # Mac/Linux
del soc_agent.db .ingest_offsets.json     # Windows
```

---

## Using your own data

Point `ingest.py` at real log files instead of the sample ones:

```bash
python -m app.ingest --source auth_log --path /var/log/auth.log
python -m app.ingest --source suricata --path /var/log/suricata/eve.json
python -m app.ingest --source router --path /path/to/router-syslog.log
python -m app.ingest --source windows_event --path exported_events.json
```

Windows Event Logs need to be exported to JSON first (e.g. via
`Get-WinEvent | ConvertTo-Json`) since `pywin32` only works on an actual Windows
host — this container/pipeline is source-agnostic and just needs that JSON shape
(see `normalizer.py`'s `parse_windows_event_json` docstring for the expected fields).

To add a new asset to the inventory with a real criticality rating (so the
agent knows a hit against your NAS matters more than a throwaway VM), insert
directly via Python:

```python
from app.db import setup, session_scope
from app.models import Asset

setup()
with session_scope() as s:
    s.add(Asset(hostname="my-nas", ip_address="192.168.1.50", criticality=5, asset_type="nas"))
```

---

## Safety design notes

- **Nothing executes for real by default.** `DryRunExecutor` only logs what it
  *would* do. To wire up real enforcement (iptables, a router API, EDR), write
  a new `ActionExecutor` subclass in `actions.py` — the tier-gating logic
  doesn't change. There's a commented `IPTablesExecutor` example in that file.
- **Two-tier action gating**: reversible/low-blast-radius actions (temporary IP
  blocks, monitoring flags) execute automatically; anything higher-stakes
  (isolating a host, disabling a user, killing a process) always waits for a
  human click in the dashboard, regardless of the agent's confidence.
- **Triage is read-only.** The agent's investigation tools (`tools.py`) cannot
  change any state — only `actions.py`, gated separately, can.
- **Alert dedup**: re-running detection on an ongoing burst won't spam
  duplicate alerts — it attaches new supporting events to the existing open
  alert instead.

---

## Extending it

- **Real threat intel**: `tool_enrich_ip` in `tools.py` currently uses a tiny
  local heuristic (private-IP check + a seed list) since this environment
  doesn't have network access to AbuseIPDB/GreyNoise/VirusTotal. The real API
  call is sketched in a comment in that function — drop in your key and it's a
  live lookup.
- **Real Sigma rules**: the YAML format in `sigma_rules/` is deliberately
  Sigma-shaped but simplified. If you want to pull from the actual open Sigma
  rule corpus, swapping in `pySigma` as the detection backend is a contained
  change — it wouldn't touch `models.py`, `agent.py`, or the alert/dedup logic.
- **More sources**: add a `parse_<source>()` generator to `normalizer.py`
  following the existing pattern, register it in `SOURCE_PARSERS`, and it's
  usable from `ingest.py` immediately.
