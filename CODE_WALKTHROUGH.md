# SOC Agent — Full Code Walkthrough

This explains what every file does, section by section. Read it alongside the
actual code open in another window — it'll make more sense that way than as
pure prose.

---

## `app/models.py` — The database schema

This file defines every table in the database using SQLAlchemy's ORM (Object-
Relational Mapper — lets you write Python classes instead of raw SQL).

```python
class Base(DeclarativeBase):
    pass
```
Every table class inherits from this. It's SQLAlchemy's way of tracking "these
are all my tables."

```python
def utcnow() -> datetime:
    return datetime.now(timezone.utc)
```
A helper so every "created at" timestamp uses UTC consistently, instead of
whatever timezone your machine happens to be in.

```python
class SourceType(str, enum.Enum):
    WINDOWS_EVENT = "windows_event"
    SYSMON = "sysmon"
    AUTH_LOG = "auth_log"
    ...
```
An **enum** — a fixed list of allowed values. This stops you from ever
accidentally writing `"widnows_event"` (typo) into the database; Python would
error immediately instead of silently storing garbage.

```python
class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
```
Same idea — the only severities that can ever exist.

```python
class AlertStatus(str, enum.Enum):
    NEW = "new"
    TRIAGED = "triaged"
    ...
```
Tracks where an alert is in its lifecycle — this is what your dashboard
tabs/filters key off of.

```python
class ActionTier(str, enum.Enum):
    AUTO = "auto"
    CONFIRM = "confirm"
```
The two-tier safety split we designed — low-risk actions vs. actions that need
a human click.

### The `Asset` table
```python
class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True)
    hostname = Column(String(255), unique=True, nullable=False)
    ip_address = Column(String(64))
    criticality = Column(Integer, default=1)
    asset_type = Column(String(64))
    notes = Column(Text)
    created_at = Column(DateTime, default=utcnow)
    events = relationship("Event", back_populates="asset")
```
- `id` — every row's unique number, auto-generated.
- `hostname` — must be unique (`unique=True`) and can't be empty
  (`nullable=False`) — you can't have two assets both named "homelab."
- `criticality` — a 1-5 number the agent uses to weigh how much an alert
  matters (attack on your NAS vs. attack on a throwaway VM).
- `relationship("Event", ...)` — this isn't a real database column. It tells
  SQLAlchemy "when I access `some_asset.events`, go find all Event rows that
  point back to this asset." It's Python-side convenience, not stored data.

### The `Event` table
```python
class Event(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    source_type = Column(Enum(SourceType), nullable=False, index=True)
    host = Column(String(255), index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    event_type = Column(String(128), index=True)
    src_ip = Column(String(64), index=True)
    ...
```
This is the "everything gets normalized into this shape" table.
- `index=True` on several columns — tells the database to build a fast lookup
  structure for that column. Without this, searching "all events from this
  IP" would have to scan every single row one by one; with it, it's near-
  instant even with millions of rows.
- `ForeignKey("assets.id")` — this column must contain either `NULL` or an
  actual `id` that exists in the `assets` table. This is how the database
  enforces "you can't link an event to an asset that doesn't exist."
- `raw = Column(JSON)` — stores the *entire original log line/record*,
  untouched, so you can always drill down to the source even after
  normalization has thrown away some detail.

### The `Alert` table
```python
class Alert(Base):
    ...
    rule_name = Column(String(255), nullable=False)
    severity = Column(Enum(Severity), default=Severity.MEDIUM, index=True)
    status = Column(Enum(AlertStatus), default=AlertStatus.NEW, index=True)
    agent_summary = Column(Text)
    agent_confidence = Column(Float)
    agent_reasoning = Column(Text)
    agent_recommended_actions = Column(JSON)
```
The `agent_*` columns start empty (`NULL`) when a detection rule first creates
an alert. They only get filled in later, when `agent.py` or `mock_agent.py`
runs triage and writes the verdict back.

### The `AlertEvent` table
```python
class AlertEvent(Base):
    __tablename__ = "alert_events"
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False)
    event_id = Column(Integer, ForeignKey("events.id"), nullable=False)
```
This is a **join table** — its only job is connecting Alerts to Events in a
many-to-many way (one alert can have many supporting events; theoretically one
event could support multiple alerts). Without this table, you'd have to cram
a list of event IDs into a single column, which databases handle badly.

### The `Action` table
```python
class Action(Base):
    ...
    action_type = Column(String(64), nullable=False)
    target = Column(String(255), nullable=False)
    tier = Column(Enum(ActionTier), nullable=False)
    status = Column(Enum(ActionStatus), default=ActionStatus.PROPOSED)
    duration_minutes = Column(Integer, nullable=True)
    executed_at = Column(DateTime, nullable=True)
```
Every recommended action becomes one row here. `duration_minutes` is only
used for timeboxed things like IP blocks (nullable because e.g. "isolate
host" has no natural duration).

### The setup functions
```python
def get_engine(db_path: str = "sqlite:///soc_agent.db"):
    return create_engine(db_path, echo=False, future=True)

def init_db(engine):
    Base.metadata.create_all(engine)

def get_session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)
```
- `get_engine` — the "connection" to the database file.
- `init_db` — reads every class defined above and actually creates the
  matching SQL tables if they don't exist yet. This is why you never had to
  write `CREATE TABLE` by hand.
- `get_session_factory` — a "session" is a working transaction — a batch of
  changes you can commit or roll back together. This creates the factory that
  produces new sessions on demand.

---

## `app/normalizer.py` — Turning raw logs into `Event` dicts

The whole point of this file: no matter what log format comes in, it comes
out the other side looking the same.

### The regex patterns
```python
_AUTH_LINE_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[\w.\-/]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
```
This is a **regular expression** — a pattern for matching text. Breaking it
down:
- `(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})` — captures something like
  `"Jul  4 01:14:02"` and names that captured piece `ts` (timestamp), so you
  can grab it later with `match.group("ts")`.
- `(?P<host>\S+)` — captures a run of non-whitespace characters, named `host`.
- `(?P<proc>[\w.\-/]+)(?:\[(?P<pid>\d+)\])?` — captures the process name
  (e.g. `sshd`), and *optionally* a `[1234]` process ID after it — the `?`
  after the group means "this part might not be there at all."
- `(?P<msg>.*)$` — everything else on the line, to the end.

```python
_SSH_FAILED_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
```
This looks for the specific phrase SSH writes on a failed login and pulls out
the username, IP, and port. The `(invalid user )?` part is optional because
SSH phrases it differently depending on whether the username exists at all.

### `parse_auth_log`
```python
def parse_auth_log(path: str, current_year: int | None = None) -> Iterator[dict]:
```
This is a **generator function** — the `Iterator[dict]` return type and the
`yield` statements inside mean it produces results one at a time, lazily,
instead of building a giant list in memory all at once. Good for huge log
files.

```python
    current_year = current_year or datetime.now().year
```
Syslog timestamps don't include a year (`"Jul 4 01:14:02"`, no year!) — this
line fills that gap in using the current year, since that's the only
sensible assumption.

```python
    with open(path, "r", errors="replace") as f:
        for line in f:
```
`errors="replace"` — if the log file has any weird non-text bytes (garbled
encoding), Python replaces them with a placeholder character instead of
crashing the whole ingestion.

```python
            m = _AUTH_LINE_RE.match(line)
            if not m:
                continue
```
If a line doesn't match the expected shape at all, skip it rather than
crashing — logs sometimes have blank lines or malformed entries.

```python
            gd = m.groupdict()
            try:
                ts = datetime.strptime(f"{current_year} {gd['ts']}", "%Y %b %d %H:%M:%S")
            except ValueError:
                ts = datetime.now()
```
Turns the captured timestamp text into an actual Python `datetime` object.
If parsing somehow fails (weird edge case), fall back to "now" rather than
crashing the whole ingestion over one bad line.

```python
            fm = _SSH_FAILED_RE.search(gd["msg"])
            if fm:
                yield {
                    **base,
                    "event_type": "auth_failure",
                    "user": fm.group("user"),
                    "src_ip": fm.group("ip"),
                    ...
                }
                continue
```
`**base` — Python's "unpack this dictionary here" syntax. `base` already has
`timestamp`, `source_type`, `host`, etc.; this line builds a *new* dict that
has all of those PLUS the SSH-specific fields, without retyping the shared
fields every time.

The `continue` after each `yield` means "we've handled this line, move to the
next one" — it stops the same line from also being checked against the sudo
pattern below it.

### `parse_suricata_eve`
```python
def parse_suricata_eve(path: str) -> Iterator[dict]:
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
```
Suricata writes one JSON object per line (this format is called "JSON Lines").
`json.loads(line)` turns that text into a Python dictionary. If a line isn't
valid JSON, skip it rather than crash.

```python
            ts_raw = rec.get("timestamp")
            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")) if ts_raw else datetime.now()
```
`.replace("Z", "+00:00")` — Suricata sometimes writes UTC timestamps ending in
`Z` (Zulu time), but Python's `fromisoformat` in some versions doesn't
understand `Z` directly — swapping it for `+00:00` (the explicit UTC offset)
makes it parseable.

```python
            alert = rec.get("alert", {})
            yield {
                ...
                "message": alert.get("signature") or rec.get("proto", ""),
```
`rec.get("alert", {})` — if there's no `"alert"` key at all, default to an
empty dict rather than crashing on `None.get(...)`. The `or` on the next line
means "use the signature text if there is one, otherwise fall back to just
the protocol name."

### `parse_windows_event_json`
```python
_WINDOWS_EVENT_ID_MAP = {
    "4624": "auth_success",
    "4625": "auth_failure",
    ...
}
```
Windows doesn't label events with readable names — it uses numeric IDs. This
dictionary translates the numbers analysts actually memorize (4625 = failed
login is a famous one) into your own readable `event_type` strings.

```python
    with open(path, "r", errors="replace") as f:
        records = json.load(f)
    if isinstance(records, dict):
        records = [records]
```
Handles both cases: a JSON file containing a list of events, or (if you only
exported one event) a single JSON object. Wrapping a lone dict in a list
means the rest of the function can always assume "a list of records."

### `SOURCE_PARSERS`
```python
SOURCE_PARSERS = {
    SourceType.AUTH_LOG: parse_auth_log,
    SourceType.SURICATA: parse_suricata_eve,
    ...
}
```
A dictionary mapping each source type to its parser *function itself* (not
its result — no parentheses). This is what lets `ingest.py` say "give me
whichever parser matches this source type" without a giant if/elif chain.

---

## `app/db.py` — Session management

```python
_engine = None
_SessionFactory = None
```
Module-level variables holding the "singleton" database connection — set once
by `setup()`, reused everywhere else, so every part of the app talks to the
same database file.

```python
def setup(db_path: str = "sqlite:///soc_agent.db"):
    global _engine, _SessionFactory
    _engine = get_engine(db_path)
    init_db(_engine)
    _SessionFactory = get_session_factory(_engine)
    return _engine
```
`global` — without this keyword, the assignments below it would create new
local variables instead of modifying the module-level ones. This function
connects to the DB, creates any missing tables, and prepares the session
factory.

```python
@contextmanager
def session_scope():
    if _SessionFactory is None:
        setup()
    session = _SessionFactory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
```
`@contextmanager` — this decorator turns a generator function into something
usable with Python's `with` statement, like `with session_scope() as
session:`. The flow:
1. Create a session.
2. `yield session` — hand it to whatever code is inside the `with` block.
3. Once that code finishes without errors, `session.commit()` saves
   everything permanently.
4. If anything inside the `with` block raised an exception,
   `session.rollback()` undoes any half-finished changes instead of leaving
   the database in a broken partial state.
5. `finally: session.close()` — always release the connection, whether it
   succeeded or failed.

This pattern is why every CLI script in this project just writes
`with session_scope() as session:` and never has to think about commit/
rollback/close manually.

---

## `app/ingest.py` — CLI to load a log file into the DB

```python
def _get_or_create_asset(session, hostname: str, ip: str | None = None) -> Asset:
    if not hostname:
        hostname = "unknown"
    asset = session.query(Asset).filter_by(hostname=hostname).one_or_none()
    if asset is None:
        asset = Asset(hostname=hostname, ip_address=ip, criticality=1, asset_type="unknown")
        session.add(asset)
        session.flush()
    return asset
```
`.one_or_none()` — queries for a matching Asset; returns `None` if there
isn't one yet (as opposed to `.one()`, which would crash if nothing matched).
If no asset exists yet for this hostname, create a bare-minimum one on the
fly (criticality defaults to 1 — lowest — until you manually update it).

`session.flush()` — pushes pending changes to the database *without*
committing the whole transaction yet. This matters because we need the new
asset's auto-generated `id` immediately (to link the Event to it), and that
`id` doesn't exist until the database has actually processed the `INSERT`.

```python
def ingest_file(source: str, path: str) -> int:
    try:
        source_type = SourceType(source)
    except ValueError:
        print(f"Unknown source type '{source}'. Valid: {[s.value for s in SourceType]}")
        return 0
```
`SourceType(source)` — tries to convert the string you typed on the command
line (like `"auth_log"`) into the matching enum value. If you typo it, this
raises `ValueError`, which gets caught and turned into a friendly error
message instead of an ugly traceback.

```python
    count = 0
    with session_scope() as session:
        for record in parser(path):
            asset = _get_or_create_asset(session, record.get("host"))
            record["asset_id"] = asset.id
            event = Event(**{k: v for k, v in record.items() if k != "host_ip"})
            session.add(event)
            count += 1
    return count
```
For every dict the parser yields: find/create its Asset, attach the asset's
`id` to the record, then `Event(**record)` unpacks that dictionary directly
into an `Event` object's constructor keyword arguments — this only works
because the dict's keys were designed to exactly match the `Event` model's
column names.

---

## `app/detection.py` — The rule engine

```python
def load_rules(rules_dir: str = RULES_DIR) -> list[dict]:
    rules = []
    for path in sorted(glob.glob(os.path.join(rules_dir, "*.yml"))):
        with open(path) as f:
            rule = yaml.safe_load(f)
            rule["_path"] = path
            rules.append(rule)
    return rules
```
`glob.glob(...*.yml)` — finds every file ending in `.yml` in the rules
folder. `yaml.safe_load` parses the YAML text into a Python dict (`safe_load`
specifically avoids executing arbitrary Python code that malicious YAML could
otherwise sneak in — always use `safe_load`, never plain `load`, for files
you didn't write yourself).

### The threshold rule engine
```python
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
```
This builds a SQL query using SQLAlchemy's Python syntax instead of raw SQL.
In plain English, this says: *"Look at events of this type that happened
after window_start. Group them by whatever field (like src_ip). Count how
many are in each group. Only keep groups where that count is at or above the
threshold."* This is the literal SQL concept of `GROUP BY ... HAVING COUNT(*)
>= N` — `HAVING` filters on the *aggregated* count, while `WHERE`/`.filter()`
filters on individual rows before grouping.

```python
    for group_value, cnt in q.all():
        matching_events = (
            session.query(Event)
            .filter(...)
            .all()
        )

        existing = _existing_open_alert(session, rule["id"], group_value, window_start)
        if existing:
            _attach_events(session, existing, matching_events)
            continue
```
For every IP (or user/host) that crossed the threshold, first check whether
there's already an open alert for this same rule + this same IP within the
window. If so, don't create a duplicate — just attach any new supporting
events to the existing alert. This is the dedup logic that stops a single
ongoing brute-force burst from spamming 50 separate alerts.

### The sequence rule engine
```python
def _run_sequence_rule(session: Session, rule: dict, now) -> list[Alert]:
    ...
    earliest_first = (
        session.query(Event)
        .filter(...)
        .order_by(Event.timestamp.asc())
        .first()
    )

    then_events = (
        session.query(Event)
        .filter(
            Event.event_type == then_spec["event_type"],
            Event.timestamp >= earliest_first.timestamp,
            ...
        )
        .all()
    )

    if not then_events:
        continue
```
This is the "failures THEN success" logic. It finds the earliest failure
event for this IP, then checks if any success event happened *after* that
timestamp. `if not then_events: continue` — if nothing came after the
failures, this group doesn't match the sequence pattern, so skip it (no
alert is created for a burst of failures alone under this particular rule —
that's what the separate threshold rule is for).

---

## `app/tools.py` — Read-only agent tools

```python
_KNOWN_BAD_IP_PREFIXES = ("45.142.", "103.211.")

def tool_enrich_ip(session: Session, ip: str) -> dict:
    result = {"ip": ip}
    try:
        addr = ipaddress.ip_address(ip)
        result["is_private"] = addr.is_private
        result["is_reserved"] = addr.is_reserved
    except ValueError:
        result["is_private"] = None
        result["is_reserved"] = None
```
`ipaddress.ip_address(ip)` is Python's built-in library for parsing IP
addresses correctly (handles both IPv4 and IPv6). `.is_private` tells you if
it's a local network address (like `192.168.x.x`) — those should almost never
be flagged as "malicious," since they're your own devices. Wrapped in
`try/except` because if `ip` isn't actually a valid IP string, this would
otherwise crash.

```python
    prior_event_count = session.query(Event).filter(Event.src_ip == ip).count()
    result["prior_event_count_in_this_db"] = prior_event_count
```
Simple but meaningful signal: has this IP shown up before, elsewhere in your
logs? A repeat offender against your own infrastructure is more suspicious
than a one-off.

```python
    if ip.startswith(_KNOWN_BAD_IP_PREFIXES):
        result["threat_intel"] = "heuristic_match: seen in known scanning/brute-force ranges..."
        result["heuristic_risk"] = "high"
```
`str.startswith()` accepts a *tuple* of prefixes and checks if the string
starts with any one of them — this is why `_KNOWN_BAD_IP_PREFIXES` is written
as a tuple `(...)` rather than a list.

### `dispatch_tool`
```python
def dispatch_tool(session: Session, tool_name: str, tool_input: dict, alert_window: tuple) -> dict:
    if tool_name == "query_logs":
        return tool_query_logs(session, alert_window, **tool_input)
    if tool_name == "enrich_ip":
        return tool_enrich_ip(session, tool_input["ip"])
    ...
    return {"error": f"Unknown tool: {tool_name}"}
```
This is the "router" — when Claude decides to call a tool by name, this
function looks at that name string and calls the matching real Python
function. `**tool_input` unpacks the dict of arguments Claude provided
directly into the function's keyword arguments.

---

## `app/agent.py` — The live Claude tool-use loop

```python
DEFAULT_MODEL = os.environ.get("SOC_AGENT_MODEL", "claude-sonnet-5")
MAX_TOOL_ROUNDS = 8
```
`os.environ.get(key, default)` — reads an environment variable if it's set,
otherwise falls back to the given default. `MAX_TOOL_ROUNDS` is a safety cap
so a confused agent can't loop forever calling tools and never concluding —
after 8 rounds it just fails loudly instead of hanging.

```python
def triage_alert(session: Session, alert: Alert, model: str = DEFAULT_MODEL) -> dict:
    client = anthropic.Anthropic()
```
Creates the API client. It automatically reads `ANTHROPIC_API_KEY` from your
environment — this is why you never see the key typed anywhere in the code.

```python
    events = [link.event for link in alert.event_links]
    if not events:
        raise ValueError(...)
    alert_window = (min(e.timestamp for e in events), max(e.timestamp for e in events))
```
`alert.event_links` gives you the join-table rows; `.event` on each one gives
you the actual Event object. `min(...)`/`max(...)` find the earliest and
latest timestamps among all supporting events — this defines the time
"window" that the `query_logs` tool will search around later.

```python
    messages = [{"role": "user", "content": _format_alert_context(alert)}]

    final_result = None
    for _round in range(MAX_TOOL_ROUNDS):
        response = client.messages.create(
            model=model,
            max_tokens=2000,
            system=SYSTEM_PROMPT,
            tools=TRIAGE_TOOLS,
            messages=messages,
        )
        messages.append({"role": "assistant", "content": response.content})
```
This is the actual conversation loop. Each iteration: send the full message
history so far to Claude, get a response, and append that response onto the
message list — this is how the model "remembers" the whole conversation,
since the API itself is stateless (it only knows what's in the `messages`
list you send each time).

```python
        tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
        if not tool_use_blocks:
            messages.append({
                "role": "user",
                "content": "Please call submit_triage to finalize your assessment.",
            })
            continue
```
A response's `content` can contain multiple pieces — text, tool calls, etc.
This filters out just the tool-call pieces. If the model just wrote text
without calling any tool, that's not useful to us (we need structured
output), so we nudge it and loop again rather than accepting the free text.

```python
        for block in tool_use_blocks:
            if block.name == "submit_triage":
                final_result = dict(block.input)
                submitted = True
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": "Triage recorded.",
                })
                continue

            result = dispatch_tool(session, block.name, block.input, alert_window)
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": str(result),
            })
```
For every tool call the model made in this turn: if it's the special
`submit_triage` tool, capture its input as the final answer. Otherwise,
actually run the real tool function and package the result. Every tool call
**must** get a matching `tool_result` sent back — this is an API requirement,
which is why even `submit_triage` gets a (trivial) result appended.

```python
        messages.append({"role": "user", "content": tool_results})
        if submitted:
            break
```
Tool results get sent back as a "user" turn (that's just the API's
convention for "here's data resulting from the tool you asked for"). If
`submit_triage` was among this round's calls, we're done — break out of the
loop.

---

## `app/mock_agent.py` — The free rule-based alternative

```python
def _most_common_src_ip(events) -> str | None:
    ips = [e.src_ip for e in events if e.src_ip]
    if not ips:
        return None
    return Counter(ips).most_common(1)[0][0]
```
`Counter` (from Python's `collections` module) counts how many times each
value appears in a list. `.most_common(1)` returns the single most frequent
one as a `[(value, count)]` list; `[0][0]` digs out just the value itself.
This finds "the IP that shows up most often among this alert's events" —
useful when an alert has multiple supporting events from the same source.

```python
    if rule == "auth-success-after-failures-001":
        severity = "critical"
        confidence = 0.9 if high_risk_ip else 0.75
```
This is a Python **ternary expression** — shorthand for an if/else that
returns a value. Reads as: "confidence is 0.9 if high_risk_ip is True,
otherwise 0.75." This is the entire "decision-making" of the mock agent —
explicit if/elif branches per rule name, unlike the real agent which reasons
freely.

```python
    reasoning = (
        f"[MOCK AGENT -- rule-based, not a live LLM call]\n"
        f"Investigation steps taken:\n  " + "\n  ".join(investigation_notes) + "\n\n"
        f"Decision: rule={rule}, high_risk_ip={high_risk_ip}, event_count={event_count} "
        f"-> severity={severity}, confidence={confidence}"
    )
```
This deliberately labels itself as mock output in plain text — so if you ever
look at this reasoning field later, you can't mistake it for a real Claude
response. `"\n  ".join(investigation_notes)` joins a list of strings with a
newline+indent between each one, for readable multi-line output.

---

## `app/actions.py` — The response/action layer

```python
ACTION_TIERS: dict[str, ActionTier] = {
    "block_ip": ActionTier.AUTO,
    "rate_limit_ip": ActionTier.AUTO,
    "monitor_closely": ActionTier.AUTO,
    "isolate_host": ActionTier.CONFIRM,
    "disable_user": ActionTier.CONFIRM,
    ...
}
```
This single dictionary is the entire safety policy of the system — every
action type is classified once, here, and every other function just looks it
up. If you ever want to make something stricter (e.g. require confirmation
for IP blocks too), this is the one line you'd change.

```python
class ActionExecutor:
    def block_ip(self, ip: str, duration_minutes: int) -> str:
        raise NotImplementedError
```
This is an **abstract base class** pattern — it defines *what methods must
exist* without saying *how* they work. `raise NotImplementedError` means "if
you use this base class directly instead of a real subclass, you get an
obvious crash," which forces you to always use a real implementation
(`DryRunExecutor` or your own).

```python
class DryRunExecutor(ActionExecutor):
    def block_ip(self, ip: str, duration_minutes: int) -> str:
        msg = f"[DRY RUN] Would block {ip} for {duration_minutes} minutes."
        logger.info(msg)
        return msg
```
`DryRunExecutor` **inherits** from `ActionExecutor` — meaning it must
implement every method the base class declared. Each method here just logs
what it *would* do and returns that message, without ever touching a real
firewall or system.

```python
def parse_action_string(raw: str) -> tuple[str, str, int | None] | None:
    parts = raw.strip().split(":")
    action_type = parts[0].strip().lower().replace(" ", "_")
    if action_type not in ACTION_TIERS:
        return None
```
Turns text like `"block_ip:45.142.212.61:60"` into structured pieces by
splitting on `:`. `.lower().replace(" ", "_")` normalizes formatting
(handles the LLM writing "Block IP" or "block ip" instead of exactly
"block_ip"). If the action type isn't one we recognize, return `None` so the
caller can skip it — this is how "no action needed" gets silently ignored
instead of crashing.

```python
def process_alert_actions(session: Session, alert: Alert, executor: ActionExecutor) -> list[Action]:
    existing = session.query(Action).filter(Action.alert_id == alert.id).count()
    if existing:
        return []

    recs = alert.agent_recommended_actions or []
    for raw in recs:
        parsed = parse_action_string(raw)
        if parsed is None:
            continue
        action_type, target, duration = parsed
        tier = ACTION_TIERS[action_type]

        action = Action(...)
        session.add(action)
        session.flush()
        created.append(action)

        if tier == ActionTier.AUTO:
            execute_action(session, action, executor)
```
`alert.agent_recommended_actions or []` — if that field is `None` (never set)
this defaults to an empty list instead of crashing on the `for` loop below.
For each valid recommendation: create the Action row first (always, so
there's a record even if execution later fails), then only *actually run it*
immediately if it's AUTO tier. CONFIRM-tier actions get created but never
touched here — they sit as `PROPOSED` until a human calls `approve_action`.

```python
def approve_action(session: Session, action: Action, executor: ActionExecutor) -> Action:
    if action.tier != ActionTier.CONFIRM:
        raise ValueError("approve_action is only for CONFIRM-tier actions.")
    action.status = ActionStatus.APPROVED
    return execute_action(session, action, executor)
```
A safety check: this function refuses to be used on AUTO-tier actions (which
should never need manual approval in the first place) — catches a
programming mistake early rather than letting it silently do the wrong
thing.

---

## `app/dashboard.py` — Streamlit UI

```python
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
```
Streamlit runs this file directly (not as part of the `app` package via
`python -m`), so Python doesn't automatically know where to find the `app`
module to import from. This line manually adds the project's root folder to
Python's search path so `from app.actions import ...` below it actually
works.

```python
st.set_page_config(page_title="SOC Agent Dashboard", layout="wide")
```
Configures the browser tab title and makes the page use the full screen
width instead of a narrow centered column.

```python
tab_alerts, tab_actions, tab_assets = st.tabs(["Alerts", "Pending Actions", "Assets"])

with tab_alerts:
    ...
```
`st.tabs()` creates the clickable tab bar; each `with tab_x:` block defines
what renders inside that specific tab. Streamlit reruns this *entire script
top to bottom* every time you interact with anything (click a button, etc.) —
that's a core quirk of how Streamlit works, and it's why the DB queries all
happen fresh each time rather than being cached.

```python
for alert in alerts:
    icon = SEVERITY_COLOR.get(alert.severity, "⚪")
    header = f"{icon} **{alert.severity.value.upper()}** — {alert.title}"
    with st.expander(header, expanded=(alert.status == AlertStatus.NEW)):
```
`st.expander` makes a collapsible section. `expanded=(alert.status ==
AlertStatus.NEW)` — this boolean decides whether it starts open or closed;
new/untriaged alerts start expanded automatically so you notice them, while
already-handled ones start collapsed to reduce clutter.

```python
    if approve_col.button("✅ Approve", key=f"approve_{action.id}"):
        approve_action(session, action, executor)
        st.rerun()
```
Every Streamlit button needs a unique `key` if there could be multiple
similar buttons on the page at once (one Approve button per pending action) —
without unique keys, Streamlit can't tell them apart. `st.rerun()` forces the
whole script to run again immediately, so the dashboard reflects the change
you just made (the approved action disappears from "pending" right away)
instead of waiting for your next click.

---

## `sigma_rules/*.yml` — The detection rules themselves

```yaml
title: SSH Brute Force - Repeated Auth Failures
id: ssh-brute-force-001
severity: high
description: >
  Multiple failed SSH authentication attempts...
detection:
  event_type: auth_failure
  group_by: src_ip
  window_minutes: 5
  threshold: 5
```
- `id` — must be unique and stable; this is what dedup logic and the mock
  agent's if/elif branches key off of. Don't rename these carelessly.
- `>` after `description:` is YAML's "fold this into one line, treating line
  breaks as spaces" syntax — lets you write a long description across
  multiple lines in the file without it literally containing line breaks in
  the final string.
- Everything under `detection:` maps directly to `detection.py`'s
  `_run_threshold_rule` function's expectations.

```yaml
detection:
  type: sequence
  group_by: src_ip
  window_minutes: 10
  first:
    event_type: auth_failure
    min_count: 3
  then:
    event_type: auth_success
```
The `type: sequence` key is what tells `run_detections()` in `detection.py`
to route this rule to `_run_sequence_rule` instead of the threshold engine.

---

## `generate_sample_logs.py` — Test data generator

```python
now = datetime.now(timezone.utc)

def fmt_syslog(dt: datetime) -> str:
    day = f"{dt.day:2d}"
    return f"{dt.strftime('%b')} {day} {dt.strftime('%H:%M:%S')}"
```
`f"{dt.day:2d}"` — formats the day number to always take up 2 characters,
padding with a space if it's a single digit (so "4" becomes " 4"). This
matches real syslog's slightly odd double-space-padded day format (you'll
notice `"Jul  4"` has two spaces, not one — that's intentional, matching real
log output).

```python
brute_start = now - timedelta(minutes=3)
```
All the fake timestamps are calculated *relative to whenever you run this
script* — this is why regenerating sample logs matters each session; if you
reuse old ones, the events might now be outside your detection rules'
lookback windows.

---

## `tests/test_agent_mock.py` — Mocked plumbing test

```python
def _block(type_, **kwargs):
    return SimpleNamespace(type=type_, **kwargs)
```
`SimpleNamespace` is a lightweight way to create an object with arbitrary
attributes, without defining a full class. This fakes the shape of a real
Anthropic API response block (which has `.type`, `.name`, `.input`, `.id`
attributes) without needing the real library's classes.

```python
def fake_create(**kwargs):
    call_count["n"] += 1
    if call_count["n"] == 1:
        return SimpleNamespace(content=[...])
    elif call_count["n"] == 2:
        ...
```
This simulates a scripted, predictable "conversation" — first call returns a
fake `enrich_ip` request, second call returns a fake
`check_asset_criticality` request, third returns `submit_triage`. This tests
that `agent.py`'s loop correctly handles multiple rounds of tool calls
without needing a real, unpredictable LLM response.

```python
with patch("anthropic.Anthropic", return_value=make_fake_client()):
    result = agent.triage_alert(session, alert)
```
`patch(...)` temporarily replaces the real `anthropic.Anthropic` class with
our fake one, only for the duration of the `with` block. This is how the test
verifies the *loop logic* works correctly without spending any real API
credits or needing network access.

---

## The overall pattern worth remembering

Almost every file in this project follows the same shape:
1. **Read something** (a log line, a database row, an API response)
2. **Validate/normalize it** (regex match, enum conversion, dict shape)
3. **Do the minimal amount of work needed**, with explicit fallbacks for
   anything that could go wrong (`try/except`, `.get()` with defaults,
   `if not X: continue`)
4. **Hand off a clean, predictable shape** to the next stage

That defensive style (checking for `None`, catching exceptions, using
sensible defaults) is what separates "code that works on my sample data"
from "code that survives real, messy, unpredictable logs" — worth carrying
into your other projects too.
