"""
Generates sample_logs/auth.log and sample_logs/eve.json with timestamps
anchored to *now* (not hardcoded dates), so detection window rules
(e.g. "5 failures in 5 minutes") actually have a chance to fire when
you test the pipeline, regardless of when you run it.

Usage: python3 generate_sample_logs.py
"""

from datetime import datetime, timedelta, timezone
import json

now = datetime.now(timezone.utc)


def fmt_syslog(dt: datetime) -> str:
    # e.g. "Jul  4 01:14:02" -- syslog's slightly odd double-space day padding
    day = f"{dt.day:2d}"
    return f"{dt.strftime('%b')} {day} {dt.strftime('%H:%M:%S')}"


auth_lines = []
brute_start = now - timedelta(minutes=3)
attackers = ["45.142.212.61"] * 8
users = ["admin", "admin", "root", "root", "test", "test", "oracle", "oracle"]
for i, (ip, user) in enumerate(zip(attackers, users)):
    ts = brute_start + timedelta(seconds=i * 3)
    auth_lines.append(
        f"{fmt_syslog(ts)} homelab sshd[{1001+i}]: Failed password for invalid user {user} "
        f"from {ip} port {51422+i*8}"
    )

# a successful legit login, unrelated
legit_ts = now - timedelta(minutes=2)
auth_lines.append(f"{fmt_syslog(legit_ts)} homelab sshd[1200]: Accepted publickey for sofia from 192.168.1.42 port 55210")
auth_lines.append(f"{fmt_syslog(legit_ts)} homelab sudo[1201]: sofia : TTY=pts/0 ; PWD=/home/sofia ; USER=root ; COMMAND=/usr/bin/apt update")

# a second attacker who ALSO gets in -- should trigger the sequence rule
cred_stuff_start = now - timedelta(minutes=8)
for i in range(3):
    ts = cred_stuff_start + timedelta(seconds=i * 4)
    auth_lines.append(
        f"{fmt_syslog(ts)} homelab sshd[{1300+i}]: Failed password for invalid user postgres "
        f"from 103.211.9.14 port {40011+i*8}"
    )
success_ts = cred_stuff_start + timedelta(seconds=20)
auth_lines.append(f"{fmt_syslog(success_ts)} homelab sshd[1310]: Accepted password for postgres from 103.211.9.14 port 40050")

with open("sample_logs/auth.log", "w") as f:
    f.write("\n".join(auth_lines) + "\n")

# --- Suricata EVE JSON, same timeframes ---
eve_records = [
    {
        "timestamp": brute_start.isoformat(),
        "host": "homelab-gw",
        "event_type": "alert",
        "src_ip": "45.142.212.61",
        "src_port": 51422,
        "dest_ip": "192.168.1.10",
        "dest_port": 22,
        "proto": "TCP",
        "alert": {"signature": "ET SCAN SSH BruteForce Tool", "category": "Attempted Administrator Privilege Gain", "severity": 1},
    },
    {
        "timestamp": cred_stuff_start.isoformat(),
        "host": "homelab-gw",
        "event_type": "alert",
        "src_ip": "103.211.9.14",
        "src_port": 40011,
        "dest_ip": "192.168.1.10",
        "dest_port": 22,
        "proto": "TCP",
        "alert": {"signature": "ET SCAN Suspicious inbound to PostgreSQL port 5432", "category": "Potentially Bad Traffic", "severity": 2},
    },
    {
        "timestamp": legit_ts.isoformat(),
        "host": "homelab-gw",
        "event_type": "dns",
        "src_ip": "192.168.1.42",
        "dest_ip": "1.1.1.1",
        "proto": "UDP",
    },
]

with open("sample_logs/eve.json", "w") as f:
    for rec in eve_records:
        f.write(json.dumps(rec) + "\n")

print(f"Generated sample logs anchored to now = {now.isoformat()}")
