from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

import pandas as pd

# 1) Parse the common auth.log prefix:
# Example:
# Jan 28 21:10:01 ubuntu sshd[1111]: Failed password for invalid user admin from 203.0.113.10 port 40111 ssh2
#
# We want to capture:
# - month, day, time  -> timestamp (auth.log doesn't include year)
# - host             -> ubuntu
# - service          -> sshd (or sudo)
# - message          -> the rest of the line after ": "
PREFIX_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<service>\w+)(?:\[\d+\])?:\s+(?P<message>.*)$"
)

# 2) Parse key event types from the message portion.
# Failed login:
# "Failed password for invalid user admin from 203.0.113.10 ..."
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# Successful login:
# "Accepted password for guenda from 203.0.113.10 ..."
ACCEPTED_RE = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# Sudo:
# "sudo:   guenda : TTY=pts/0 ; ..."
SUDO_RE = re.compile(
    r"^(?P<user>\S+)\s*:"
)


def _parse_timestamp(mon: str, day: str, time_str: str, year: int) -> datetime:
    """
    auth.log does not include a year, so we inject one.
    For our project MVP, current year is good enough.
    """
    dt_str = f"{year} {mon} {day} {time_str}"
    return datetime.strptime(dt_str, "%Y %b %d %H:%M:%S")


def parse_auth_log(path: str | Path, year: int | None = None) -> pd.DataFrame:
    """
    Reads an auth.log-style file and returns a DataFrame with columns:
      timestamp, host, service, event_type, username, ip, raw
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    if year is None:
        year = datetime.now().year

    rows: List[Dict[str, Any]] = []

    # Read file safely; ignore weird characters instead of crashing.
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        raw = line.strip()
        if not raw:
            continue

        # Step 1: split the line into prefix fields + message.
        m = PREFIX_RE.match(raw)
        if not m:
            # If it doesn't match the expected prefix format,
            # keep it as OTHER so we don't lose visibility.
            rows.append(
                {
                    "timestamp": pd.NaT,
                    "host": None,
                    "service": None,
                    "event_type": "OTHER",
                    "username": None,
                    "ip": None,
                    "raw": raw,
                }
            )
            continue

        ts = _parse_timestamp(m["mon"], m["day"], m["time"], year)
        host = m["host"]
        service = m["service"]
        msg = m["message"].lstrip()

        # Default classification
        event_type = "OTHER"
        username: Optional[str] = None
        ip: Optional[str] = None

        # Step 2: classify the message content into a security-relevant event type.
        m_failed = FAILED_RE.search(msg)
        if m_failed:
            event_type = "FAILED_LOGIN"
            username = m_failed["user"]
            ip = m_failed["ip"]
        else:
            m_acc = ACCEPTED_RE.search(msg)
            if m_acc:
                event_type = "SUCCESS_LOGIN"
                username = m_acc["user"]
                ip = m_acc["ip"]
            else:
                m_sudo = SUDO_RE.search(msg)
                if m_sudo:
                    event_type = "SUDO"
                    username = m_sudo["user"]

        rows.append(
            {
                "timestamp": ts,
                "host": host,
                "service": service,
                "event_type": event_type,
                "username": username,
                "ip": ip,
                "raw": raw,
            }
        )

    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df
