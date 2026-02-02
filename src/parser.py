from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

import pandas as pd

# 1) Parse the common auth.log prefix:
PREFIX_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<service>\w+)(?:\[\d+\])?:\s+(?P<message>.*)$"
)

# 2) Parse key event types from the message portion.
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# Successful login:
# "Accepted password for guenda from 203.0.113.10 ..."
ACCEPTED_RE = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

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

   
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        raw = line.strip()
        if not raw:
            continue

        
        m = PREFIX_RE.match(raw)
        if not m:
            
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

        
        event_type = "OTHER"
        username: Optional[str] = None
        ip: Optional[str] = None

    
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
