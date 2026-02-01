from __future__ import annotations

import pandas as pd


def detect_bruteforce_by_ip(
    events: pd.DataFrame,
    threshold: int = 8,
    window_minutes: int = 10,
) -> pd.DataFrame:
    """
    Brute force detection:
    Trigger if >= threshold FAILED_LOGIN events from the same IP
    within window_minutes.

    Returns a DataFrame of alerts with:
      alert_type, severity, ip, start_time, end_time, count, evidence
    """

    
    df = events.copy()
    df = df[
        (df["event_type"] == "FAILED_LOGIN")
        & df["ip"].notna()
        & df["timestamp"].notna()
    ].copy()

    
    if df.empty:
        return pd.DataFrame(
            columns=["alert_type", "severity", "ip", "start_time", "end_time", "count", "evidence"]
        )

    
    df = df.sort_values("timestamp")

    window = pd.Timedelta(minutes=window_minutes)
    alerts = []

    
    for ip, group in df.groupby("ip"):
        times = group["timestamp"].tolist()
        raws = group["raw"].tolist()

        left = 0

        
        for right in range(len(times)):
            
            while times[right] - times[left] > window:
                left += 1

            count = right - left + 1

            
            if count >= threshold:
                start_time = times[left]
                end_time = times[right]

                
                evidence = " | ".join(raws[max(left, right - 2) : right + 1])

                alerts.append(
                    {
                        "alert_type": "BRUTE_FORCE_IP",
                        "severity": "HIGH",
                        "ip": ip,
                        "start_time": start_time,
                        "end_time": end_time,
                        "count": count,
                        "evidence": evidence,
                        "username": "multiple/unknown",
                    }
                )

                
                break

    return pd.DataFrame(alerts)


def detect_success_after_failures(
    events: pd.DataFrame,
    failure_threshold: int = 5,
    window_minutes: int = 30,
) -> pd.DataFrame:
    """
    Detect successful logins that occur after multiple failures
    from the same IP within a time window.

    Returns alerts DataFrame.
    """

    df = events.copy()

    
    failures = df[
        (df["event_type"] == "FAILED_LOGIN")
        & df["ip"].notna()
        & df["timestamp"].notna()
    ].copy()

    successes = df[
        (df["event_type"] == "SUCCESS_LOGIN")
        & df["ip"].notna()
        & df["timestamp"].notna()
    ].copy()

    if failures.empty or successes.empty:
        return pd.DataFrame(
            columns=[
                "alert_type",
                "severity",
                "ip",
                "username",
                "success_time",
                "failure_count",
                "evidence",
            ]
        )

    window = pd.Timedelta(minutes=window_minutes)
    alerts = []

    for _, success in successes.iterrows():
        ip = success["ip"]
        success_time = success["timestamp"]
        username = success["username"]

        
        recent_failures = failures[
            (failures["ip"] == ip)
            & (failures["timestamp"] >= success_time - window)
            & (failures["timestamp"] < success_time)
        ]

        failure_count = len(recent_failures)

        if failure_count >= failure_threshold:
            evidence_lines = recent_failures.tail(3)["raw"].tolist()
            evidence_lines.append(success["raw"])

            alerts.append(
                {
                    "alert_type": "SUCCESS_AFTER_FAILURES",
                    "severity": "HIGH",
                    "ip": ip,
                    "username": username,
                    "success_time": success_time,
                    "failure_count": failure_count,
                    "evidence": " | ".join(evidence_lines),
                }
            )

    return pd.DataFrame(alerts)

def detect_success_after_failures(
    events: pd.DataFrame,
    failure_threshold: int = 5,
    window_minutes: int = 30,
) -> pd.DataFrame:
    """
    Alert when a SUCCESS_LOGIN occurs from an IP that had >= failure_threshold
    FAILED_LOGIN events within the previous window_minutes.
    """
    df = events.copy()

    failures = df[
        (df["event_type"] == "FAILED_LOGIN")
        & df["ip"].notna()
        & df["timestamp"].notna()
    ].copy()

    successes = df[
        (df["event_type"] == "SUCCESS_LOGIN")
        & df["ip"].notna()
        & df["timestamp"].notna()
    ].copy()

    if failures.empty or successes.empty:
        return pd.DataFrame(
            columns=["alert_type", "severity", "ip", "username", "start_time", "end_time", "count", "evidence"]
        )

    window = pd.Timedelta(minutes=window_minutes)
    alerts = []

    for _, s in successes.iterrows():
        ip = s["ip"]
        success_time = s["timestamp"]
        username = s["username"]

        recent_failures = failures[
            (failures["ip"] == ip)
            & (failures["timestamp"] >= success_time - window)
            & (failures["timestamp"] < success_time)
        ]

        failure_count = len(recent_failures)

        if failure_count >= failure_threshold:
            evidence = recent_failures.tail(3)["raw"].tolist()
            evidence.append(s["raw"])

            first_failure_time = recent_failures["timestamp"].min()

            alerts.append(
                {
       		   "alert_type": "SUCCESS_AFTER_FAILURES",
                   "severity": "HIGH",
                   "ip": ip,
                   "username": username,
                   "start_time": first_failure_time,
                   "end_time": success_time,
                   "count": failure_count,
                   "evidence": " | ".join(evidence),
                }
            )

    return pd.DataFrame(alerts)





