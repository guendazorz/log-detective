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

    # 1) Keep only failed logins that have an IP + timestamp
    df = events.copy()
    df = df[
        (df["event_type"] == "FAILED_LOGIN")
        & df["ip"].notna()
        & df["timestamp"].notna()
    ].copy()

    # If there's nothing to analyze, return empty alerts table
    if df.empty:
        return pd.DataFrame(
            columns=["alert_type", "severity", "ip", "start_time", "end_time", "count", "evidence"]
        )

    # Sort by time so the sliding window logic works
    df = df.sort_values("timestamp")

    window = pd.Timedelta(minutes=window_minutes)
    alerts = []

    # 2) Analyze each IP separately
    for ip, group in df.groupby("ip"):
        times = group["timestamp"].tolist()
        raws = group["raw"].tolist()

        left = 0

        # 3) Sliding window over time
        for right in range(len(times)):
            # Shrink window until it's within the allowed time range
            while times[right] - times[left] > window:
                left += 1

            count = right - left + 1

            # If we cross threshold, we record an alert
            if count >= threshold:
                start_time = times[left]
                end_time = times[right]

                # Evidence: last ~3 raw lines in the window (enough to prove it)
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
                    }
                )

                # MVP choice: once we flag an IP once, stop adding more alerts for it
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

    # Keep only events we care about
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

        # Look backward in time for failures from same IP
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

