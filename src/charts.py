from __future__ import annotations

from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt


def plot_top_attacking_ips(events: pd.DataFrame, out_path: str | Path, top_n: int = 10) -> None:
    """
    Bar chart: top IPs by FAILED_LOGIN count.
    """
    df = events[(events["event_type"] == "FAILED_LOGIN") & events["ip"].notna()].copy()
    counts = df["ip"].value_counts().head(top_n)

    plt.figure()
    counts.plot(kind="bar")
    plt.title(f"Top {top_n} Attacking IPs (Failed Logins)")
    plt.xlabel("IP")
    plt.ylabel("Failed login count")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_failed_login_timeline(events: pd.DataFrame, out_path: str | Path, freq: str = "1min") -> None:
    """
    Line chart: failed logins over time (bucketed).
    freq examples: '1min', '5min', '15min'
    """
    df = events[(events["event_type"] == "FAILED_LOGIN") & events["timestamp"].notna()].copy()
    if df.empty:
        # still create an empty chart (optional), but we'll just skip for MVP
        return

    df = df.set_index("timestamp")
    series = df.resample(freq).size()

    plt.figure()
    plt.plot(series.index, series.values)
    plt.title(f"Failed Login Timeline ({freq} buckets)")
    plt.xlabel("Time")
    plt.ylabel("Failed logins")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()
