from __future__ import annotations

from pathlib import Path

from src.parser import parse_auth_log
from src.detections import detect_bruteforce_by_ip
from src.charts import plot_top_attacking_ips, plot_failed_login_timeline



def main() -> None:
    log_path = Path("data/sample_auth.log")
    out_dir = Path("outputs")
    out_dir.mkdir(exist_ok=True)

    # 1) Parse logs
    events = parse_auth_log(log_path)

    # 2) Run brute force detection
    alerts = detect_bruteforce_by_ip(events, threshold=8, window_minutes=10)

    # 3) Export results
    events.to_csv(out_dir / "parsed_events.csv", index=False)
    alerts.to_csv(out_dir / "flagged_events.csv", index=False)

    print(f"Parsed events written to: {out_dir / 'parsed_events.csv'}")
    print(f"Alerts written to: {out_dir / 'flagged_events.csv'}")

    # 4) Generate charts
    plot_top_attacking_ips(events, out_dir / "top_attacking_ips.png",         top_n=10)
    plot_failed_login_timeline(events, out_dir /   "failed_login_timeline.png", freq="1min")

    print(f"Charts written to: {out_dir / 'top_attacking_ips.png'}")
    print(f"Charts written to: {out_dir / 'failed_login_timeline.png'}")

    if alerts.empty:
        print("No alerts detected.")
    else:
        print("\n=== Alerts ===")
        print(alerts.to_string(index=False))


if __name__ == "__main__":
    main()
