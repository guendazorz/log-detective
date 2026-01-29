from __future__ import annotations

from pathlib import Path

from src.parser import parse_auth_log
from src.detections import detect_bruteforce_by_ip
from src.charts import plot_top_attacking_ips, plot_failed_login_timeline
from src.detections import detect_success_after_failures
import pandas as pd



def main() -> None:
    log_path = Path("data/sample_auth.log")
    out_dir = Path("outputs")
    out_dir.mkdir(exist_ok=True)

    # 1) Parse logs
    events = parse_auth_log(log_path)

    # 2) Run detections
    alerts = detect_bruteforce_by_ip(events, threshold=8, window_minutes=10)
    alerts2 = detect_success_after_failures(events, failure_threshold=5, window_minutes=30)

    # 3) Combine alerts
    all_alerts = alerts
    if not alerts2.empty:
        all_alerts = pd.concat([alerts, alerts2], ignore_index=True)

    # 4) Export results
    events.to_csv(out_dir / "parsed_events.csv", index=False)
    all_alerts.to_csv(out_dir / "flagged_events.csv", index=False)

    print(f"Parsed events written to: {out_dir / 'parsed_events.csv'}")
    print(f"Alerts written to: {out_dir / 'flagged_events.csv'}")

    # 5) Generate charts
    plot_top_attacking_ips(events, out_dir / "top_attacking_ips.png", top_n=10)
    plot_failed_login_timeline(events, out_dir / "failed_login_timeline.png", freq="1min")

    print(f"Charts written to: {out_dir / 'top_attacking_ips.png'}")
    print(f"Charts written to: {out_dir / 'failed_login_timeline.png'}")

    if all_alerts.empty:
        print("No alerts detected.")
    else:
        print("\n=== Alerts ===")
        print(all_alerts.to_string(index=False))


if __name__ == "__main__":
    main()

