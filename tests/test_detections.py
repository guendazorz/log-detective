from src.parser import parse_auth_log
from src.detections import detect_bruteforce_by_ip


def test_bruteforce_detection_triggers():
    """
    Brute force detection should trigger for IP with >= 8 failures.
    """
    events = parse_auth_log("data/sample_auth.log")
    alerts = detect_bruteforce_by_ip(events, threshold=8, window_minutes=10)

    assert len(alerts) == 1
    assert alerts.iloc[0]["ip"] == "203.0.113.10"
    assert alerts.iloc[0]["count"] >= 8


def test_bruteforce_detection_does_not_trigger_for_low_activity():
    """
    IP with only a few failures should not trigger brute force detection.
    """
    events = parse_auth_log("data/sample_auth.log")
    alerts = detect_bruteforce_by_ip(events, threshold=8, window_minutes=10)

    # Ensure the benign IP is NOT flagged
    assert "198.51.100.7" not in alerts["ip"].values
