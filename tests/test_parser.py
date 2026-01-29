from src.parser import parse_auth_log


def test_parser_counts_events():
    """
    Parser should correctly classify events from the sample auth log.
    """
    df = parse_auth_log("data/sample_auth.log")

    counts = df["event_type"].value_counts().to_dict()

    assert counts.get("FAILED_LOGIN") == 10
    assert counts.get("SUCCESS_LOGIN") == 1
    assert counts.get("SUDO") == 1
