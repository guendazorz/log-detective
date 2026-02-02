from __future__ import annotations

from pathlib import Path
import tempfile

import pandas as pd
import streamlit as st

from src.parser import parse_auth_log
from src.detections import detect_bruteforce_by_ip, detect_success_after_failures
from src.charts import plot_top_attacking_ips, plot_failed_login_timeline


st.set_page_config(page_title="Log Detective", layout="wide")

st.title("🕵️ Log Detective — Mini SOC Dashboard")
st.caption("Parse Linux auth logs → detect suspicious patterns → visualize + export alerts")


# Sidebar controls
st.sidebar.header("Data source")

default_path = Path("data/sample_auth.log")
use_sample = st.sidebar.checkbox("Use sample log (data/sample_auth.log)", value=True)

uploaded = st.sidebar.file_uploader("…or upload an auth.log file", type=["log", "txt"])

st.sidebar.header("Detection thresholds")

bf_threshold = st.sidebar.slider("Brute force: failed attempts threshold", min_value=3, max_value=25, value=8, step=1)
bf_window = st.sidebar.slider("Brute force: time window (minutes)", min_value=1, max_value=60, value=10, step=1)

saf_threshold = st.sidebar.slider("Success-after-failures: failed attempts threshold", min_value=1, max_value=25, value=5, step=1)
saf_window = st.sidebar.slider("Success-after-failures: lookback window (minutes)", min_value=1, max_value=240, value=30, step=5)

timeline_bucket = st.sidebar.selectbox("Timeline bucket size", ["1min", "5min", "15min", "30min"], index=0)



# Load logs
def load_log_to_path() -> Path | None:
    """
    Returns a filesystem path to a log file:
    - sample log, or
    - uploaded file written to a temp file
    """
    if use_sample:
        if default_path.exists():
            return default_path
        st.error(f"Sample log not found at: {default_path}")
        return None

    if uploaded is None:
        st.info("Upload a log file or enable the sample log.")
        return None

    
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".log")
    tmp.write(uploaded.getvalue())
    tmp.flush()
    return Path(tmp.name)


log_path = load_log_to_path()
if log_path is None:
    st.stop()



# Parse + detect
events = parse_auth_log(log_path)

alerts_bf = detect_bruteforce_by_ip(events, threshold=bf_threshold, window_minutes=bf_window)
alerts_saf = detect_success_after_failures(events, failure_threshold=saf_threshold, window_minutes=saf_window)

all_alerts = alerts_bf
if not alerts_saf.empty:
    all_alerts = pd.concat([alerts_bf, alerts_saf], ignore_index=True)


preferred_cols = ["alert_type", "severity", "ip", "username", "start_time", "end_time", "count", "evidence"]
all_alerts = all_alerts[[c for c in preferred_cols if c in all_alerts.columns]]



# Top metrics
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Total events parsed", len(events))

with col2:
    failed_count = int((events["event_type"] == "FAILED_LOGIN").sum())
    st.metric("Failed logins", failed_count)

with col3:
    success_count = int((events["event_type"] == "SUCCESS_LOGIN").sum())
    st.metric("Successful logins", success_count)

with col4:
    st.metric("Alerts generated", len(all_alerts))



# Alerts + Data
left, right = st.columns([1, 1])

with left:
    st.subheader("🚨 Alerts")
    if all_alerts.empty:
        st.success("No alerts detected with the current thresholds.")
    else:
        st.dataframe(all_alerts, use_container_width=True)

        
        st.download_button(
            label="Download alerts CSV",
            data=all_alerts.to_csv(index=False).encode("utf-8"),
            file_name="flagged_events.csv",
            mime="text/csv",
        )

with right:
    st.subheader("📄 Parsed events (preview)")
    st.dataframe(events.head(200), use_container_width=True)

    
    st.download_button(
        label="Download parsed events CSV",
        data=events.to_csv(index=False).encode("utf-8"),
        file_name="parsed_events.csv",
        mime="text/csv",
    )



# Charts (generated to temp files)
st.subheader("📊 Visuals")

chart1, chart2 = st.columns(2)

with tempfile.TemporaryDirectory() as tmpdir:
    tmpdir = Path(tmpdir)
    top_ips_path = tmpdir / "top_attacking_ips.png"
    timeline_path = tmpdir / "failed_login_timeline.png"

    plot_top_attacking_ips(events, top_ips_path, top_n=10)
    plot_failed_login_timeline(events, timeline_path, freq=timeline_bucket)

    with chart1:
        st.caption("Top Attacking IPs (Failed Logins)")
        if top_ips_path.exists():
            st.image(str(top_ips_path), use_container_width=True)

    with chart2:
        st.caption("Failed Login Timeline")
        if timeline_path.exists():
            st.image(str(timeline_path), use_container_width=True)


st.divider()
st.caption(f"Log source: {log_path}")
