"""API Logs - View recent API request logs"""
from __future__ import annotations

import streamlit as st
import pandas as pd

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils import api_get, auto_refresh_toggle, setup_auto_refresh, COLORS

st.title("API Logs")

# Controls row
col1, col2, col3, col4 = st.columns([2, 1, 1, 1])

with col1:
    hours_options = {"1 hour": 1, "6 hours": 6, "24 hours": 24, "7 days": 168}
    time_range = st.selectbox("Time range", options=list(hours_options.keys()), index=2)
    hours = hours_options[time_range]

with col2:
    limit = st.selectbox("Max entries", options=[50, 100, 200, 500], index=1)

with col3:
    status_filter = st.selectbox(
        "Status filter",
        options=["All", "2xx Success", "4xx Client Error", "5xx Server Error"],
        index=0,
    )

with col4:
    auto_refresh = auto_refresh_toggle("logs_auto_refresh")
    if st.button("Refresh"):
        st.rerun()

setup_auto_refresh(auto_refresh)

# Path filter
path_filter = st.text_input("Filter by path (contains)", placeholder="/auth/token")

st.markdown("---")

# Build query params
params = {"hours": hours, "limit": limit}
if path_filter:
    params["path"] = path_filter
if status_filter == "2xx Success":
    params["status_code"] = 200
elif status_filter == "4xx Client Error":
    # We'll filter client-side for 4xx range
    pass
elif status_filter == "5xx Server Error":
    # We'll filter client-side for 5xx range
    pass

# Fetch logs
try:
    logs = api_get("/logs/requests", params=params)
except Exception as e:
    st.error(f"Cannot fetch logs: {e}")
    st.stop()

# Filter by status range client-side if needed
if status_filter == "4xx Client Error":
    logs = [l for l in logs if 400 <= l["status_code"] < 500]
elif status_filter == "5xx Server Error":
    logs = [l for l in logs if l["status_code"] >= 500]

# Summary metrics
total_logs = len(logs)
errors_4xx = len([l for l in logs if 400 <= l["status_code"] < 500])
errors_5xx = len([l for l in logs if l["status_code"] >= 500])
avg_latency = sum(l["latency_ms"] for l in logs) / total_logs if total_logs > 0 else 0

m1, m2, m3, m4 = st.columns(4)
with m1:
    st.metric("Total Requests", total_logs)
with m2:
    st.metric("4xx Errors", errors_4xx)
with m3:
    st.metric("5xx Errors", errors_5xx)
with m4:
    st.metric("Avg Latency", f"{avg_latency:.1f}ms")

st.markdown("---")

# Display logs
st.subheader("Request Logs")

if logs:
    # Prepare dataframe
    df = pd.DataFrame(logs)

    # Format timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")

    # Format latency
    df["latency_ms"] = df["latency_ms"].apply(lambda x: f"{x:.1f}")

    # Select and rename columns for display
    display_cols = ["timestamp", "method", "path", "status_code", "latency_ms"]
    if "error_detail" in df.columns:
        display_cols.append("error_detail")

    df_display = df[display_cols].copy()
    df_display.columns = ["Timestamp", "Method", "Path", "Status", "Latency (ms)"] + (
        ["Error"] if "error_detail" in display_cols else []
    )

    # Color-code status
    def color_status(val):
        try:
            code = int(val)
            if code >= 500:
                return "background-color: #f8d7da; color: #721c24"  # Red for 5xx
            elif code >= 400:
                return "background-color: #fff3cd; color: #856404"  # Yellow for 4xx
            elif code >= 200 and code < 300:
                return "background-color: #d4edda; color: #155724"  # Green for 2xx
            else:
                return ""
        except (ValueError, TypeError):
            return ""

    styled_df = df_display.style.applymap(color_status, subset=["Status"])
    st.dataframe(styled_df, use_container_width=True, hide_index=True, height=500)

    # Export option
    st.download_button(
        "Download CSV",
        df.to_csv(index=False),
        file_name="api_logs.csv",
        mime="text/csv",
    )
else:
    st.info("No logs found for the selected filters")

# Endpoint breakdown
st.markdown("---")
st.subheader("Requests by Endpoint")

if logs:
    endpoint_counts = {}
    for log in logs:
        path = log["path"]
        if path not in endpoint_counts:
            endpoint_counts[path] = {"count": 0, "errors": 0}
        endpoint_counts[path]["count"] += 1
        if log["status_code"] >= 400:
            endpoint_counts[path]["errors"] += 1

    endpoint_df = pd.DataFrame([
        {"Endpoint": k, "Requests": v["count"], "Errors": v["errors"]}
        for k, v in sorted(endpoint_counts.items(), key=lambda x: x[1]["count"], reverse=True)
    ])
    st.dataframe(endpoint_df, use_container_width=True, hide_index=True)
