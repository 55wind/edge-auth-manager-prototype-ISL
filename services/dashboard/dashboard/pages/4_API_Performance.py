"""API Performance - Request metrics and latency analysis"""
from __future__ import annotations

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils import (
    api_get, time_range_selector, auto_refresh_toggle, setup_auto_refresh,
    format_latency, format_percentage, COLORS, CHART_LAYOUT,
)

st.title("API Performance")

# Controls
col1, col2, col3 = st.columns([2, 1, 1])
with col2:
    hours = time_range_selector("perf_time_range")
with col3:
    auto_refresh = auto_refresh_toggle("perf_auto_refresh")

setup_auto_refresh(auto_refresh)

# Fetch data
try:
    request_stats = api_get("/metrics/requests", {"hours": hours})
    hourly_volume = api_get("/metrics/requests/hourly", {"hours": hours})
    endpoint_stats = api_get("/metrics/requests/endpoints", {"hours": hours})
except Exception as e:
    st.error(f"Cannot reach manager API: {e}")
    st.stop()

# Summary metrics
st.subheader("Request Summary")
m1, m2, m3, m4, m5, m6 = st.columns(6)

with m1:
    st.metric("Total Requests", f"{request_stats['total_requests']:,}")
with m2:
    st.metric("Errors (5xx)", request_stats["error_count"])
with m3:
    st.metric("Error Rate", format_percentage(request_stats["error_rate"]))
with m4:
    st.metric("P50 Latency", format_latency(request_stats["latency_p50_ms"]))
with m5:
    st.metric("P95 Latency", format_latency(request_stats["latency_p95_ms"]))
with m6:
    st.metric("P99 Latency", format_latency(request_stats["latency_p99_ms"]))

st.markdown("---")

# Charts row
chart1, chart2 = st.columns(2)

with chart1:
    st.subheader("Request Volume Over Time")
    if hourly_volume:
        df = pd.DataFrame(hourly_volume)
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df["hour"],
            y=df["total"],
            mode="lines+markers",
            name="Total Requests",
            line=dict(color=COLORS["primary"]),
            fill="tozeroy",
        ))
        if df["errors"].sum() > 0:
            fig.add_trace(go.Scatter(
                x=df["hour"],
                y=df["errors"],
                mode="lines+markers",
                name="Errors",
                line=dict(color=COLORS["danger"]),
            ))
        fig.update_layout(
            **CHART_LAYOUT,
            xaxis_title="Time",
            yaxis_title="Requests",
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No request data in the selected time range")

with chart2:
    st.subheader("Latency Percentiles")
    latency_data = pd.DataFrame({
        "Percentile": ["P50", "P95", "P99"],
        "Latency (ms)": [
            request_stats["latency_p50_ms"],
            request_stats["latency_p95_ms"],
            request_stats["latency_p99_ms"],
        ],
    })

    if latency_data["Latency (ms)"].sum() > 0:
        fig = px.bar(
            latency_data,
            x="Percentile",
            y="Latency (ms)",
            color="Percentile",
            color_discrete_sequence=[COLORS["success"], COLORS["warning"], COLORS["danger"]],
        )
        fig.update_layout(
            **CHART_LAYOUT,
            showlegend=False,
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No latency data available")

st.markdown("---")

# Endpoint statistics
st.subheader("Endpoint Statistics")
if endpoint_stats:
    # Error rate by endpoint chart
    st.write("**Error Rate by Endpoint**")
    endpoints_with_errors = [e for e in endpoint_stats if e["errors"] > 0]
    if endpoints_with_errors:
        df_errors = pd.DataFrame(endpoints_with_errors)
        fig = px.bar(
            df_errors,
            x="path",
            y="error_rate",
            color="error_rate",
            color_continuous_scale=["green", "yellow", "red"],
            labels={"path": "Endpoint", "error_rate": "Error Rate (%)"},
        )
        fig.update_layout(**CHART_LAYOUT)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.success("No endpoint errors in the selected time range")

    # Endpoint table
    st.write("**Detailed Statistics**")
    df = pd.DataFrame(endpoint_stats)
    df["error_rate"] = df["error_rate"].apply(lambda x: f"{x:.1f}%")
    df["avg_latency_ms"] = df["avg_latency_ms"].apply(lambda x: f"{x:.2f}")
    df["p95_latency_ms"] = df["p95_latency_ms"].apply(lambda x: f"{x:.2f}")
    df.columns = ["Endpoint", "Count", "Errors", "Error Rate", "Avg Latency (ms)", "P95 Latency (ms)"]

    st.dataframe(df, use_container_width=True, hide_index=True)
else:
    st.info("No endpoint data available")

st.markdown("---")

# Performance analysis
st.subheader("Performance Analysis")

col1, col2 = st.columns(2)

with col1:
    st.write("**Latency Health**")
    p99 = request_stats["latency_p99_ms"]
    if p99 < 100:
        st.success(f"Excellent: P99 latency is {format_latency(p99)}")
    elif p99 < 500:
        st.info(f"Good: P99 latency is {format_latency(p99)}")
    elif p99 < 1000:
        st.warning(f"Moderate: P99 latency is {format_latency(p99)}")
    else:
        st.error(f"Poor: P99 latency is {format_latency(p99)}")

with col2:
    st.write("**Error Health**")
    error_rate = request_stats["error_rate"]
    if error_rate == 0:
        st.success("No errors detected")
    elif error_rate < 1:
        st.info(f"Low error rate: {format_percentage(error_rate)}")
    elif error_rate < 5:
        st.warning(f"Elevated error rate: {format_percentage(error_rate)}")
    else:
        st.error(f"High error rate: {format_percentage(error_rate)}")

# Recommendations
if request_stats["error_rate"] > 5 or request_stats["latency_p99_ms"] > 1000:
    st.markdown("---")
    st.subheader("Recommendations")
    if request_stats["error_rate"] > 5:
        st.write("- Investigate error logs for root cause of high error rate")
        st.write("- Check database connectivity and query performance")
    if request_stats["latency_p99_ms"] > 1000:
        st.write("- Review slow endpoints for optimization opportunities")
        st.write("- Consider adding caching for frequently accessed data")
        st.write("- Monitor database query performance")
