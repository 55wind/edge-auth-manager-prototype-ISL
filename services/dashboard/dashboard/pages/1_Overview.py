"""Overview Dashboard - Summary metrics and charts"""
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
    format_percentage, format_latency, COLORS, CHART_LAYOUT,
)

st.title("System Overview")

# Controls
col1, col2, col3 = st.columns([2, 1, 1])
with col2:
    hours = time_range_selector("overview_time_range")
with col3:
    auto_refresh = auto_refresh_toggle("overview_auto_refresh")

setup_auto_refresh(auto_refresh)

# Fetch data
try:
    overview = api_get("/metrics/overview")
    hourly_requests = api_get("/metrics/requests/hourly", {"hours": hours})
    system = api_get("/metrics/system")
except Exception as e:
    st.error(f"Cannot reach manager API: {e}")
    st.stop()

# Metric cards row
st.subheader("Key Metrics")
m1, m2, m3, m4, m5 = st.columns(5)

with m1:
    st.metric("Total Devices", overview["total_devices"])
with m2:
    st.metric("Approved", overview["approved_devices"], delta=None)
with m3:
    st.metric("API Requests (24h)", f"{overview['requests_24h']:,}")
with m4:
    st.metric("Auth Success Rate", format_percentage(overview["auth_success_rate"]))
with m5:
    incident_color = "inverse" if overview["active_incidents"] > 0 else "off"
    st.metric("Active Incidents", overview["active_incidents"], delta_color=incident_color)

st.markdown("---")

# Charts row
chart1, chart2 = st.columns(2)

with chart1:
    st.subheader("Device Status Distribution")
    device_data = pd.DataFrame({
        "Status": ["Approved", "Pending", "Revoked"],
        "Count": [
            overview["approved_devices"],
            overview["pending_devices"],
            overview["revoked_devices"],
        ],
    })

    if device_data["Count"].sum() > 0:
        fig = px.pie(
            device_data,
            values="Count",
            names="Status",
            color="Status",
            color_discrete_map={
                "Approved": COLORS["approved"],
                "Pending": COLORS["pending"],
                "Revoked": COLORS["revoked"],
            },
        )
        fig.update_layout(**CHART_LAYOUT)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No devices registered yet")

with chart2:
    st.subheader("Request Volume Over Time")
    if hourly_requests:
        df = pd.DataFrame(hourly_requests)
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df["hour"],
            y=df["total"],
            mode="lines+markers",
            name="Requests",
            fill="tozeroy",
            line=dict(color=COLORS["primary"]),
        ))
        fig.update_layout(
            **CHART_LAYOUT,
            xaxis_title="Time",
            yaxis_title="Requests",
            showlegend=False,
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No request data available yet")

st.markdown("---")

# System health
st.subheader("System Health")
h1, h2, h3 = st.columns(3)

with h1:
    uptime_hours = system.get("uptime_seconds", 0) / 3600
    if uptime_hours < 1:
        uptime_str = f"{system.get('uptime_seconds', 0) / 60:.1f} minutes"
    elif uptime_hours < 24:
        uptime_str = f"{uptime_hours:.1f} hours"
    else:
        uptime_str = f"{uptime_hours / 24:.1f} days"
    st.metric("Uptime", uptime_str)

with h2:
    st.metric("Avg Latency", format_latency(overview["avg_latency_ms"]))

with h3:
    status = system.get("status", "unknown")
    status_emoji = {"healthy": "OK", "degraded": "Warning", "unhealthy": "Error"}.get(status, status)
    st.metric("Status", status_emoji)

# Quick stats
st.markdown("---")
st.subheader("Quick Statistics")

q1, q2, q3, q4 = st.columns(4)
with q1:
    st.metric("Pending Approval", overview["pending_devices"])
with q2:
    st.metric("Revoked Devices", overview["revoked_devices"])
with q3:
    error_rate = 100 - overview["auth_success_rate"] if overview["auth_success_rate"] < 100 else 0
    st.metric("Auth Failure Rate", format_percentage(error_rate))
with q4:
    st.metric("Manager URL", st.session_state.get("manager_url", "Connected"))

# Security posture
st.markdown("---")
st.subheader("Security Posture")
try:
    sec_config = api_get("/admin/security-config")
    s1, s2, s3, s4, s5 = st.columns(5)
    with s1:
        st.metric("mTLS", "Enforced" if sec_config.get("mtls_required") else "Optional")
    with s2:
        st.metric("JWT TTL", f"{sec_config.get('jwt_ttl_seconds', '?')}s")
    with s3:
        st.metric("RBAC Roles", str(len(sec_config.get("rbac_roles", []))))
    with s4:
        st.metric("Blocked Tokens", sec_config.get("blocklist_entries", 0))
    with s5:
        rotation = sec_config.get("last_secret_rotation")
        st.metric("Last Rotation", rotation[:10] if rotation else "Never")
except Exception:
    st.info("Security config not available — manager may not support /admin/security-config")
