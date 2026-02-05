"""Security Incidents - View and manage security alerts"""
from __future__ import annotations

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils import (
    api_get, api_post, auto_refresh_toggle, setup_auto_refresh,
    severity_badge, COLORS, CHART_LAYOUT,
)

st.title("Security Incidents")

# Controls
col1, col2, col3 = st.columns([2, 1, 1])
with col2:
    days = st.selectbox(
        "Time range",
        options=[1, 3, 7, 14, 30],
        index=2,  # Default to 7 days
        format_func=lambda x: f"{x} day{'s' if x > 1 else ''}",
        key="security_days",
    )
with col3:
    auto_refresh = auto_refresh_toggle("security_auto_refresh")

setup_auto_refresh(auto_refresh)

# Fetch data
try:
    incident_counts = api_get("/metrics/security/counts", {"days": days})
    incidents_by_type = api_get("/metrics/security/by-type", {"days": days})
    incidents = api_get("/metrics/security", {"days": days})
except Exception as e:
    st.error(f"Cannot reach manager API: {e}")
    st.stop()

# Severity counters
st.subheader("Active Incidents by Severity")
m1, m2, m3, m4, m5 = st.columns(5)

with m1:
    critical = incident_counts.get("critical", 0)
    st.metric("Critical", critical)
    if critical > 0:
        st.error("Immediate attention required")
with m2:
    high = incident_counts.get("high", 0)
    st.metric("High", high)
with m3:
    medium = incident_counts.get("medium", 0)
    st.metric("Medium", medium)
with m4:
    low = incident_counts.get("low", 0)
    st.metric("Low", low)
with m5:
    total = incident_counts.get("total", 0)
    st.metric("Total Active", total)

st.markdown("---")

# Charts row
chart1, chart2 = st.columns(2)

with chart1:
    st.subheader("Incidents by Type")
    if incidents_by_type:
        df = pd.DataFrame(incidents_by_type)
        fig = px.bar(
            df,
            x="type",
            y="count",
            color="count",
            color_continuous_scale=["yellow", "orange", "red"],
            labels={"type": "Incident Type", "count": "Count"},
        )
        fig.update_layout(**CHART_LAYOUT)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.success("No incidents in the selected time range")

with chart2:
    st.subheader("Severity Distribution")
    severity_data = pd.DataFrame({
        "Severity": ["Critical", "High", "Medium", "Low"],
        "Count": [
            incident_counts.get("critical", 0),
            incident_counts.get("high", 0),
            incident_counts.get("medium", 0),
            incident_counts.get("low", 0),
        ],
    })

    if severity_data["Count"].sum() > 0:
        fig = px.pie(
            severity_data,
            values="Count",
            names="Severity",
            color="Severity",
            color_discrete_map={
                "Critical": COLORS["critical"],
                "High": COLORS["high"],
                "Medium": COLORS["medium"],
                "Low": COLORS["low"],
            },
        )
        fig.update_layout(**CHART_LAYOUT)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.success("No active incidents")

st.markdown("---")

# Filter options
st.subheader("Incident Log")
filter_col1, filter_col2 = st.columns([1, 3])
with filter_col1:
    show_resolved = st.checkbox("Show resolved", value=False)

# Filter incidents
filtered_incidents = incidents
if not show_resolved:
    filtered_incidents = [i for i in incidents if not i.get("resolved", False)]

# Incident list
if filtered_incidents:
    for incident in filtered_incidents:
        severity = incident.get("severity", "UNKNOWN")
        incident_type = incident.get("incident_type", "Unknown")
        description = incident.get("description", "No description")
        namespace = incident.get("namespace", "N/A")
        timestamp = incident.get("timestamp", "Unknown time")
        resolved = incident.get("resolved", False)
        incident_id = incident.get("id")

        # Severity color
        severity_colors = {
            "CRITICAL": "red",
            "HIGH": "orange",
            "MEDIUM": "yellow",
            "LOW": "green",
        }
        border_color = severity_colors.get(severity, "gray")

        with st.expander(
            f"**{severity}** - {incident_type} | {timestamp[:16]}",
            expanded=severity in ["CRITICAL", "HIGH"] and not resolved,
        ):
            col1, col2 = st.columns([3, 1])
            with col1:
                st.write(f"**Type:** {incident_type}")
                st.write(f"**Severity:** {severity_badge(severity)}")
                st.write(f"**Description:** {description}")
                st.write(f"**Namespace:** {namespace}")
                st.write(f"**Time:** {timestamp}")
                st.write(f"**Status:** {'Resolved' if resolved else 'Active'}")

            with col2:
                if not resolved and incident_id:
                    if st.button(f"Resolve", key=f"resolve_{incident_id}"):
                        try:
                            api_post(f"/metrics/incidents/{incident_id}/resolve", {})
                            st.success("Incident resolved")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Failed to resolve: {e}")
                elif resolved:
                    st.write(":white_check_mark: Resolved")
else:
    st.success("No incidents to display")

st.markdown("---")

# Incident types explanation
st.subheader("Incident Type Reference")
with st.expander("View incident type descriptions"):
    st.write("""
    **AUTH_FAILURE_BURST** - High volume of authentication failures detected in a short time period.
    This could indicate a brute force attack or misconfigured devices.

    **STALE_DEVICE** - An approved device has not checked in for an extended period.
    This could indicate a network issue, device failure, or the device being taken offline.

    **CERT_EXPIRED** - A device certificate has expired and needs renewal.

    **REVOKED_ACCESS_ATTEMPT** - A revoked device attempted to authenticate.
    This could indicate a compromised device or misconfiguration.

    **DEVICE_DECOMMISSIONED** - A device was decommissioned by an admin.
    The device is permanently removed from active service and all tokens are revoked.

    **DEVICE_TRANSFERRED** - A device was transferred to a new site or group.
    Namespace may have changed; previous tokens are revoked.

    **SUSPICIOUS_ACTIVITY** - Unusual patterns detected that don't fit other categories.
    """)

# Quick actions
st.subheader("Quick Actions")
qa1, qa2, qa3 = st.columns(3)

with qa1:
    if st.button("View All Devices"):
        st.switch_page("pages/2_Devices.py")

with qa2:
    if st.button("View Auth Metrics"):
        st.switch_page("pages/3_Authentication.py")

with qa3:
    if st.button("Refresh Data"):
        st.rerun()
