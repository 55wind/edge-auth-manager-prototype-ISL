"""Authentication Metrics - Success/failure rates and analysis"""
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
    format_percentage, COLORS, CHART_LAYOUT,
)

st.title("Authentication Metrics")

# Controls
col1, col2, col3 = st.columns([2, 1, 1])
with col2:
    hours = time_range_selector("auth_time_range")
with col3:
    auto_refresh = auto_refresh_toggle("auth_auto_refresh")

setup_auto_refresh(auto_refresh)

# Fetch data
try:
    auth_stats = api_get("/metrics/auth", {"hours": hours})
    hourly_auth = api_get("/metrics/auth/hourly", {"hours": hours})
    device_auth = api_get("/metrics/auth/devices", {"hours": hours})
except Exception as e:
    st.error(f"Cannot reach manager API: {e}")
    st.stop()

# Summary metrics
st.subheader("Authentication Summary")
m1, m2, m3, m4 = st.columns(4)

with m1:
    st.metric("Total Attempts", f"{auth_stats['total_attempts']:,}")
with m2:
    st.metric("Successes", f"{auth_stats['successes']:,}")
with m3:
    st.metric("Failures", f"{auth_stats['failures']:,}")
with m4:
    color = "normal" if auth_stats["success_rate"] >= 95 else "inverse"
    st.metric("Success Rate", format_percentage(auth_stats["success_rate"]))

st.markdown("---")

# Charts row
chart1, chart2 = st.columns(2)

with chart1:
    st.subheader("Auth Events Over Time")
    if hourly_auth:
        df = pd.DataFrame(hourly_auth)
        fig = go.Figure()
        fig.add_trace(go.Bar(
            x=df["hour"],
            y=df["success"],
            name="Success",
            marker_color=COLORS["success"],
        ))
        fig.add_trace(go.Bar(
            x=df["hour"],
            y=df["failure"],
            name="Failure",
            marker_color=COLORS["danger"],
        ))
        fig.update_layout(
            **CHART_LAYOUT,
            barmode="stack",
            xaxis_title="Time",
            yaxis_title="Events",
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No auth events in the selected time range")

with chart2:
    st.subheader("Failure Reasons")
    failure_reasons = auth_stats.get("failure_reasons", {})
    if failure_reasons:
        df = pd.DataFrame({
            "Reason": list(failure_reasons.keys()),
            "Count": list(failure_reasons.values()),
        })
        fig = px.pie(
            df,
            values="Count",
            names="Reason",
            color_discrete_sequence=px.colors.qualitative.Set2,
        )
        fig.update_layout(**CHART_LAYOUT)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.success("No authentication failures")

st.markdown("---")

# Event type breakdown
st.subheader("Events by Type")
by_type = auth_stats.get("by_event_type", {})
if by_type:
    type_cols = st.columns(len(by_type))
    for i, (event_type, count) in enumerate(by_type.items()):
        with type_cols[i]:
            st.metric(event_type.replace("_", " ").title(), count)
else:
    st.info("No events recorded")

st.markdown("---")

# Per-device statistics
st.subheader("Per-Device Authentication Stats")
if device_auth:
    df = pd.DataFrame(device_auth)
    df["success_rate"] = df["success_rate"].apply(lambda x: f"{x:.1f}%")
    df.columns = ["Namespace", "Total", "Successes", "Failures", "Success Rate"]

    # Color-code rows with high failure rates
    def highlight_failures(row):
        if row["Failures"] > 0:
            return ["background-color: #fff3cd"] * len(row)
        return [""] * len(row)

    styled_df = df.style.apply(highlight_failures, axis=1)
    st.dataframe(styled_df, use_container_width=True, hide_index=True)
else:
    st.info("No device-specific auth data available")

# Failure analysis
st.markdown("---")
st.subheader("Failure Analysis")

if auth_stats["failures"] > 0:
    failure_rate = (auth_stats["failures"] / auth_stats["total_attempts"] * 100) if auth_stats["total_attempts"] > 0 else 0

    if failure_rate > 10:
        st.error(f"High failure rate detected: {failure_rate:.1f}%")
        st.write("**Recommended actions:**")
        st.write("- Check for expired or revoked device certificates")
        st.write("- Verify device registration status")
        st.write("- Review network connectivity between agents and manager")
    elif failure_rate > 5:
        st.warning(f"Elevated failure rate: {failure_rate:.1f}%")
        st.write("Monitor for increasing trend and investigate if rate continues to rise.")
    else:
        st.success(f"Failure rate within normal range: {failure_rate:.1f}%")
else:
    st.success("No authentication failures in the selected time range")

# JWT Security Status
st.markdown("---")
st.subheader("JWT Security Status")

try:
    sec_config = api_get("/admin/security-config")
    j1, j2, j3, j4 = st.columns(4)
    with j1:
        st.metric("JWT Algorithm", sec_config.get("jwt_algorithm", "N/A"))
    with j2:
        st.metric("Token TTL", f"{sec_config.get('jwt_ttl_seconds', 'N/A')}s")
    with j3:
        st.metric("HMAC Algorithm", sec_config.get("hmac_algorithm", "N/A"))
    with j4:
        blocklist_count = sec_config.get("blocklist_namespaces", 0)
        st.metric("Blocked Tokens", blocklist_count)

    # Rotation info
    rotation_info = sec_config.get("jwt_secret_rotated_at")
    if rotation_info:
        st.info(f"Last JWT secret rotation: {rotation_info}")
    else:
        st.caption("No JWT secret rotation has been performed yet.")

    # RBAC matrix
    with st.expander("RBAC Permission Matrix"):
        try:
            rbac = api_get("/admin/rbac-matrix")
            for role, paths in rbac.items():
                st.markdown(f"**{role}**: {', '.join(f'`{p}`' for p in sorted(paths))}")
        except Exception:
            st.info("RBAC matrix not available")

except Exception:
    st.info("Security config endpoint not available")

# CRL/OCSP Section
st.markdown("---")
st.subheader("Certificate Revocation Check (CRL/OCSP)")

col_crl, col_ocsp = st.columns(2)

with col_crl:
    st.markdown("**CRL (Certificate Revocation List)**")
    try:
        crl_data = api_get("/cert/crl")
        revoked_count = crl_data.get("total", 0)
        st.metric("Revoked Certificates", revoked_count)
        if revoked_count > 0:
            with st.expander(f"View {revoked_count} revoked certificates"):
                for cert in crl_data.get("revoked_certificates", []):
                    st.text(f"• {cert['namespace']}")
        else:
            st.success("No revoked certificates")
    except Exception:
        st.info("CRL endpoint not available")

with col_ocsp:
    st.markdown("**OCSP (Online Certificate Status Protocol)**")
    ocsp_ns = st.text_input("Check namespace:", placeholder="default/site/group/device", key="ocsp_check")
    if ocsp_ns:
        try:
            ocsp_result = api_get("/cert/ocsp", {"namespace": ocsp_ns})
            resp = ocsp_result.get("ocsp_response", {})
            status = resp.get("status", "UNKNOWN")

            if status == "GOOD":
                st.success(f"Status: {status}")
            elif status == "REVOKED":
                st.error(f"Status: {status}")
            else:
                st.warning(f"Status: {status}")

            st.caption(f"Produced: {resp.get('produced_at', 'N/A')}")
        except Exception as e:
            st.error(f"OCSP check failed: {e}")
