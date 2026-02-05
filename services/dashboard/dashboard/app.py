"""Edge Auth Manager Dashboard - Main Entry Point

This is a multi-page Streamlit application for monitoring and managing
the edge device authentication system.

Pages:
- Overview: Summary metrics and system health
- Devices: Device management (approve, revoke, certificates)
- Authentication: Auth success/failure rates and analysis
- API Performance: Request metrics and latency tracking
- Security: Security incident management
"""
from __future__ import annotations

import os

import streamlit as st

# Page configuration
st.set_page_config(
    page_title="Edge Auth Manager Dashboard",
    page_icon=":shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Sidebar navigation info
st.sidebar.title("Edge Auth Manager")
st.sidebar.write("Prototype Dashboard")
st.sidebar.markdown("---")

MANAGER_BASE_URL = os.getenv("MANAGER_BASE_URL", "https://localhost:8443")
st.sidebar.caption(f"Manager: {MANAGER_BASE_URL}")

# Main page content - redirect to Overview
st.title("Edge Auth Manager Dashboard")
st.write("Welcome to the Edge Auth Manager Dashboard (Prototype)")

st.markdown("""
### Quick Navigation

Use the sidebar to navigate between dashboard pages:

- **Overview** - System health, key metrics, and request volume charts
- **Devices** - Manage device registration, approval, and certificates
- **Authentication** - Monitor auth success/failure rates and trends
- **API Performance** - Track request latency and endpoint statistics
- **Security** - View and manage security incidents
- **Logs** - View API request logs and filter by path/status

### System Requirements

- **Linux**: CentOS 7.8 or later, Ubuntu 20.04 LTS or later
- **Docker**: version 28.4 or later
- **Kubernetes**: version 1.30 or later
- **IDE**: Visual Studio Code, PyCharm

### System Architecture

This dashboard monitors an edge device authentication system with:
- **mTLS-based** mutual authentication
- **JWT token** authorization with automatic refresh
- **RabbitMQ** message bus for device telemetry
- **SQLite** for device and metrics storage
""")

# Quick stats
st.markdown("---")
st.subheader("Quick Status")

from utils import api_get

try:
    overview = api_get("/metrics/overview")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Devices", overview["total_devices"])
    with col2:
        st.metric("Approved", overview["approved_devices"])
    with col3:
        st.metric("Requests (24h)", f"{overview['requests_24h']:,}")
    with col4:
        st.metric("Active Incidents", overview["active_incidents"])

    if overview["pending_devices"] > 0:
        st.warning(f"{overview['pending_devices']} device(s) pending approval. Go to Devices page to approve.")

    if overview["active_incidents"] > 0:
        st.error(f"{overview['active_incidents']} active security incident(s). Go to Security page to review.")

except Exception as e:
    st.warning(f"Could not fetch status: {e}")
    st.info("Make sure the Manager API is running and certificates are properly configured.")

st.markdown("---")
st.caption("Edge Auth Manager Prototype - KPI Dashboard v0.1.0")
