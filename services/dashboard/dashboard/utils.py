"""Shared utilities for the KPI dashboard"""
from __future__ import annotations

import os
from typing import Any, Optional

import requests
import streamlit as st

MANAGER_BASE_URL = os.getenv("MANAGER_BASE_URL", "https://localhost:8443")
CERTS_DIR = os.getenv("CERTS_DIR", "./certs")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "dev-admin-token")

# Chart color scheme
COLORS = {
    "primary": "#1f77b4",
    "success": "#2ca02c",
    "warning": "#ff7f0e",
    "danger": "#d62728",
    "info": "#17becf",
    "pending": "#ff7f0e",
    "approved": "#2ca02c",
    "revoked": "#d62728",
    "critical": "#d62728",
    "high": "#ff7f0e",
    "medium": "#ffbb78",
    "low": "#98df8a",
}

# Plotly layout defaults
CHART_LAYOUT = {
    "margin": dict(l=40, r=40, t=40, b=40),
    "paper_bgcolor": "rgba(0,0,0,0)",
    "plot_bgcolor": "rgba(0,0,0,0)",
    "font": dict(size=12),
}


def mtls_session() -> requests.Session:
    """Create an mTLS session for API communication"""
    s = requests.Session()
    s.verify = os.path.join(CERTS_DIR, "admin", "ca.crt")
    s.cert = (
        os.path.join(CERTS_DIR, "admin", "client.crt"),
        os.path.join(CERTS_DIR, "admin", "client.key"),
    )
    return s


def api_get(path: str, params: Optional[dict] = None) -> Any:
    """Make a GET request to the Manager API"""
    with mtls_session() as s:
        r = s.get(
            MANAGER_BASE_URL + path,
            params=params,
            headers={"X-Admin-Token": ADMIN_TOKEN},
            timeout=10,
        )
        r.raise_for_status()
        return r.json()


def api_post(path: str, body: dict) -> Any:
    """Make a POST request to the Manager API"""
    with mtls_session() as s:
        r = s.post(
            MANAGER_BASE_URL + path,
            json=body,
            headers={"X-Admin-Token": ADMIN_TOKEN},
            timeout=10,
        )
        r.raise_for_status()
        return r.json()


def time_range_selector(key: str = "time_range") -> int:
    """Display a time range selector and return hours"""
    options = {
        "1 hour": 1,
        "6 hours": 6,
        "24 hours": 24,
        "7 days": 168,
    }
    selected = st.selectbox(
        "Time range",
        options=list(options.keys()),
        index=2,  # Default to 24 hours
        key=key,
    )
    return options[selected]


def auto_refresh_toggle(key: str = "auto_refresh") -> bool:
    """Display auto-refresh toggle"""
    return st.toggle("Auto-refresh (30s)", key=key)


def setup_auto_refresh(enabled: bool, interval_seconds: int = 30):
    """Set up auto-refresh using Streamlit's native rerun"""
    if enabled:
        import time
        if "last_refresh" not in st.session_state:
            st.session_state.last_refresh = time.time()

        elapsed = time.time() - st.session_state.last_refresh
        if elapsed >= interval_seconds:
            st.session_state.last_refresh = time.time()
            st.rerun()


def metric_card(label: str, value: Any, delta: Optional[str] = None, help_text: Optional[str] = None):
    """Display a metric card"""
    st.metric(label=label, value=value, delta=delta, help=help_text)


def format_percentage(value: float) -> str:
    """Format a percentage value"""
    return f"{value:.1f}%"


def format_latency(value: float) -> str:
    """Format a latency value in milliseconds"""
    if value < 1:
        return f"{value * 1000:.0f}us"
    elif value < 1000:
        return f"{value:.1f}ms"
    else:
        return f"{value / 1000:.2f}s"


def severity_badge(severity: str) -> str:
    """Return a colored badge for severity level"""
    colors = {
        "CRITICAL": ":red[CRITICAL]",
        "HIGH": ":orange[HIGH]",
        "MEDIUM": ":orange[MEDIUM]",
        "LOW": ":green[LOW]",
    }
    return colors.get(severity, severity)
