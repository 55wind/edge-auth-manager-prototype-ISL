"""Device Management - View and manage registered devices"""
from __future__ import annotations

import streamlit as st
import pandas as pd

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils import api_get, api_post, auto_refresh_toggle, setup_auto_refresh

st.title("Device Management")

# Controls
col1, col2 = st.columns([3, 1])
with col2:
    auto_refresh = auto_refresh_toggle("devices_auto_refresh")
    if st.button("Refresh"):
        st.rerun()

setup_auto_refresh(auto_refresh)

# Fetch devices
try:
    devices = api_get("/device/list")
except Exception as e:
    st.error(f"Cannot reach manager API: {e}")
    st.stop()

# Summary metrics
pending = [d for d in devices if d["status"] == "PENDING"]
approved = [d for d in devices if d["status"] == "APPROVED"]
revoked = [d for d in devices if d["status"] == "REVOKED"]

m1, m2, m3, m4 = st.columns(4)
with m1:
    st.metric("Total Devices", len(devices))
with m2:
    st.metric("Pending", len(pending))
with m3:
    st.metric("Approved", len(approved))
with m4:
    st.metric("Revoked", len(revoked))

st.markdown("---")

# Filter controls
st.subheader("Device List")
filter_col1, filter_col2 = st.columns([1, 3])
with filter_col1:
    status_filter = st.selectbox(
        "Filter by status",
        ["All", "PENDING", "APPROVED", "REVOKED"],
        index=0,
    )

# Filter devices
filtered_devices = devices
if status_filter != "All":
    filtered_devices = [d for d in devices if d["status"] == status_filter]

# Display devices table
if filtered_devices:
    df = pd.DataFrame(filtered_devices)
    df = df[["namespace", "status", "agent_version", "last_seen"]]
    df.columns = ["Namespace", "Status", "Agent Version", "Last Seen"]

    # Color-code status
    def color_status(val):
        colors = {
            "PENDING": "background-color: #fff3cd",
            "APPROVED": "background-color: #d4edda",
            "REVOKED": "background-color: #f8d7da",
        }
        return colors.get(val, "")

    styled_df = df.style.applymap(color_status, subset=["Status"])
    st.dataframe(styled_df, use_container_width=True, hide_index=True)
else:
    st.info("No devices match the filter criteria")

st.markdown("---")

# Admin actions
st.subheader("Admin Actions")

if devices:
    ns = st.selectbox(
        "Select device namespace",
        [d["namespace"] for d in devices],
        key="device_namespace_select",
    )

    # Get selected device info
    selected_device = next((d for d in devices if d["namespace"] == ns), None)
    if selected_device:
        st.caption(f"Status: **{selected_device['status']}** | Version: {selected_device['agent_version']}")

    c1, c2, c3, c4, c5, c6 = st.columns(6)

    with c1:
        if st.button("Approve", disabled=selected_device and selected_device["status"] == "APPROVED"):
            try:
                api_post("/device/approve", {"namespace": ns})
                st.success(f"Approved: {ns}")
                st.rerun()
            except Exception as e:
                st.error(str(e))

    with c2:
        if st.button("Revoke", disabled=selected_device and selected_device["status"] == "REVOKED"):
            try:
                api_post("/device/revoke", {"namespace": ns})
                st.success(f"Revoked: {ns}")
                st.rerun()
            except Exception as e:
                st.error(str(e))

    with c3:
        if st.button("Issue Cert"):
            try:
                api_post("/cert/issue", {"namespace": ns})
                st.success(f"Cert issued for: {ns}")
                st.rerun()
            except Exception as e:
                st.error(str(e))

    with c4:
        if st.button("Renew Cert"):
            try:
                api_post("/cert/renew", {"namespace": ns})
                st.success(f"Cert renewed for: {ns}")
                st.rerun()
            except Exception as e:
                st.error(str(e))

    with c5:
        if st.button("Decommission", type="secondary"):
            try:
                api_post("/device/decommission", {"namespace": ns, "reason": "Admin decommission via dashboard"})
                st.success(f"Decommissioned: {ns}")
                st.rerun()
            except Exception as e:
                st.error(str(e))

    with c6:
        if st.button("Transfer", type="secondary"):
            st.session_state["show_transfer_form"] = True

    # Transfer form
    if st.session_state.get("show_transfer_form"):
        with st.form("transfer_form"):
            st.markdown(f"**Transfer device:** `{ns}`")
            new_site = st.text_input("New site (leave blank to keep current)")
            new_group = st.text_input("New group (leave blank to keep current)")
            transfer_reason = st.text_input("Reason for transfer", value="")
            submitted = st.form_submit_button("Submit Transfer")
            if submitted:
                payload = {"namespace": ns, "reason": transfer_reason or "Dashboard transfer"}
                if new_site:
                    payload["new_site"] = new_site
                if new_group:
                    payload["new_group"] = new_group
                try:
                    api_post("/device/transfer", payload)
                    st.success(f"Transferred: {ns}")
                    st.session_state["show_transfer_form"] = False
                    st.rerun()
                except Exception as e:
                    st.error(str(e))

    # Certificate status
    st.markdown("---")
    st.subheader("Certificate Status")
    try:
        cert_status = api_get("/cert/status", {"namespace": ns})
        cs1, cs2 = st.columns(2)
        with cs1:
            st.metric("Cert Status", cert_status.get("status", "UNKNOWN"))
        with cs2:
            not_after = cert_status.get("not_after", "N/A")
            st.metric("Expires", not_after[:10] if not_after and not_after != "N/A" else "N/A")
    except Exception:
        st.info("No certificate information available")

    # CRL (Certificate Revocation List)
    st.markdown("---")
    st.subheader("Certificate Revocation List (CRL)")
    try:
        crl_data = api_get("/cert/crl")
        crl_entries = crl_data.get("revoked_certs", [])
        if crl_entries:
            st.warning(f"{len(crl_entries)} revoked certificate(s)")
            crl_df = pd.DataFrame(crl_entries)
            st.dataframe(crl_df, use_container_width=True, hide_index=True)
        else:
            st.success("No revoked certificates in CRL")
    except Exception:
        st.info("CRL endpoint not available")
else:
    st.info("No devices registered yet")

# Stale devices section
st.markdown("---")
st.subheader("Stale Devices")
try:
    stale_devices = api_get("/metrics/devices/stale", {"hours": 24})
    if stale_devices:
        st.warning(f"{len(stale_devices)} device(s) haven't checked in for over 24 hours")
        stale_df = pd.DataFrame(stale_devices)
        stale_df = stale_df[["namespace", "last_seen", "hours_stale"]]
        stale_df.columns = ["Namespace", "Last Seen", "Hours Stale"]
        stale_df["Hours Stale"] = stale_df["Hours Stale"].apply(lambda x: f"{x:.1f}")
        st.dataframe(stale_df, use_container_width=True, hide_index=True)
    else:
        st.success("All approved devices are active")
except Exception:
    st.info("Stale device detection not available")

# RabbitMQ info
st.markdown("---")
st.subheader("Message Bus (RabbitMQ)")
st.write("RabbitMQ Management UI: http://localhost:15672")
st.write("Queue: `agent.metadata` (TLS AMQP on port 5671)")
st.info("Default guest user has been removed for security. Use isl credentials.")
