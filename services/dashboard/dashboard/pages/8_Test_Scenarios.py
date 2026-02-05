"""Continuous Automated Test System - Recurring validation of all requirement areas."""
from __future__ import annotations

import hashlib
import os
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils import mtls_session, MANAGER_BASE_URL, ADMIN_TOKEN, COLORS, CHART_LAYOUT

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEVICE_A = {
    "domain": "default", "site": "test", "group": "scenarios",
    "device_id": "test-device-A",
    "hw_fingerprint": hashlib.sha256(b"test-device-A-hw").hexdigest(),
    "agent_version": "0.1.0-test",
}
DEVICE_B = {
    "domain": "default", "site": "test", "group": "scenarios",
    "device_id": "test-device-B",
    "hw_fingerprint": hashlib.sha256(b"test-device-B-hw").hexdigest(),
    "agent_version": "0.1.0-test",
}
NS_A = "default/test/scenarios/test-device-A"
NS_B = "default/test/scenarios/test-device-B"
NS_FAKE = "default/test/scenarios/nonexistent-device"

RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "rabbitmq")
RABBITMQ_MGMT_PORT = os.getenv("RABBITMQ_MGMT_PORT", "15672")
RABBITMQ_USER = os.getenv("RABBITMQ_USER", "isl")
RABBITMQ_PASS = os.getenv("RABBITMQ_EDGE_PASSWORD", "wjdqhqhghdusrntlf1!")
RABBITMQ_MGMT_URL = f"http://{RABBITMQ_HOST}:{RABBITMQ_MGMT_PORT}"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class TestResult:
    test_name: str
    category: str
    status: str  # PASS, FAIL, ERROR
    expected: str
    actual: str
    duration_ms: float
    timestamp: str
    error_detail: Optional[str] = None


@dataclass
class CycleResult:
    cycle_number: int
    timestamp: str
    results: List[TestResult] = field(default_factory=list)
    duration_s: float = 0.0

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.status == "PASS")

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if r.status == "FAIL")

    @property
    def errors(self) -> int:
        return sum(1 for r in self.results if r.status == "ERROR")

    @property
    def pass_rate(self) -> float:
        return (self.passed / self.total * 100) if self.total else 0.0


class ResultStore:
    """Bounded in-memory store for cycle results."""

    def __init__(self, maxlen: int = 100):
        self.cycles: deque[CycleResult] = deque(maxlen=maxlen)

    def add(self, cycle: CycleResult):
        self.cycles.append(cycle)

    @property
    def all_results(self) -> List[TestResult]:
        out = []
        for c in self.cycles:
            out.extend(c.results)
        return out

    @property
    def latest(self) -> Optional[CycleResult]:
        return self.cycles[-1] if self.cycles else None


# ---------------------------------------------------------------------------
# Helper: HTTP calls
# ---------------------------------------------------------------------------
def _post(session, path: str, body: dict | None = None, headers: dict | None = None):
    hdrs = {"X-Admin-Token": ADMIN_TOKEN}
    if headers:
        hdrs.update(headers)
    r = session.post(MANAGER_BASE_URL + path, json=body or {}, headers=hdrs, timeout=10)
    try:
        data = r.json()
    except Exception:
        data = {}
    return r.status_code, data


def _get(session, path: str, params: dict | None = None):
    r = session.get(
        MANAGER_BASE_URL + path,
        params=params,
        headers={"X-Admin-Token": ADMIN_TOKEN},
        timeout=10,
    )
    try:
        data = r.json()
    except Exception:
        data = {}
    return r.status_code, data


def _run_test(name: str, category: str, fn) -> TestResult:
    """Execute a test function and return a TestResult."""
    ts = datetime.utcnow().isoformat(timespec="seconds")
    t0 = time.perf_counter()
    try:
        passed, expected, actual = fn()
        dur = (time.perf_counter() - t0) * 1000
        return TestResult(
            test_name=name, category=category,
            status="PASS" if passed else "FAIL",
            expected=str(expected), actual=str(actual),
            duration_ms=round(dur, 1), timestamp=ts,
        )
    except Exception as e:
        dur = (time.perf_counter() - t0) * 1000
        return TestResult(
            test_name=name, category=category,
            status="ERROR", expected="no exception", actual=type(e).__name__,
            duration_ms=round(dur, 1), timestamp=ts,
            error_detail=str(e)[:200],
        )


# ---------------------------------------------------------------------------
# Test suites
# ---------------------------------------------------------------------------
def run_agent_security_tests(s) -> List[TestResult]:
    results = []
    cat = "Agent Security Module"

    def t_register_a():
        code, data = _post(s, "/device/register", DEVICE_A)
        return 200 <= code < 300, "2xx", code

    def t_register_b():
        code, data = _post(s, "/device/register", DEVICE_B)
        return 200 <= code < 300, "2xx", code

    def t_idempotent():
        code, _ = _post(s, "/device/register", DEVICE_A)
        return 200 <= code < 300, "2xx (idempotent)", code

    def t_dup_fingerprint():
        bad = {**DEVICE_A, "hw_fingerprint": hashlib.sha256(b"wrong-hw").hexdigest()}
        code, _ = _post(s, "/device/register", bad)
        return code == 409, "409", code

    def t_response_structure():
        _, data = _post(s, "/device/register", DEVICE_A)
        has_all = all(k in data for k in ("namespace", "status"))
        return has_all, "namespace+status present", str(list(data.keys())[:5])

    def t_ns_validation_reject():
        """Namespace segments with invalid chars should be rejected (422)."""
        bad_device = {**DEVICE_A, "device_id": "bad/slash"}
        code, _ = _post(s, "/device/register", bad_device)
        return code == 422, "422 (validation)", code

    def t_ns_validation_empty():
        """Empty namespace segment should be rejected (422)."""
        bad_device = {**DEVICE_A, "site": ""}
        code, _ = _post(s, "/device/register", bad_device)
        return code == 422, "422 (empty segment)", code

    results.append(_run_test("Register device-A", cat, t_register_a))
    results.append(_run_test("Register device-B", cat, t_register_b))
    results.append(_run_test("Idempotent re-registration", cat, t_idempotent))
    results.append(_run_test("Duplicate fingerprint detection", cat, t_dup_fingerprint))
    results.append(_run_test("Registration response structure", cat, t_response_structure))
    results.append(_run_test("Namespace validation (slash)", cat, t_ns_validation_reject))
    results.append(_run_test("Namespace validation (empty)", cat, t_ns_validation_empty))
    return results


def run_mtls_session_tests(s) -> List[TestResult]:
    results = []
    cat = "Async/mTLS/Session"

    def t_healthcheck():
        code, data = _get(s, "/healthz")
        return code == 200 and data.get("ok") is True, "200+ok=True", f"{code},ok={data.get('ok')}"

    def t_session_reuse():
        codes = []
        for _ in range(5):
            c, _ = _get(s, "/healthz")
            codes.append(c)
        all_ok = all(c == 200 for c in codes)
        return all_ok, "5x200", str(codes)

    def t_no_mtls():
        import requests as req
        try:
            req.get(MANAGER_BASE_URL + "/healthz", timeout=5, verify=False)
            return False, "connection error", "connected without mTLS"
        except Exception:
            return True, "connection error", "rejected"

    def t_concurrent():
        codes = []
        with ThreadPoolExecutor(max_workers=3) as pool:
            futs = [pool.submit(lambda: _get(s, "/healthz")) for _ in range(3)]
            for f in as_completed(futs):
                c, _ = f.result()
                codes.append(c)
        return all(c == 200 for c in codes), "3x200", str(codes)

    def t_latency():
        t0 = time.perf_counter()
        _get(s, "/healthz")
        ms = (time.perf_counter() - t0) * 1000
        return ms < 2000, "<2000ms", f"{ms:.0f}ms"

    def t_correlation_id():
        """Request should return X-Request-Id header."""
        r = s.get(MANAGER_BASE_URL + "/healthz",
                  headers={"X-Admin-Token": ADMIN_TOKEN, "X-Request-Id": "test-trace-123"},
                  timeout=10)
        rid = r.headers.get("X-Request-Id", "")
        return rid == "test-trace-123", "test-trace-123", rid

    results.append(_run_test("mTLS healthcheck", cat, t_healthcheck))
    results.append(_run_test("Session reuse (5 requests)", cat, t_session_reuse))
    results.append(_run_test("mTLS cert required", cat, t_no_mtls))
    results.append(_run_test("Concurrent requests (3)", cat, t_concurrent))
    results.append(_run_test("Response latency <2s", cat, t_latency))
    results.append(_run_test("Correlation ID propagation", cat, t_correlation_id))
    return results


def run_auth_module_tests(s) -> List[TestResult]:
    results = []
    cat = "Auth Module APIs"

    # Approve device-A
    def t_approve_a():
        code, _ = _post(s, "/device/approve", {"namespace": NS_A})
        return 200 <= code < 300, "2xx", code

    results.append(_run_test("Approve device-A", cat, t_approve_a))

    # Get token for approved device-A
    token_a = [""]

    def t_token_a():
        code, data = _post(s, "/auth/token", {"namespace": NS_A})
        token_a[0] = data.get("access_token", "")
        return code == 200 and bool(token_a[0]), "200+token", f"{code},token={'yes' if token_a[0] else 'no'}"

    results.append(_run_test("Token for approved device", cat, t_token_a))

    def t_validate_good():
        code, data = _post(s, "/auth/validate", headers={"Authorization": f"Bearer {token_a[0]}"})
        return data.get("ok") is True, "ok=True", f"ok={data.get('ok')}"

    results.append(_run_test("Validate good token", cat, t_validate_good))

    def t_validate_bad():
        code, data = _post(s, "/auth/validate", headers={"Authorization": "Bearer invalid.token.here"})
        return data.get("ok") is False, "ok=False", f"ok={data.get('ok')}"

    results.append(_run_test("Validate bad token", cat, t_validate_bad))

    # Revoke device-B then try token
    def t_revoke_b():
        code, _ = _post(s, "/device/revoke", {"namespace": NS_B})
        return 200 <= code < 300, "2xx", code

    results.append(_run_test("Revoke device-B", cat, t_revoke_b))

    def t_token_revoked():
        code, _ = _post(s, "/auth/token", {"namespace": NS_B})
        return code == 403, "403", code

    results.append(_run_test("Token for revoked device", cat, t_token_revoked))

    def t_token_fake():
        code, _ = _post(s, "/auth/token", {"namespace": NS_FAKE})
        return code == 404, "404", code

    results.append(_run_test("Token for non-existent device", cat, t_token_fake))

    def t_admin_required():
        r = s.post(MANAGER_BASE_URL + "/device/approve", json={"namespace": NS_A}, timeout=10)
        return r.status_code in (401, 403), "401/403", r.status_code

    results.append(_run_test("Admin auth required", cat, t_admin_required))

    # Cert lifecycle
    def t_cert_issue():
        code, data = _post(s, "/cert/issue", {"namespace": NS_A})
        return 200 <= code < 300 and data.get("status") == "ISSUED", "ISSUED", f"{code},{data.get('status')}"

    results.append(_run_test("Cert issue", cat, t_cert_issue))

    def t_cert_status():
        code, data = _get(s, "/cert/status", {"namespace": NS_A})
        return data.get("status") == "ISSUED", "ISSUED", data.get("status")

    results.append(_run_test("Cert status", cat, t_cert_status))

    def t_cert_renew():
        code, data = _post(s, "/cert/renew", {"namespace": NS_A})
        return 200 <= code < 300 and data.get("status") == "ISSUED", "ISSUED", f"{code},{data.get('status')}"

    results.append(_run_test("Cert renew", cat, t_cert_renew))

    def t_cert_revoke():
        code, data = _post(s, "/cert/revoke", {"namespace": NS_A})
        return data.get("status") == "REVOKED", "REVOKED", data.get("status")

    results.append(_run_test("Cert revoke", cat, t_cert_revoke))

    # CRL endpoint
    def t_cert_crl():
        code, data = _get(s, "/cert/crl")
        return code == 200 and "revoked_certificates" in data, "200+revoked_certificates", f"{code},{list(data.keys())[:3]}"

    results.append(_run_test("CRL endpoint", cat, t_cert_crl))

    # RBAC matrix
    def t_rbac_matrix():
        code, data = _get(s, "/admin/rbac-matrix")
        return code == 200 and "admin" in data and "agent" in data, "admin+agent roles", f"{code},{list(data.keys())}"

    results.append(_run_test("RBAC matrix endpoint", cat, t_rbac_matrix))

    # Security config
    def t_security_config():
        code, data = _get(s, "/admin/security-config")
        has_fields = all(k in data for k in ("jwt_issuer", "jwt_ttl_seconds", "hmac_algorithm", "rbac_roles"))
        return code == 200 and has_fields, "200+config fields", f"{code},{list(data.keys())[:5]}"

    results.append(_run_test("Security config endpoint", cat, t_security_config))

    # Device decommission
    def t_decommission():
        # Re-register device-B first (it was revoked)
        _post(s, "/device/register", DEVICE_B)
        code, data = _post(s, "/device/decommission", {
            "namespace": NS_B, "reason": "end-of-life test"
        })
        return code == 200 and data.get("status") == "DECOMMISSIONED", "DECOMMISSIONED", f"{code},{data.get('status')}"

    results.append(_run_test("Device decommission", cat, t_decommission))

    # Device transfer
    def t_transfer():
        # Re-register device-B (was decommissioned)
        _post(s, "/device/register", DEVICE_B)
        _post(s, "/device/approve", {"namespace": NS_B})
        code, data = _post(s, "/device/transfer", {
            "namespace": NS_B, "new_site": "warehouse", "reason": "relocation test"
        })
        return code == 200 and "new_namespace" in data, "200+new_namespace", f"{code},{data.get('new_namespace', '')}"

    results.append(_run_test("Device transfer", cat, t_transfer))

    return results


def run_message_bus_tests() -> List[TestResult]:
    import requests as req
    results = []
    cat = "Message Bus"
    auth = (RABBITMQ_USER, RABBITMQ_PASS)

    def t_rmq_health():
        r = req.get(f"{RABBITMQ_MGMT_URL}/api/healthchecks/node", auth=auth, timeout=10)
        data = r.json() if r.ok else {}
        return r.ok and data.get("status") == "ok", "status=ok", f"{r.status_code},{data.get('status')}"

    def t_queue_exists():
        r = req.get(f"{RABBITMQ_MGMT_URL}/api/queues", auth=auth, timeout=10)
        queues = r.json() if r.ok else []
        names = [q.get("name") for q in queues]
        return "agent.metadata" in names, "agent.metadata found", str(names[:5])

    def t_agent_active():
        with mtls_session() as s:
            code, data = _get(s, "/device/list")
        devices = data if isinstance(data, list) else []
        return len(devices) > 0, "devices>0", f"{len(devices)} devices"

    def t_stale():
        with mtls_session() as s:
            code, data = _get(s, "/metrics/devices/stale")
        stale = data if isinstance(data, list) else data.get("devices", []) if isinstance(data, dict) else []
        return len(stale) <= 5, "<=5 stale", f"{len(stale)} stale"

    def t_auth_metrics():
        with mtls_session() as s:
            code, data = _get(s, "/metrics/auth")
        total = data.get("total_attempts", 0) if isinstance(data, dict) else 0
        return total > 0, "total>0", f"total={total}"

    def t_rmq_tls():
        r = req.get(f"{RABBITMQ_MGMT_URL}/api/connections", auth=auth, timeout=10)
        conns = r.json() if r.ok else []
        if not conns:
            return True, "ssl conns or empty", "no connections"
        has_ssl = any(c.get("ssl") or c.get("peer_cert_subject") for c in conns)
        return has_ssl, "ssl=true", f"{len(conns)} conns, ssl={has_ssl}"

    def t_rmq_permissions():
        """Verify RabbitMQ user has restricted permissions (not .*)."""
        r = req.get(f"{RABBITMQ_MGMT_URL}/api/permissions", auth=auth, timeout=10)
        if not r.ok:
            return False, "permissions readable", f"HTTP {r.status_code}"
        perms = r.json() if r.ok else []
        for p in perms:
            if p.get("user") == RABBITMQ_USER:
                conf = p.get("configure", "")
                # Should be restricted (not .*)
                restricted = conf != ".*"
                return restricted, "restricted perms", f"configure={conf}"
        return False, f"{RABBITMQ_USER} found", "user not found"

    results.append(_run_test("RabbitMQ health", cat, t_rmq_health))
    results.append(_run_test("Queue exists (agent.metadata)", cat, t_queue_exists))
    results.append(_run_test("Agent devices active", cat, t_agent_active))
    results.append(_run_test("No stale devices", cat, t_stale))
    results.append(_run_test("Auth metrics activity", cat, t_auth_metrics))
    results.append(_run_test("RabbitMQ TLS connections", cat, t_rmq_tls))
    results.append(_run_test("RabbitMQ restricted permissions", cat, t_rmq_permissions))
    return results


# ---------------------------------------------------------------------------
# Full cycle runner
# ---------------------------------------------------------------------------
def run_full_cycle(cycle_number: int) -> CycleResult:
    ts = datetime.utcnow().isoformat(timespec="seconds")
    t0 = time.perf_counter()
    all_results: List[TestResult] = []

    with mtls_session() as s:
        all_results.extend(run_agent_security_tests(s))
        all_results.extend(run_mtls_session_tests(s))
        all_results.extend(run_auth_module_tests(s))

    all_results.extend(run_message_bus_tests())

    dur = time.perf_counter() - t0
    return CycleResult(
        cycle_number=cycle_number,
        timestamp=ts,
        results=all_results,
        duration_s=round(dur, 2),
    )


# ---------------------------------------------------------------------------
# Background test runner
# ---------------------------------------------------------------------------
class TestRunner:
    def __init__(self, store: ResultStore, interval: int = 30):
        self.store = store
        self.interval = interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._cycle_count = 0
        self.running = False

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        self.running = False

    def _loop(self):
        while not self._stop_event.is_set():
            self._cycle_count += 1
            try:
                cycle = run_full_cycle(self._cycle_count)
                self.store.add(cycle)
            except Exception:
                pass
            self._stop_event.wait(timeout=self.interval)


# ---------------------------------------------------------------------------
# Streamlit UI
# ---------------------------------------------------------------------------
st.set_page_config(page_title="Test Scenarios", layout="wide") if not hasattr(st, "_page_config_set") else None
st.title("Continuous Test Scenarios")
st.markdown("Automated recurring validation of all 4 requirement areas with historical tracking.")

# Session state init
if "result_store" not in st.session_state:
    st.session_state.result_store = ResultStore(maxlen=100)
if "test_runner" not in st.session_state:
    st.session_state.test_runner = TestRunner(st.session_state.result_store)

store: ResultStore = st.session_state.result_store
runner: TestRunner = st.session_state.test_runner

# --- Control panel ---
st.markdown("---")
ctrl1, ctrl2, ctrl3, ctrl4 = st.columns([2, 2, 2, 4])

with ctrl1:
    interval = st.number_input(
        "Interval (seconds)", min_value=10, max_value=300,
        value=30, step=10, disabled=runner.running,
        key="interval_input",
    )
    runner.interval = interval

with ctrl2:
    if runner.running:
        if st.button("Stop Testing", type="secondary", use_container_width=True):
            runner.stop()
            st.rerun()
    else:
        if st.button("Start Continuous Testing", type="primary", use_container_width=True):
            runner.start()
            st.rerun()

with ctrl3:
    if not runner.running:
        if st.button("Run Single Cycle", use_container_width=True):
            with st.spinner("Running..."):
                runner._cycle_count += 1
                cycle = run_full_cycle(runner._cycle_count)
                store.add(cycle)
            st.rerun()

with ctrl4:
    status_color = "green" if runner.running else "gray"
    status_text = "RUNNING" if runner.running else "STOPPED"
    st.markdown(f"**Status:** :{status_color}[{status_text}]")
    st.markdown(f"**Cycles completed:** {len(store.cycles)}")
    if store.latest:
        st.markdown(f"**Last run:** {store.latest.timestamp} ({store.latest.duration_s}s)")

# Auto-refresh while running
if runner.running:
    time.sleep(0.1)  # small yield
    if "last_auto_refresh" not in st.session_state:
        st.session_state.last_auto_refresh = time.time()
    if time.time() - st.session_state.last_auto_refresh >= 5:
        st.session_state.last_auto_refresh = time.time()
        st.rerun()

# --- Tabs ---
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "Current Cycle", "Historical Stats", "Category Breakdown", "Test Log", "Security Config",
])

# TAB 1: Current Cycle
with tab1:
    latest = store.latest
    if latest is None:
        st.info("No test results yet. Start testing or run a single cycle.")
    else:
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Total", latest.total)
        m2.metric("Passed", latest.passed)
        m3.metric("Failed", latest.failed)
        m4.metric("Errors", latest.errors)
        m5.metric("Pass Rate", f"{latest.pass_rate:.0f}%")

        rows = []
        for r in latest.results:
            rows.append({
                "Test": r.test_name,
                "Category": r.category,
                "Status": r.status,
                "Expected": r.expected,
                "Actual": r.actual,
                "Duration": f"{r.duration_ms:.0f}ms",
                "Error": r.error_detail or "",
            })
        df = pd.DataFrame(rows)

        def color_status(val):
            if val == "PASS":
                return "background-color: #d4edda; color: #155724"
            elif val == "FAIL":
                return "background-color: #f8d7da; color: #721c24"
            return "background-color: #fff3cd; color: #856404"

        styled = df.style.applymap(color_status, subset=["Status"])
        st.dataframe(styled, use_container_width=True, hide_index=True)

# TAB 2: Historical Stats
with tab2:
    if len(store.cycles) < 1:
        st.info("No historical data yet.")
    else:
        all_r = store.all_results
        total_all = len(all_r)
        pass_all = sum(1 for r in all_r if r.status == "PASS")
        fail_all = sum(1 for r in all_r if r.status == "FAIL")
        err_all = sum(1 for r in all_r if r.status == "ERROR")

        h1, h2, h3, h4, h5 = st.columns(5)
        h1.metric("Total Tests Run", total_all)
        h2.metric("Total Passed", pass_all)
        h3.metric("Total Failed", fail_all)
        h4.metric("Total Errors", err_all)
        h5.metric("Overall Pass Rate", f"{pass_all / total_all * 100:.1f}%" if total_all else "N/A")

        # Trend line chart
        if len(store.cycles) >= 2:
            st.subheader("Pass Rate Trend")
            cycle_nums = [c.cycle_number for c in store.cycles]
            pass_rates = [c.pass_rate for c in store.cycles]

            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=cycle_nums, y=pass_rates,
                mode="lines+markers",
                name="Pass Rate %",
                line=dict(color=COLORS["success"], width=2),
                marker=dict(size=6),
            ))
            fig.update_layout(
                xaxis_title="Cycle #",
                yaxis_title="Pass Rate (%)",
                yaxis=dict(range=[0, 105]),
                **CHART_LAYOUT,
            )
            st.plotly_chart(fig, use_container_width=True)

        # Cycle history table
        st.subheader("Cycle History")
        cycle_rows = []
        for c in reversed(store.cycles):
            cycle_rows.append({
                "Cycle": c.cycle_number,
                "Timestamp": c.timestamp,
                "Total": c.total,
                "Passed": c.passed,
                "Failed": c.failed,
                "Errors": c.errors,
                "Pass Rate": f"{c.pass_rate:.0f}%",
                "Duration": f"{c.duration_s}s",
            })
        st.dataframe(pd.DataFrame(cycle_rows), use_container_width=True, hide_index=True)

# TAB 3: Category Breakdown
with tab3:
    if len(store.cycles) < 1:
        st.info("No data yet.")
    else:
        all_r = store.all_results
        categories = sorted(set(r.category for r in all_r))
        cat_rows = []
        cat_rates = []
        for cat in categories:
            cat_results = [r for r in all_r if r.category == cat]
            t = len(cat_results)
            p = sum(1 for r in cat_results if r.status == "PASS")
            rate = p / t * 100 if t else 0
            cat_rows.append({
                "Category": cat,
                "Total": t,
                "Passed": p,
                "Failed": sum(1 for r in cat_results if r.status == "FAIL"),
                "Errors": sum(1 for r in cat_results if r.status == "ERROR"),
                "Pass Rate": f"{rate:.1f}%",
            })
            cat_rates.append(rate)

        st.dataframe(pd.DataFrame(cat_rows), use_container_width=True, hide_index=True)

        # Bar chart
        fig = go.Figure()
        bar_colors = [COLORS["success"] if r >= 80 else COLORS["warning"] if r >= 50 else COLORS["danger"] for r in cat_rates]
        fig.add_trace(go.Bar(
            x=categories, y=cat_rates,
            marker_color=bar_colors,
            text=[f"{r:.0f}%" for r in cat_rates],
            textposition="auto",
        ))
        fig.update_layout(
            yaxis_title="Pass Rate (%)",
            yaxis=dict(range=[0, 105]),
            **CHART_LAYOUT,
        )
        st.plotly_chart(fig, use_container_width=True)

# TAB 4: Test Log
with tab4:
    if len(store.cycles) < 1:
        st.info("No log entries yet.")
    else:
        all_r = store.all_results
        categories = sorted(set(r.category for r in all_r))

        f1, f2 = st.columns(2)
        with f1:
            status_filter = st.multiselect("Filter by status", ["PASS", "FAIL", "ERROR"], default=["PASS", "FAIL", "ERROR"])
        with f2:
            cat_filter = st.multiselect("Filter by category", categories, default=categories)

        filtered = [
            r for r in reversed(all_r)
            if r.status in status_filter and r.category in cat_filter
        ][:100]

        log_rows = []
        for r in filtered:
            log_rows.append({
                "Timestamp": r.timestamp,
                "Test": r.test_name,
                "Category": r.category,
                "Status": r.status,
                "Expected": r.expected,
                "Actual": r.actual,
                "Duration": f"{r.duration_ms:.0f}ms",
                "Error": r.error_detail or "",
            })

        if log_rows:
            df = pd.DataFrame(log_rows)

            def color_log_status(val):
                if val == "PASS":
                    return "background-color: #d4edda; color: #155724"
                elif val == "FAIL":
                    return "background-color: #f8d7da; color: #721c24"
                return "background-color: #fff3cd; color: #856404"

            styled = df.style.applymap(color_log_status, subset=["Status"])
            st.dataframe(styled, use_container_width=True, hide_index=True)
        else:
            st.info("No results match the selected filters.")

# TAB 5: Security Config
with tab5:
    st.subheader("Security Configuration & RBAC")
    st.markdown("Live security configuration retrieved from the manager API.")

    try:
        with mtls_session() as s:
            # Security config
            code, config = _get(s, "/admin/security-config")
            if code == 200:
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("JWT TTL", f"{config.get('jwt_ttl_seconds', '?')}s")
                c2.metric("Rotation Grace", f"{config.get('jwt_rotation_grace_seconds', '?')}s")
                c3.metric("HMAC Algorithm", config.get("hmac_algorithm", "?"))
                c4.metric("Blocklist Entries", config.get("blocklist_namespaces", 0))

                st.markdown("**JWT Configuration:**")
                st.json({
                    "issuer": config.get("jwt_issuer"),
                    "audience": config.get("jwt_audience"),
                    "ttl_seconds": config.get("jwt_ttl_seconds"),
                    "rotation_grace_seconds": config.get("jwt_rotation_grace_seconds"),
                    "last_rotation": config.get("jwt_secret_rotated_at", "never"),
                    "auto_approve": config.get("auto_approve"),
                })

            # RBAC matrix
            code, matrix = _get(s, "/admin/rbac-matrix")
            if code == 200:
                st.markdown("**RBAC Permission Matrix:**")
                for role, paths in matrix.items():
                    with st.expander(f"Role: **{role}** ({len(paths)} permissions)"):
                        for p in sorted(paths):
                            st.markdown(f"- `{p}`")

            # CRL
            code, crl = _get(s, "/cert/crl")
            if code == 200:
                st.markdown(f"**Certificate Revocation List:** {crl.get('total', 0)} revoked certificates")
                if crl.get("revoked_certificates"):
                    st.dataframe(
                        pd.DataFrame(crl["revoked_certificates"]),
                        use_container_width=True, hide_index=True,
                    )
    except Exception as e:
        st.error(f"Cannot reach manager API: {e}")
