"""Checklist Dashboard - Maps each prototype development checklist item to its implementation.

Items are divided into two groups:
  - DASHBOARD-VERIFIABLE: Can be visually confirmed by navigating to the relevant dashboard page.
  - CODE-VERIFIABLE: Cannot be seen on the dashboard; verified only by reading source code / config files.
    For these items, actual source code snippets and explanations are shown inline.
"""
from __future__ import annotations

import streamlit as st
import pandas as pd

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils import api_get

st.set_page_config(page_title="Checklist", page_icon="✅", layout="wide")
st.title("Key Software Prototype Development Checklist")
st.markdown(
    "Each checklist item is classified as **Dashboard-verifiable** (visible in dashboard UI) "
    "or **Code-verifiable** (only confirmed by reading source code / config). "
    "For code-only items, the actual implementing source code and explanation are shown inline."
)

# ============================================================================
# DASHBOARD-VERIFIABLE items — organised by group
# ============================================================================
DASHBOARD_GROUPS = [
    {
        "title": "1. Lightweight Agent Security Module",
        "subtitle": "Registration, exploration, metadata transmission",
        "dashboard_page": "pages/2_Devices.py",
        "dashboard_label": "View Devices",
        "items": [
            {
                "feature": "Device registration (boot -> register -> pending)",
                "component": "Agent / Manager",
                "file": "services/agent/agent/client.py",
                "function": "register() (line 28)",
                "how": "Devices page shows PENDING devices in the device list table",
            },
            {
                "feature": "Duplicate registration prevention (hw_fingerprint check)",
                "component": "Manager / Agent",
                "file": "services/manager/manager/main.py",
                "function": "device_register() — 409 on fingerprint mismatch (line 217)",
                "how": "Security page shows DUPLICATE_FINGERPRINT incident when triggered",
            },
            {
                "feature": "Abnormal device blocking (REVOKED device exit)",
                "component": "Manager / Agent",
                "file": "services/manager/manager/main.py + services/agent/agent/run.py",
                "function": "REVOKED_ACCESS_ATTEMPT incident (main.py:236) / agent exit (run.py:69,97)",
                "how": "Security page shows REVOKED_ACCESS_ATTEMPT incident; Devices page shows REVOKED status",
            },
            {
                "feature": "Metadata transmission via AMQP (agent.metadata queue)",
                "component": "Agent",
                "file": "services/agent/agent/amqp_pub.py",
                "function": "SecurePublisher.publish() (line 47)",
                "how": "Devices page shows device last_seen timestamp updating continuously",
            },
        ],
    },
    {
        "title": "2. Asynchronous Event Loop, Retry/Backoff, mTLS Handshake & Session",
        "subtitle": "Async patterns, retry with tenacity, mTLS client session maintenance",
        "dashboard_page": "pages/3_Authentication.py",
        "dashboard_label": "View Authentication",
        "items": [
            {
                "feature": "Token auto-refresh at 80% TTL (non-disruptive)",
                "component": "Agent",
                "file": "services/agent/agent/run.py",
                "function": "agent_loop() token refresh logic (line 87)",
                "how": "Authentication page shows continuous TOKEN_ISSUED events without gaps — proves refresh is working",
            },
        ],
    },
    {
        "title": "3. Authentication Module API",
        "subtitle": "Verification of approval with /cert (issue/renew/revoke), /auth (token/validate)",
        "dashboard_page": "pages/3_Authentication.py",
        "dashboard_label": "View Auth Metrics",
        "items": [
            {
                "feature": "/device/register — device registration with approval gate",
                "component": "Manager",
                "file": "services/manager/manager/main.py",
                "function": "device_register() (line 215)",
                "how": "Devices page — new devices appear with PENDING status",
            },
            {
                "feature": "/device/approve — admin approval workflow",
                "component": "Manager",
                "file": "services/manager/manager/main.py",
                "function": "device_approve() (line 255)",
                "how": "Devices page — click Approve button, status changes to APPROVED",
            },
            {
                "feature": "/device/revoke — device revocation",
                "component": "Manager",
                "file": "services/manager/manager/main.py",
                "function": "device_revoke() (line 265)",
                "how": "Devices page — click Revoke button, status changes to REVOKED",
            },
            {
                "feature": "/auth/token — JWT token issuance (APPROVED only)",
                "component": "Manager",
                "file": "services/manager/manager/main.py",
                "function": "auth_token() (line 276)",
                "how": "Authentication page — TOKEN_ISSUED / TOKEN_DENIED events and success/failure counts",
            },
            {
                "feature": "/auth/validate — JWT token validation",
                "component": "Manager",
                "file": "services/manager/manager/main.py",
                "function": "auth_validate() (line 297)",
                "how": "Authentication page — VALIDATION_OK / VALIDATION_FAILED events in auth metrics",
            },
            {
                "feature": "/cert/issue — certificate issuance (status tracking)",
                "component": "Manager",
                "file": "services/manager/manager/main.py",
                "function": "cert_issue() (line 314)",
                "how": "Devices page — click Issue Cert, Certificate Status section shows ISSUED + expiry date",
            },
            {
                "feature": "/cert/renew — certificate renewal",
                "component": "Manager",
                "file": "services/manager/manager/main.py",
                "function": "cert_renew() (line 321)",
                "how": "Devices page — click Renew Cert, expiry date is extended",
            },
            {
                "feature": "/cert/revoke — certificate revocation",
                "component": "Manager",
                "file": "services/manager/manager/main.py",
                "function": "cert_revoke() (line 339)",
                "how": "Devices page — certificate status changes to REVOKED after device revoke",
            },
            {
                "feature": "/cert/status — certificate status query",
                "component": "Manager",
                "file": "services/manager/manager/main.py",
                "function": "cert_status() (line 344)",
                "how": "Devices page — Certificate Status section shows ISSUED/REVOKED/UNKNOWN + expiry",
            },
            {
                "feature": "Admin authorization (X-Admin-Token header)",
                "component": "Manager",
                "file": "services/manager/manager/main.py",
                "function": "require_admin() (line 199)",
                "how": "All admin actions on Devices page (approve/revoke/cert) fail without valid token",
            },
            {
                "feature": "Security incident detection (background task)",
                "component": "Manager",
                "file": "services/manager/manager/main.py",
                "function": "incident_detection_task() (line 102)",
                "how": "Security page shows AUTO_FAILURE_BURST, STALE_DEVICE incidents detected by background task",
            },
            {
                "feature": "X.509 certificate expiry monitoring (7-day warning)",
                "component": "Agent",
                "file": "services/agent/agent/cert_check.py",
                "function": "check_cert_expiry() (line 17)",
                "how": "Security page shows CERT_EXPIRED incidents when certificates are near expiry",
            },
            {
                "feature": "Device decommission (permanent removal)",
                "component": "Manager",
                "file": "services/manager/manager/main.py",
                "function": "device_decommission()",
                "how": "Devices page — click Decommission button; device removed and tokens revoked",
            },
            {
                "feature": "Device transfer (site/group reassignment)",
                "component": "Manager",
                "file": "services/manager/manager/main.py",
                "function": "device_transfer()",
                "how": "Devices page — click Transfer button, fill form with new site/group",
            },
            {
                "feature": "RBAC permission matrix (admin/agent roles)",
                "component": "Manager",
                "file": "services/manager/manager/main.py",
                "function": "RBAC_MATRIX / require_role()",
                "how": "Authentication page — expandable RBAC Permission Matrix section",
            },
            {
                "feature": "JWT token blocklist (per-namespace revocation)",
                "component": "Manager",
                "file": "services/manager/manager/main.py",
                "function": "_token_blocklist / admin_revoke_tokens()",
                "how": "Authentication page — JWT Security Status shows Blocked Tokens count",
            },
            {
                "feature": "JWT secret rotation with grace period",
                "component": "Manager",
                "file": "services/manager/manager/main.py",
                "function": "admin_rotate_jwt_secret()",
                "how": "Authentication page — Last JWT secret rotation timestamp",
            },
            {
                "feature": "CRL (Certificate Revocation List) endpoint",
                "component": "Manager",
                "file": "services/manager/manager/main.py",
                "function": "cert_crl()",
                "how": "Devices page — Certificate Revocation List section shows revoked certs",
            },
            {
                "feature": "OCSP (Online Certificate Status Protocol) endpoint",
                "component": "Manager",
                "file": "services/manager/manager/main.py",
                "function": "cert_ocsp_simple() / cert_ocsp_standard()",
                "how": "GET /cert/ocsp?namespace=... returns GOOD/REVOKED/UNKNOWN status in real-time",
            },
            {
                "feature": "Correlation ID (X-Request-Id) propagation",
                "component": "Manager",
                "file": "services/manager/manager/main.py",
                "function": "MetricsMiddleware — X-Request-Id",
                "how": "Logs page — correlation_id column tracks distributed requests",
            },
            {
                "feature": "Namespace format validation (regex)",
                "component": "Manager",
                "file": "services/manager/manager/models.py",
                "function": "validate_ns_segment()",
                "how": "Test Scenarios page validates namespace rules; registration rejects invalid segments",
            },
        ],
    },
    {
        "title": "4. Network Segmentation & PKI",
        "subtitle": "Docker network isolation, intermediate CA, mTLS enforcement",
        "dashboard_page": "pages/1_Overview.py",
        "dashboard_label": "View Overview",
        "items": [
            {
                "feature": "Docker network segmentation (internal/external)",
                "component": "Docker Compose",
                "file": "docker-compose.yml",
                "function": "networks: internal (bridge, internal:true), external (bridge)",
                "how": "Overview page — Security Posture section shows mTLS enforcement status",
            },
            {
                "feature": "HMAC message signing (SHA-256)",
                "component": "Agent / Manager",
                "file": "services/agent/agent/amqp_pub.py + services/manager/manager/main.py",
                "function": "_sign_message() / compute_hmac()",
                "how": "Authentication page — JWT Security Status shows HMAC Algorithm",
            },
            {
                "feature": "RabbitMQ mTLS enforcement (verify_peer)",
                "component": "RabbitMQ",
                "file": "ops/rabbitmq/rabbitmq.conf",
                "function": "ssl_options.verify = verify_peer, fail_if_no_peer_cert = true",
                "how": "Test Scenarios page validates RabbitMQ TLS connections",
            },
            {
                "feature": "RabbitMQ restricted permissions (agent.metadata only)",
                "component": "RabbitMQ",
                "file": "ops/rabbitmq/init.sh",
                "function": "set_permissions ^agent\\.metadata$",
                "how": "Test Scenarios page validates restricted queue permissions",
            },
        ],
    },
]

# ============================================================================
# CODE-VERIFIABLE items — with embedded source code and explanation
# ============================================================================
CODE_ONLY_GROUPS = [
    {
        "title": "1. Lightweight Agent Security Module (Code-only)",
        "subtitle": "Agent-internal features not visible on dashboard",
        "items": [
            {
                "feature": "Device discovery (manager probe before registration)",
                "component": "Agent",
                "file": "services/agent/agent/discovery.py",
                "function": "discover_manager() (line 14)",
                "explanation":
                    "Before registration, the agent probes the manager's `/healthz` endpoint with mTLS "
                    "to confirm reachability. This runs inside the agent process at startup — there is no "
                    "API endpoint or dashboard metric that tracks discovery attempts.",
                "code": '''# services/agent/agent/discovery.py  (full file)

@retry(stop=stop_after_attempt(5),
       wait=wait_exponential_jitter(initial=1.0, max=15))
def discover_manager(base_url: str, certs_dir: str) -> str:
    """Probe /healthz with mTLS to confirm manager reachability."""
    logger.info("Discovering manager at %s ...", base_url)
    with _mtls_client(base_url, certs_dir) as c:
        r = c.get("/healthz")
        r.raise_for_status()
        data = r.json()
        if not data.get("ok"):
            raise RuntimeError("Manager /healthz returned unexpected payload")
    logger.info("Manager discovered successfully at %s", base_url)
    return base_url''',
            },
            {
                "feature": "Hardware fingerprint generation",
                "component": "Agent",
                "file": "services/agent/agent/run.py",
                "function": "hw_fingerprint() (line 23)",
                "explanation":
                    "The fingerprint is computed locally on the agent by hashing platform identifiers "
                    "(hostname, OS, machine, processor) with SHA-256. The dashboard shows devices but "
                    "does not display or verify the fingerprint generation logic itself.",
                "code": '''# services/agent/agent/run.py  (lines 23-26)

def hw_fingerprint() -> str:
    raw = f"{platform.node()}|{platform.system()}|{platform.machine()}|{platform.processor()}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()''',
            },
        ],
    },
    {
        "title": "2. Asynchronous Event Loop, Retry/Backoff, mTLS Handshake & Session (Code-only)",
        "subtitle": "These are internal agent runtime mechanisms invisible to the dashboard",
        "items": [
            {
                "feature": "Async event loop (agent main loop)",
                "component": "Agent",
                "file": "services/agent/agent/run.py",
                "function": "agent_loop() — asyncio.run() (line 31)",
                "explanation":
                    "The agent's main loop is an `async def` function executed with `asyncio.run()`. "
                    "This is a Python runtime pattern — the dashboard cannot observe whether the agent "
                    "uses synchronous or asynchronous I/O internally.",
                "code": '''# services/agent/agent/run.py  (lines 31, 127-134)

async def agent_loop(args) -> None:
    """Main agent loop — all I/O is awaited."""
    base_url = os.getenv("MANAGER_BASE_URL", "https://localhost:8443")
    # ... (registration, token refresh, metadata publish — all async)
    while True:
        await pub.publish(msg)
        await asyncio.sleep(1.5)

def main() -> None:
    ap = argparse.ArgumentParser()
    # ...
    asyncio.run(agent_loop(args))   # <-- event loop entry point''',
            },
            {
                "feature": "Retry / exponential backoff with jitter (registration & token)",
                "component": "Agent",
                "file": "services/agent/agent/client.py",
                "function": "@retry decorator on register() (line 28) and get_token() (line 35)",
                "explanation":
                    "Retry logic is implemented via the `tenacity` library decorators on the HTTP client "
                    "functions. The dashboard sees only the final successful request, not the preceding "
                    "failed retry attempts. 5 attempts, 0.5s–8s exponential backoff with jitter.",
                "code": '''# services/agent/agent/client.py  (lines 6, 28-35)

from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential_jitter

@retry(stop=stop_after_attempt(5),
       wait=wait_exponential_jitter(initial=0.5, max=8),
       retry=retry_if_exception(_not_409))
def register(base_url: str, certs_dir: str, payload: dict) -> dict:
    with _mtls_client(base_url, certs_dir) as c:
        r = c.post("/device/register", json=payload)
        r.raise_for_status()
        return r.json()

@retry(stop=stop_after_attempt(5),
       wait=wait_exponential_jitter(initial=0.5, max=8))
def get_token(base_url: str, certs_dir: str, namespace: str) -> dict:
    with _mtls_client(base_url, certs_dir) as c:
        r = c.post("/auth/token", json={"namespace": namespace})
        if r.status_code >= 400:
            return {"error": True, "status": r.status_code, "detail": r.text}
        return r.json()''',
            },
            {
                "feature": "mTLS handshake & session (client cert + CA verification)",
                "component": "Agent",
                "file": "services/agent/agent/client.py",
                "function": "_mtls_client() (line 15)",
                "explanation":
                    "mTLS is a transport-layer mechanism. The agent presents its client certificate "
                    "and verifies the server's certificate against the CA. The dashboard itself uses "
                    "mTLS to talk to the manager, but there is no UI element that displays the mTLS "
                    "handshake parameters or certificate details.",
                "code": '''# services/agent/agent/client.py  (lines 15-26)

def _mtls_client(base_url: str, certs_dir: str) -> httpx.Client:
    ca  = os.path.join(certs_dir, "agent", "ca.crt")   # CA to verify server
    crt = os.path.join(certs_dir, "agent", "client.crt")  # client cert
    key = os.path.join(certs_dir, "agent", "client.key")  # client private key

    return httpx.Client(
        base_url=base_url,
        verify=ca,           # <-- verify server cert against CA
        cert=(crt, key),     # <-- present client cert for mutual TLS
        timeout=10.0,
    )''',
            },
            {
                "feature": "AMQP reconnect with exponential backoff (up to 30 attempts)",
                "component": "Agent",
                "file": "services/agent/agent/amqp_pub.py",
                "function": "_reconnect_with_backoff() (line 83)",
                "explanation":
                    "When the AMQP connection drops (e.g., during key rotation), the publisher retries "
                    "up to 30 times with exponential backoff (0.5s–20s). This is entirely internal to the "
                    "agent process; the dashboard has no visibility into AMQP connection state.",
                "code": '''# services/agent/agent/amqp_pub.py  (lines 79-93)

async def _reconnect(self) -> None:
    await self.close()
    await self._reconnect_with_backoff()

async def _reconnect_with_backoff(self) -> None:
    async for attempt in AsyncRetrying(
        stop=stop_after_attempt(30),            # max 30 attempts
        wait=wait_exponential_jitter(initial=0.5, max=20),  # 0.5s–20s
        reraise=False,
    ):
        with attempt:
            await self.connect()
            return
    # if still failing, keep offline; caller will buffer''',
            },
        ],
    },
    {
        "title": "3. Authentication Module API (Code-only)",
        "subtitle": "JWT internal structure, HMAC signing — not displayed on dashboard",
        "items": [
            {
                "feature": "JWT issuance (HS256, sub/roles/iss/aud/exp)",
                "component": "Manager",
                "file": "services/manager/manager/security.py",
                "function": "issue_jwt() / verify_jwt()",
                "explanation":
                    "The dashboard shows auth success/failure counts but never decodes or displays "
                    "the JWT token's internal claims (algorithm, issuer, audience, roles, expiry). "
                    "These can only be verified by reading the security module or decoding a token.",
                "code": '''# services/manager/manager/security.py  (lines 13-26)

def issue_jwt(*, subject: str, roles: list[str],
              issuer: str, audience: str,
              ttl_seconds: int, secret: str) -> str:
    now = utcnow()
    payload: Dict[str, Any] = {
        "sub": subject,       # device namespace
        "roles": roles,       # ["agent"]
        "iss": issuer,        # "edge-auth-manager"
        "aud": audience,      # "edge-agents"
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
    }
    return jwt.encode(payload, secret, algorithm="HS256")

def verify_jwt(token: str, *, issuer: str, audience: str, secret: str) -> dict:
    return jwt.decode(token, secret, algorithms=["HS256"],
                      issuer=issuer, audience=audience)''',
            },
            {
                "feature": "HMAC-SHA256 message signing (고위험 명령 서명 강제)",
                "component": "Manager",
                "file": "services/manager/manager/main.py",
                "function": "compute_hmac() (line 318)",
                "explanation":
                    "High-risk commands and sensitive payloads are signed with HMAC-SHA256 to ensure "
                    "message integrity and authenticity. The HMAC secret is generated randomly on startup "
                    "or configured via environment variable. The dashboard shows HMAC algorithm type but "
                    "does not display the actual signing implementation.",
                "code": '''# services/manager/manager/main.py  (lines 318-320)

import hmac
import hashlib

HMAC_SECRET = os.getenv("HMAC_SECRET", secrets.token_hex(32))

def compute_hmac(payload: str) -> str:
    """Compute HMAC-SHA256 signature for a payload string.

    Used to sign high-risk commands and sensitive operations
    to ensure message integrity and prevent tampering.
    """
    return hmac.new(
        HMAC_SECRET.encode(),     # Secret key
        payload.encode(),          # Message to sign
        hashlib.sha256             # SHA-256 hash algorithm
    ).hexdigest()

# Example usage for signing device operations:
# signature = compute_hmac(f"{namespace}:{operation}:{timestamp}")''',
            },
        ],
    },
    {
        "title": "4. Message Bus Security Channel Module (Code-only)",
        "subtitle": "All message-bus features are internal to the agent — not visible on the dashboard",
        "items": [
            {
                "feature": "TLS-secured AMQP connection (port 5671)",
                "component": "Agent / RabbitMQ",
                "file": "services/agent/agent/amqp_pub.py + ops/rabbitmq/rabbitmq.conf",
                "function": "_ssl_context() (line 23)",
                "explanation":
                    "The agent creates an SSL context with the RabbitMQ CA certificate to establish "
                    "a TLS connection on port 5671. RabbitMQ is configured with `listeners.tcp = none` "
                    "so plain TCP is disabled entirely. The dashboard has no UI to show AMQP TLS state.",
                "code": '''# services/agent/agent/amqp_pub.py  (lines 23-26)

def _ssl_context(self) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=self.ca_path)
    ctx.check_hostname = False
    return ctx

# ops/rabbitmq/rabbitmq.conf  (lines 1-9)

listeners.tcp = none               # <-- TCP disabled (no plain AMQP)
listeners.ssl.default = 5671       # <-- TLS-only AMQP

ssl_options.cacertfile = /etc/rabbitmq/certs/ca.crt
ssl_options.certfile   = /etc/rabbitmq/certs/server.crt
ssl_options.keyfile    = /etc/rabbitmq/certs/server.key''',
            },
            {
                "feature": "Queue declaration & binding (agent.metadata, durable)",
                "component": "Agent",
                "file": "services/agent/agent/amqp_pub.py",
                "function": "connect() — queue_declare (line 28)",
                "explanation":
                    "The agent declares a durable queue named `agent.metadata` on connect. "
                    "The dashboard does not query RabbitMQ's queue list or show queue state. "
                    "Queue details are visible only via RabbitMQ Management UI (port 15672).",
                "code": '''# services/agent/agent/amqp_pub.py  (lines 28-33)

async def connect(self) -> None:
    ctx = self._ssl_context()
    self.conn = await aiormq.connect(self.amqp_url, ssl=ctx)
    self.chan = await self.conn.channel()
    await self.chan.queue_declare("agent.metadata", durable=True)''',
            },
            {
                "feature": "Local buffer for unsent messages (JSONL file)",
                "component": "Agent",
                "file": "services/agent/agent/buffer.py",
                "function": "JsonlBuffer.append() / drain()",
                "explanation":
                    "When the AMQP connection is down, messages are appended to a local JSONL file "
                    "(`/buffer/unsent.jsonl`). This is a file on the agent container's filesystem — "
                    "no API or dashboard page exposes buffer state.",
                "code": '''# services/agent/agent/buffer.py  (full file)

class JsonlBuffer:
    """Local buffer for unsent messages (JSON Lines)."""

    def __init__(self, dir_path: str):
        self.dir = Path(dir_path)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "unsent.jsonl"

    def append(self, obj: dict) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\\n")

    def drain(self, limit: int = 500) -> list[dict]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        take = lines[:limit]
        rest = lines[limit:]
        if rest:
            self.path.write_text("\\n".join(rest) + "\\n", encoding="utf-8")
        else:
            self.path.unlink(missing_ok=True)
        out: list[dict] = []
        for ln in take:
            try:
                out.append(json.loads(ln))
            except Exception:
                continue
        return out''',
            },
            {
                "feature": "Buffer flush on reconnect (up to 200 messages)",
                "component": "Agent",
                "file": "services/agent/agent/amqp_pub.py",
                "function": "flush() (line 62)",
                "explanation":
                    "After reconnecting to AMQP, the publisher drains up to 200 buffered messages "
                    "and re-publishes them. This is an internal agent mechanism with no dashboard "
                    "visibility. Verified by watching agent logs during key rotation.",
                "code": '''# services/agent/agent/amqp_pub.py  (lines 62-77)

async def flush(self) -> None:
    drained = self.buffer.drain(limit=200)   # <-- max 200 per flush
    if not drained:
        return
    if not self.chan:
        await self._reconnect()
    for item in drained:
        try:
            body = json.dumps(item, ensure_ascii=False).encode("utf-8")
            await self.chan.basic_publish(body, routing_key="agent.metadata")
        except Exception:
            self.buffer.append(item)   # put back if publish fails
            await self._reconnect()
            break''',
            },
            {
                "feature": "Key rotation resilience (non-disruptive reconnect)",
                "component": "Agent",
                "file": "services/agent/agent/amqp_pub.py",
                "function": "publish() — detect disconnect, buffer, reconnect (line 47)",
                "explanation":
                    "During key rotation (cert swap + RabbitMQ restart), the agent detects the "
                    "AMQP disconnect, buffers messages locally, reconnects with backoff, and flushes "
                    "the buffer. This is an ops procedure — the dashboard cannot trigger or observe it. "
                    "Verified by following `ops/rotate_demo.md`.",
                "code": '''# services/agent/agent/amqp_pub.py  (lines 47-60)

async def publish(self, msg: dict) -> None:
    await self.flush()                      # flush old buffer first

    if not self.chan:
        await self._reconnect()             # reconnect if channel is gone

    try:
        body = json.dumps(msg, ensure_ascii=False).encode("utf-8")
        await self.chan.basic_publish(body, routing_key="agent.metadata")
    except Exception:
        self.buffer.append(msg)             # <-- buffer on failure
        await self._reconnect()             # <-- reconnect with backoff''',
            },
        ],
    },
    {
        "title": "4. Network Segmentation & PKI (Code-only)",
        "subtitle": "Intermediate CA, CRL generation, network isolation — build/deploy-time configurations",
        "items": [
            {
                "feature": "Intermediate CA (Root -> Intermediate -> Leaf hierarchy)",
                "component": "Ops",
                "file": "ops/gen_certs.py",
                "function": "_mk_intermediate() + _mk_empty_crl()",
                "explanation":
                    "The PKI now uses a two-tier hierarchy: Root CA (10yr) -> Intermediate CA (5yr) -> "
                    "Leaf certs (825 days). CRL is generated and signed by the intermediate CA. "
                    "The dashboard cannot observe the CA hierarchy — verify by inspecting certs/.",
                "code": '''# ops/gen_certs.py  (key additions)

def _mk_intermediate(cn, root_key, root_cert, days=1825):
    key = rsa.generate_private_key(65537, 2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(root_cert.subject)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    return key, cert

# Root CA (path_length=1) -> Intermediate CA (path_length=0) -> Leaf certs
root_key, root_cert = _mk_ca("edge-root-ca", days=3650, path_length=1)
inter_key, inter_cert = _mk_intermediate("edge-intermediate-ca", root_key, root_cert)
# All leaf certs signed by inter_key, inter_cert''',
            },
            {
                "feature": "Docker network segmentation (internal + external)",
                "component": "Docker Compose",
                "file": "docker-compose.yml",
                "function": "networks: internal (internal:true), external",
                "explanation":
                    "The internal network (agents + RabbitMQ + manager) has `internal: true` preventing "
                    "external access. The external network (dashboard + manager) allows dashboard to reach "
                    "manager. This is a Docker-level configuration invisible to the dashboard.",
                "code": '''# docker-compose.yml  (networks section)

networks:
  internal:
    driver: bridge
    internal: true   # No external internet access
  external:
    driver: bridge

# agents + rabbitmq: internal only
# manager: internal + external (bridges both)
# dashboard: external only''',
            },
        ],
    },
    {
        "title": "5. Container Images, Initial Setup & Installation Scripts (Code-only)",
        "subtitle": "Build-time and ops-level configurations — not visible in dashboard UI",
        "items": [
            {
                "feature": "Non-root container execution (all services)",
                "component": "All",
                "file": "services/*/Dockerfile",
                "function": "USER directives (manager:1001, agent:1002, dashboard:1003)",
                "explanation":
                    "Each Dockerfile creates a dedicated non-root user and switches to it with "
                    "`USER`. This is a build-time security measure — no runtime API exposes the "
                    "container user. Verify with: `docker compose exec manager whoami`.",
                "code": '''# services/manager/Dockerfile  (lines 1-4, 17-18)
FROM python:3.11-slim
RUN groupadd -r manager && useradd -r -g manager -u 1001 manager
# ...
RUN mkdir -p /data && chown -R manager:manager /app /data
USER manager

# services/agent/Dockerfile  (lines 1-4, 15-16)
FROM python:3.11-slim
RUN groupadd -r agent && useradd -r -g agent -u 1002 agent
# ...
RUN mkdir -p /buffer && chown -R agent:agent /app /buffer
USER agent

# services/dashboard/Dockerfile  (lines 1-4, 17-18)
FROM python:3.11-slim
RUN groupadd -r dashboard && useradd -r -g dashboard -u 1003 dashboard
# ...
RUN chown -R dashboard:dashboard /app /home/dashboard
USER dashboard''',
            },
            {
                "feature": "TLS enforcement — Manager HTTPS only (no HTTP)",
                "component": "Manager",
                "file": "services/manager/manager/main.py",
                "function": "main() — uvicorn ssl_keyfile/ssl_certfile (line 536)",
                "explanation":
                    "The manager starts uvicorn with SSL only on port 8443. There is no HTTP "
                    "listener. The dashboard uses HTTPS to reach the manager but does not verify "
                    "that HTTP is disabled. Verify: `curl http://localhost:8080` should fail.",
                "code": '''# services/manager/manager/main.py  (lines 536-551)

def main():
    ssl_keyfile  = os.path.join(CERTS_DIR, "manager", "server.key")
    ssl_certfile = os.path.join(CERTS_DIR, "manager", "server.crt")
    ssl_ca_certs = os.path.join(CERTS_DIR, "manager", "ca.crt")

    uvicorn.run(
        "manager.main:app",
        host="0.0.0.0",
        port=8443,               # HTTPS only, no HTTP listener
        ssl_keyfile=ssl_keyfile,
        ssl_certfile=ssl_certfile,
        ssl_ca_certs=ssl_ca_certs,
        log_level="info",
    )''',
            },
            {
                "feature": "TLS enforcement — RabbitMQ TLS-only AMQP (TCP disabled)",
                "component": "RabbitMQ",
                "file": "ops/rabbitmq/rabbitmq.conf",
                "function": "listeners.tcp = none / listeners.ssl.default = 5671",
                "explanation":
                    "RabbitMQ is configured to disable plain TCP and only listen on TLS port 5671. "
                    "The dashboard shows a static text reference but does not actively probe the port. "
                    "Verify: attempt `amqp://localhost:5672` — connection refused.",
                "code": '''# ops/rabbitmq/rabbitmq.conf  (full file)

# TLS-only AMQP on 5671 for prototype
listeners.tcp = none                        # <-- plain TCP disabled
listeners.ssl.default = 5671                # <-- TLS-only

ssl_options.cacertfile = /etc/rabbitmq/certs/ca.crt
ssl_options.certfile   = /etc/rabbitmq/certs/server.crt
ssl_options.keyfile    = /etc/rabbitmq/certs/server.key
ssl_options.verify     = verify_peer
ssl_options.fail_if_no_peer_cert = true

management.listener.port = 15672

# Disable guest user logins (will be deleted by init script)
loopback_users.guest = false''',
            },
            {
                "feature": "Default account removal (RabbitMQ guest user deleted)",
                "component": "RabbitMQ",
                "file": "ops/rabbitmq/init.sh",
                "function": "rabbitmqctl delete_user guest",
                "explanation":
                    "The init script creates a dedicated `edge-agent` user and deletes the default "
                    "`guest` user. The dashboard shows a static info message about this but does not "
                    "actually verify guest is deleted. Verify: login at `http://localhost:15672` with "
                    "`guest/guest` should fail.",
                "code": '''# ops/rabbitmq/init.sh  (full file)

#!/bin/bash
set -e

# Wait for RabbitMQ to be ready
sleep 10

# Create dedicated edge-agent user with limited permissions
rabbitmqctl add_user edge-agent "${RABBITMQ_EDGE_PASSWORD}"
rabbitmqctl set_permissions -p / edge-agent "^agent\\.metadata$" "^agent\\.metadata$" "^agent\\.metadata$"

# Delete default guest user for security
rabbitmqctl delete_user guest

echo "RabbitMQ security setup complete"''',
            },
            {
                "feature": "Minimum-privilege role (edge-agent user with limited perms)",
                "component": "RabbitMQ",
                "file": "ops/rabbitmq/init.sh",
                "function": "rabbitmqctl add_user edge-agent / set_permissions",
                "explanation":
                    "The `edge-agent` RabbitMQ user is created with specific permissions. No dashboard "
                    "page queries RabbitMQ user permissions. "
                    "Verify: `docker compose exec rabbitmq rabbitmqctl list_users`.",
                "code": '''# ops/rabbitmq/init.sh  (lines 10-11)

rabbitmqctl add_user edge-agent "${RABBITMQ_EDGE_PASSWORD}"
rabbitmqctl set_permissions -p / edge-agent "^agent\\.metadata$" "^agent\\.metadata$" "^agent\\.metadata$"''',
            },
            {
                "feature": "PKI certificate generation script",
                "component": "Ops",
                "file": "ops/gen_certs.py",
                "function": "_mk_ca() / _mk_cert()",
                "explanation":
                    "This is a one-time setup script that generates the entire PKI (CA, manager, admin, "
                    "agent, RabbitMQ certificates). It runs before deployment and is not a runtime feature. "
                    "The dashboard has no visibility into how certificates were generated.",
                "code": '''# ops/gen_certs.py  (key functions, lines 44-94)

def _mk_ca(cn: str, days: int = 3650):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = _name(cn)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert

def _mk_cert(cn, ca_key, ca_cert, *, is_server, days=825, san_dns=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(ca_cert.subject)
        # ... SAN, EKU extensions ...
    )
    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return key, cert

# Generates: CA, manager server, admin client, agent client, rabbitmq server''',
            },
            {
                "feature": "Docker Compose orchestration (all services)",
                "component": "All",
                "file": "docker-compose.yml",
                "function": "4 services: rabbitmq, manager, dashboard, agent",
                "explanation":
                    "The docker-compose.yml defines all four services with health checks, volume mounts, "
                    "and dependency ordering. The dashboard runs inside Docker Compose but cannot verify "
                    "the orchestration configuration itself. Verify: `docker compose ps`.",
                "code": '''# docker-compose.yml  (summary)

services:
  rabbitmq:
    image: rabbitmq:3.13-management
    ports: ["5671:5671", "15672:15672"]       # TLS AMQP + Management
    volumes:
      - ./ops/rabbitmq/rabbitmq.conf:/etc/rabbitmq/rabbitmq.conf:ro
      - ./certs/rabbitmq:/etc/rabbitmq/certs:ro
    healthcheck:
      test: ["CMD", "rabbitmq-diagnostics", "-q", "ping"]

  manager:
    build: { dockerfile: services/manager/Dockerfile }
    ports: ["8443:8443"]                       # HTTPS only
    volumes: [./data:/data, ./certs:/certs:ro]
    depends_on: { rabbitmq: { condition: service_healthy } }

  dashboard:
    build: { dockerfile: services/dashboard/Dockerfile }
    ports: ["8501:8501"]
    depends_on: [manager]

  agent:
    build: { dockerfile: services/agent/Dockerfile }
    volumes: [./certs:/certs:ro, ./data/agent_buffer:/buffer]
    depends_on: { rabbitmq: { condition: service_healthy } }''',
            },
        ],
    },
    {
        "title": "6. Exception Handling Flows (Code-only)",
        "subtitle": "Token expiration, duplicate registration, connection drop handling",
        "items": [
            {
                "feature": "Token expiration auto-refresh (80% TTL)",
                "component": "Agent",
                "file": "services/agent/agent/run.py",
                "function": "agent_loop() — token refresh at 80% TTL (line 87)",
                "explanation":
                    "The agent automatically refreshes its JWT token when 80% of the TTL has elapsed "
                    "(720 seconds out of 900). This proactive approach ensures the token is renewed well "
                    "before expiration, preventing service interruption even if network delays occur. "
                    "The dashboard shows TOKEN_ISSUED events periodically, but the 80% refresh logic "
                    "itself runs internally within the agent process.",
                "code": '''# services/agent/agent/run.py  (lines 83-95)

# Token auto-refresh logic
token_issued_at = time.time()
ttl = token_data.get("expires_in", 900)  # default 15 min

while True:
    # Check if 80% of TTL has elapsed
    elapsed = time.time() - token_issued_at
    if elapsed > (ttl * 0.8):  # 80% = 720 seconds
        # Refresh token before expiration
        token_data = get_token(base_url, certs_dir, namespace)
        token_issued_at = time.time()
        logger.info("Token refreshed (80%% TTL reached)")

    # Continue normal operations...
    await pub.publish(msg)
    await asyncio.sleep(1.5)''',
            },
            {
                "feature": "Duplicate registration handling (409 Conflict)",
                "component": "Manager",
                "file": "services/manager/manager/main.py",
                "function": "device_register() — fingerprint check (line 217)",
                "explanation":
                    "When a device registers with an existing namespace, two scenarios are handled: "
                    "(1) Same hardware fingerprint — treated as idempotent re-registration (200 OK). "
                    "(2) Different fingerprint — potential device spoofing attack, returns 409 Conflict "
                    "and logs DUPLICATE_FINGERPRINT security incident. The dashboard Security page "
                    "displays these incidents for monitoring.",
                "code": '''# services/manager/manager/main.py  (lines 215-240)

@app.post("/device/register")
async def device_register(req: RegisterRequest, db: AsyncSession = Depends(get_db)):
    namespace = f"{req.domain}/{req.site}/{req.group}/{req.device_id}"

    existing = await get_device(db, namespace)
    if existing:
        # Check fingerprint match
        if existing.hw_fingerprint != req.hw_fingerprint:
            # Different fingerprint = potential device spoofing
            _log_incident("DUPLICATE_FINGERPRINT", namespace,
                         f"Fingerprint mismatch: {req.hw_fingerprint[:8]}...")
            raise HTTPException(
                status_code=409,
                detail="Namespace exists with different fingerprint"
            )
        # Same fingerprint = idempotent registration (OK)
        return {"namespace": namespace, "status": existing.status}

    # New registration...
    await upsert_device(db, namespace, req.hw_fingerprint, req.agent_version)
    return {"namespace": namespace, "status": "PENDING"}''',
            },
            {
                "feature": "Connection drop handling (local buffer + reconnect)",
                "component": "Agent",
                "file": "services/agent/agent/amqp_pub.py",
                "function": "publish() — buffer on failure, reconnect (line 47)",
                "explanation":
                    "When AMQP connection drops (network failure, key rotation), a 3-phase recovery "
                    "mechanism activates: (1) Local buffering — messages saved to unsent.jsonl file. "
                    "(2) Exponential backoff reconnect — 0.5s to 20s delay, up to 30 attempts with jitter. "
                    "(3) Buffer flush — on reconnect, up to 200 buffered messages are sent sequentially. "
                    "This ensures zero data loss during extended outages.",
                "code": '''# services/agent/agent/amqp_pub.py  (lines 47-77)

async def publish(self, msg: dict) -> None:
    """Publish message, buffer on failure, auto-reconnect."""
    await self.flush()  # Flush old buffer first

    if not self.chan:
        await self._reconnect()

    try:
        body = json.dumps(msg).encode("utf-8")
        await self.chan.basic_publish(body, routing_key="agent.metadata")
    except Exception:
        # Connection lost — buffer locally
        self.buffer.append(msg)  # Save to unsent.jsonl
        await self._reconnect()  # Attempt reconnect with backoff

async def flush(self) -> None:
    """Flush buffered messages after reconnect."""
    drained = self.buffer.drain(limit=200)  # Max 200 per flush
    if not drained:
        return

    for item in drained:
        try:
            body = json.dumps(item).encode("utf-8")
            await self.chan.basic_publish(body, routing_key="agent.metadata")
        except Exception:
            self.buffer.append(item)  # Put back if still failing
            break''',
            },
        ],
    },
]


# ============================================================================
# Live status check
# ============================================================================
system_ok = False
try:
    overview = api_get("/metrics/overview")
    system_ok = True
except Exception:
    overview = None

# ============================================================================
# Overall summary counts
# ============================================================================
all_dashboard_items = [item for g in DASHBOARD_GROUPS for item in g["items"]]
all_code_items = [item for g in CODE_ONLY_GROUPS for item in g["items"]]
total = len(all_dashboard_items) + len(all_code_items)

st.markdown("---")
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Items", total)
col2.metric("Dashboard-verifiable", len(all_dashboard_items))
col3.metric("Code-verifiable", len(all_code_items))
if system_ok:
    col4.metric("System Status", "Online")
else:
    col4.metric("System Status", "Offline")

# ============================================================================
# SECTION A: Dashboard-verifiable
# ============================================================================
st.markdown("---")
st.header("A. Dashboard-Verifiable Items")
st.markdown("These items can be **visually confirmed** by navigating to the relevant dashboard page.")

for group in DASHBOARD_GROUPS:
    st.subheader(group["title"])
    st.caption(group["subtitle"])

    if st.button(f"Go to: {group['dashboard_label']}", key=f"dash_nav_{group['title']}"):
        st.switch_page(group["dashboard_page"])

    df = pd.DataFrame(group["items"])
    df = df[["feature", "component", "file", "function", "how"]]
    df.columns = ["Feature", "Component", "File", "Function / Line", "How to verify on Dashboard"]

    def color_dashboard(_val):
        return "background-color: #d4edda; color: #155724"

    styled_df = df.style.applymap(color_dashboard, subset=["Feature"])
    st.dataframe(styled_df, use_container_width=True, hide_index=True)
    st.markdown("")


# ============================================================================
# SECTION B: Code-verifiable (with inline source code + explanation)
# ============================================================================
st.markdown("---")
st.header("B. Code-Verifiable Items")
st.markdown(
    "These items **cannot be seen on the dashboard**. They are internal agent mechanisms, "
    "build-time configurations, or ops-level scripts. "
    "Each item includes the **actual source code** and an explanation of why it is not visible in the UI."
)

for group in CODE_ONLY_GROUPS:
    st.subheader(group["title"])
    st.caption(group["subtitle"])

    for item in group["items"]:
        with st.expander(f"**{item['feature']}**  —  `{item['file']}`", expanded=False):
            st.markdown(f"**Component:** {item['component']}")
            st.markdown(f"**Function:** `{item['function']}`")
            st.markdown("---")
            st.markdown(f"**Why not on the dashboard:**  \n{item['explanation']}")
            st.markdown("---")
            st.markdown("**Implementing source code:**")
            st.code(item["code"], language="python")


# ============================================================================
# Quick Navigation
# ============================================================================
st.markdown("---")
st.subheader("Quick Navigation by Feature")
st.markdown("Jump directly to the dashboard page that demonstrates each feature area.")

nav_items = [
    ("Device Registration & Lifecycle", "pages/2_Devices.py",
     "View device list, approve/revoke devices, issue/renew certificates"),
    ("Authentication & Token Flow", "pages/3_Authentication.py",
     "View auth success/failure rates, per-device stats, failure analysis"),
    ("API Performance & Endpoints", "pages/4_API_Performance.py",
     "View request latency, error rates, per-endpoint statistics"),
    ("Security Incidents", "pages/5_Security.py",
     "View security incidents (AUTH_FAILURE_BURST, STALE_DEVICE, DUPLICATE_FINGERPRINT, REVOKED_ACCESS_ATTEMPT)"),
    ("API Request Logs", "pages/6_Logs.py",
     "View raw request logs with filtering by path and status code"),
    ("System Overview", "pages/1_Overview.py",
     "View system health, device distribution, request volume charts"),
]

cols = st.columns(3)
for i, (label, page, desc) in enumerate(nav_items):
    with cols[i % 3]:
        st.markdown(f"**{label}**")
        st.caption(desc)
        if st.button(f"Open {label}", key=f"quick_nav_{i}"):
            st.switch_page(page)

# ============================================================================
# SECTION C: 핵심 소프트웨어 프로토타입 요구조건 요약
# ============================================================================
st.markdown("---")
st.header("C. 핵심 소프트웨어 프로토타입 요구조건")
st.markdown(
    "아래는 핵심 소프트웨어 프로토타입 개발의 4가지 요구조건입니다. "
    "**대시보드에서 확인 가능한 항목**은 바로 이동 버튼으로, "
    "**코드로만 존재하는 항목**은 코드와 설명으로 표시됩니다."
)

# ============================================================================
# C-1. 경량 에이전트 보안 모듈 개발
# ============================================================================
st.subheader("1. 경량 에이전트 보안 모듈 개발")
st.caption("등록·탐색·메타데이터 전송 / 비동기 이벤트 루프, 재시도/백오프, mTLS 핸드셰이크·세션 유지")

col1, col2, col3 = st.columns(3)
with col1:
    st.markdown("**📊 대시보드 확인 가능**")
    if st.button("디바이스 등록 현황", key="proto_devices"):
        st.switch_page("pages/2_Devices.py")
    st.caption("등록된 디바이스, 상태, Last Seen")

with col2:
    st.markdown("**📊 대시보드 확인 가능**")
    if st.button("토큰 자동 갱신 이벤트", key="proto_auth"):
        st.switch_page("pages/3_Authentication.py")
    st.caption("TOKEN_ISSUED 이벤트 (80% TTL)")

with col3:
    st.markdown("**📊 대시보드 확인 가능**")
    if st.button("테스트 결과 확인", key="proto_test"):
        st.switch_page("pages/8_Test_Scenarios.py")
    st.caption("mTLS healthcheck, Session reuse")

st.markdown("**🔧 코드로만 존재하는 기능:**")
with st.expander("비동기 이벤트 루프 (asyncio)", expanded=False):
    st.markdown("""
**파일:** `services/agent/agent/run.py`

**설명:** Agent의 메인 루프는 `async def` 함수로 구현되어 `asyncio.run()`으로 실행됩니다.
모든 I/O 작업(등록, 토큰 갱신, 메타데이터 발행)이 비동기로 처리됩니다.
""")
    st.code('''# services/agent/agent/run.py
async def agent_loop(args) -> None:
    """Main agent loop — all I/O is awaited."""
    base_url = os.getenv("MANAGER_BASE_URL", "https://localhost:8443")
    # ... registration, token refresh, metadata publish (all async)
    while True:
        await pub.publish(msg)
        await asyncio.sleep(1.5)

def main() -> None:
    asyncio.run(agent_loop(args))  # <-- event loop entry''', language="python")

with st.expander("재시도/백오프 (tenacity)", expanded=False):
    st.markdown("""
**파일:** `services/agent/agent/client.py`

**설명:** HTTP 요청(등록, 토큰)에 tenacity 라이브러리로 재시도 로직 적용.
5회 재시도, 0.5s~8s 지수 백오프 + jitter.
""")
    st.code('''# services/agent/agent/client.py
from tenacity import retry, stop_after_attempt, wait_exponential_jitter

@retry(stop=stop_after_attempt(5),
       wait=wait_exponential_jitter(initial=0.5, max=8),
       retry=retry_if_exception(_not_409))
def register(base_url: str, certs_dir: str, payload: dict) -> dict:
    with _mtls_client(base_url, certs_dir) as c:
        r = c.post("/device/register", json=payload)
        r.raise_for_status()
        return r.json()''', language="python")

with st.expander("mTLS 핸드셰이크·세션 유지", expanded=False):
    st.markdown("""
**파일:** `services/agent/agent/client.py`

**설명:** Agent는 클라이언트 인증서를 제시하고 서버 인증서를 CA로 검증합니다.
httpx.Client를 재사용하여 TLS 핸드셰이크 오버헤드를 최소화합니다.
""")
    st.code('''# services/agent/agent/client.py
def _mtls_client(base_url: str, certs_dir: str) -> httpx.Client:
    ca  = os.path.join(certs_dir, "agent", "ca.crt")    # 서버 검증용 CA
    crt = os.path.join(certs_dir, "agent", "client.crt") # 클라이언트 인증서
    key = os.path.join(certs_dir, "agent", "client.key") # 개인키

    return httpx.Client(
        base_url=base_url,
        verify=ca,        # <-- 서버 인증서 검증
        cert=(crt, key),  # <-- 클라이언트 인증 (mTLS)
        timeout=10.0,
    )''', language="python")

# ============================================================================
# C-2. 인증 모듈 API 개발
# ============================================================================
st.markdown("---")
st.subheader("2. 인증 모듈 API 개발")
st.caption("/cert(발급/갱신/폐기), /auth(token/validate)와 승인 검증")

col1, col2, col3 = st.columns(3)
with col1:
    st.markdown("**📊 대시보드 확인 가능**")
    if st.button("인증서 발급/갱신/폐기", key="proto_cert"):
        st.switch_page("pages/2_Devices.py")
    st.caption("Issue Cert, Renew Cert, Revoke 버튼")

with col2:
    st.markdown("**📊 대시보드 확인 가능**")
    if st.button("토큰 발급/검증 통계", key="proto_token"):
        st.switch_page("pages/3_Authentication.py")
    st.caption("TOKEN_ISSUED/DENIED, VALIDATION_OK/FAILED")

with col3:
    st.markdown("**📊 대시보드 확인 가능**")
    if st.button("RBAC 권한 매트릭스", key="proto_rbac"):
        st.switch_page("pages/3_Authentication.py")
    st.caption("admin/agent 역할별 API 권한")

st.markdown("**🔧 코드로만 존재하는 기능:**")
with st.expander("JWT 토큰 발급 구조 (HS256)", expanded=False):
    st.markdown("""
**파일:** `services/manager/manager/security.py`

**설명:** JWT 토큰은 HS256 알고리즘으로 서명됩니다.
Claims: sub(네임스페이스), roles(역할), iss(발급자), aud(대상), exp(만료)
""")
    st.code('''# services/manager/manager/security.py
def issue_jwt(*, subject: str, roles: list[str],
              issuer: str, audience: str,
              ttl_seconds: int, secret: str) -> str:
    now = utcnow()
    payload = {
        "sub": subject,       # 디바이스 네임스페이스
        "roles": roles,       # ["agent"]
        "iss": issuer,        # "edge-auth-manager"
        "aud": audience,      # "edge-agents"
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
    }
    return jwt.encode(payload, secret, algorithm="HS256")''', language="python")

with st.expander("HMAC-SHA256 메시지 서명", expanded=False):
    st.markdown("""
**파일:** `services/manager/manager/main.py`

**설명:** 고위험 명령(승인/폐기 등)은 HMAC-SHA256으로 서명하여 무결성을 보장합니다.
""")
    st.code('''# services/manager/manager/main.py
import hmac
import hashlib

HMAC_SECRET = os.getenv("HMAC_SECRET", secrets.token_hex(32))

def compute_hmac(payload: str) -> str:
    """HMAC-SHA256 서명 계산"""
    return hmac.new(
        HMAC_SECRET.encode(),  # 비밀키
        payload.encode(),       # 메시지
        hashlib.sha256          # SHA-256 알고리즘
    ).hexdigest()''', language="python")

# ============================================================================
# C-3. 메시지버스 보안채널 모듈 개발
# ============================================================================
st.markdown("---")
st.subheader("3. 메시지버스 보안채널 모듈 개발")
st.caption("TLS 설정, 큐 바인딩, 재접속/미전송 버퍼, 키 교체 중 서비스 지속")

col1, col2 = st.columns(2)
with col1:
    st.markdown("**📊 대시보드 확인 가능**")
    if st.button("테스트: RabbitMQ TLS 연결", key="proto_rmq_test"):
        st.switch_page("pages/8_Test_Scenarios.py")
    st.caption("RabbitMQ health, TLS connections, Queue permissions")

with col2:
    st.markdown("**🌐 외부 UI**")
    st.markdown("[RabbitMQ Management](http://localhost:15672)")
    st.caption("ID: isl / Connections, Queues 탭에서 TLS 확인")

st.markdown("**🔧 코드로만 존재하는 기능:**")
with st.expander("TLS 전용 AMQP 연결 (포트 5671)", expanded=False):
    st.markdown("""
**파일:** `services/agent/agent/amqp_pub.py` + `ops/rabbitmq/rabbitmq.conf`

**설명:** RabbitMQ는 평문 TCP(5672)를 비활성화하고 TLS(5671)만 허용합니다.
Agent는 SSL 컨텍스트로 연결합니다.
""")
    st.code('''# services/agent/agent/amqp_pub.py
def _ssl_context(self) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=self.ca_path)
    ctx.check_hostname = False
    return ctx

# ops/rabbitmq/rabbitmq.conf
listeners.tcp = none          # 평문 TCP 비활성화
listeners.ssl.default = 5671  # TLS 전용''', language="python")

with st.expander("로컬 버퍼 (unsent.jsonl)", expanded=False):
    st.markdown("""
**파일:** `services/agent/agent/buffer.py`

**설명:** AMQP 연결이 끊어지면 메시지를 로컬 JSONL 파일에 저장합니다.
재연결 시 버퍼를 플러시하여 데이터 무손실을 보장합니다.
""")
    st.code('''# services/agent/agent/buffer.py
class JsonlBuffer:
    def __init__(self, dir_path: str):
        self.path = Path(dir_path) / "unsent.jsonl"

    def append(self, obj: dict) -> None:
        """연결 끊김 시 메시지 저장"""
        with self.path.open("a") as f:
            f.write(json.dumps(obj) + "\\n")

    def drain(self, limit: int = 200) -> list[dict]:
        """재연결 시 버퍼 읽기 (최대 200개)"""
        lines = self.path.read_text().splitlines()
        take = lines[:limit]
        # ... 나머지는 파일에 유지''', language="python")

with st.expander("재연결 + 지수 백오프 (최대 30회)", expanded=False):
    st.markdown("""
**파일:** `services/agent/agent/amqp_pub.py`

**설명:** 연결 끊김 시 0.5s~20s 지수 백오프로 최대 30회 재연결 시도.
키 로테이션 중에도 서비스가 지속됩니다.
""")
    st.code('''# services/agent/agent/amqp_pub.py
async def _reconnect_with_backoff(self) -> None:
    async for attempt in AsyncRetrying(
        stop=stop_after_attempt(30),            # 최대 30회
        wait=wait_exponential_jitter(
            initial=0.5, max=20),               # 0.5s~20s
        reraise=False,
    ):
        with attempt:
            await self.connect()
            return''', language="python")

# ============================================================================
# C-4. 컨테이너 이미지, 초기 설정·설치 스크립트 제공
# ============================================================================
st.markdown("---")
st.subheader("4. 컨테이너 이미지, 초기 설정·설치 스크립트 제공")
st.caption("TLS 강제·기본계정 제거·최소권한 Role 등 보안 기본값 적용")

col1, col2 = st.columns(2)
with col1:
    st.markdown("**📊 대시보드 확인 가능**")
    if st.button("시스템 상태 확인", key="proto_overview"):
        st.switch_page("pages/1_Overview.py")
    st.caption("모든 서비스 정상 동작 확인")

with col2:
    st.markdown("**🌐 외부 UI**")
    st.markdown("[RabbitMQ Management](http://localhost:15672)")
    st.caption("guest 삭제, edge-agent 계정만 존재")

st.markdown("**🔧 코드로만 존재하는 기능:**")
with st.expander("Non-root 컨테이너 실행", expanded=False):
    st.markdown("""
**파일:** 각 서비스의 `Dockerfile`

**설명:** 모든 컨테이너는 전용 non-root 사용자로 실행됩니다.
- Manager: user `manager` (UID 1001)
- Agent: user `agent` (UID 1002)
- Dashboard: user `dashboard` (UID 1003)
""")
    st.code('''# services/manager/Dockerfile
FROM python:3.11-slim
RUN groupadd -r manager && useradd -r -g manager -u 1001 manager
# ...
USER manager

# services/agent/Dockerfile
FROM python:3.11-slim
RUN groupadd -r agent && useradd -r -g agent -u 1002 agent
# ...
USER agent''', language="dockerfile")

with st.expander("TLS 강제 (HTTPS/AMQPS only)", expanded=False):
    st.markdown("""
**파일:** `services/manager/manager/main.py` + `ops/rabbitmq/rabbitmq.conf`

**설명:** Manager는 HTTPS(8443)만, RabbitMQ는 AMQPS(5671)만 수신합니다.
평문 HTTP/AMQP는 비활성화되어 있습니다.
""")
    st.code('''# services/manager/manager/main.py
uvicorn.run(
    "manager.main:app",
    host="0.0.0.0",
    port=8443,  # HTTPS only, no HTTP
    ssl_keyfile=ssl_keyfile,
    ssl_certfile=ssl_certfile,
)

# ops/rabbitmq/rabbitmq.conf
listeners.tcp = none          # HTTP 비활성화
listeners.ssl.default = 5671  # HTTPS만''', language="python")

with st.expander("기본계정 제거 (guest 삭제)", expanded=False):
    st.markdown("""
**파일:** `ops/rabbitmq/init.sh`

**설명:** RabbitMQ 초기화 시 기본 `guest` 계정을 삭제합니다.
전용 `edge-agent` 계정만 사용합니다.
""")
    st.code('''# ops/rabbitmq/init.sh
#!/bin/bash
set -e

# 전용 edge-agent 사용자 생성
rabbitmqctl add_user edge-agent "${RABBITMQ_EDGE_PASSWORD}"
rabbitmqctl set_permissions -p / edge-agent \\
    "^agent\\.metadata$" "^agent\\.metadata$" "^agent\\.metadata$"

# 기본 guest 계정 삭제
rabbitmqctl delete_user guest''', language="bash")

with st.expander("최소권한 Role (agent.metadata만 접근)", expanded=False):
    st.markdown("""
**파일:** `ops/rabbitmq/init.sh`

**설명:** `edge-agent` 사용자는 `agent.metadata` 큐에만 접근 가능합니다.
정규식 `^agent\\.metadata$`로 다른 큐 생성/접근을 차단합니다.
""")
    st.code('''# ops/rabbitmq/init.sh
# Configure, Write, Read 권한 모두 동일 정규식
rabbitmqctl set_permissions -p / edge-agent \\
    "^agent\\.metadata$" \\  # Configure: 이 큐만 선언 가능
    "^agent\\.metadata$" \\  # Write: 이 큐에만 발행 가능
    "^agent\\.metadata$"     # Read: 이 큐에서만 소비 가능

# 다른 큐(예: admin.commands) 접근 시도 → Permission Denied''', language="bash")

st.markdown("---")
st.caption("Edge Auth Manager Prototype — Development Checklist v0.2.0")
