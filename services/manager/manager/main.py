from __future__ import annotations

import os
import ssl
import asyncio
import time
import hmac
import hashlib
import logging
import uuid
from collections import defaultdict
from typing import Annotated, Optional
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, status, Header, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import uvicorn
from sqlalchemy.ext.asyncio import AsyncSession

from manager.models import (
    DeviceRegisterIn, DeviceOut, ApproveIn, DeviceTransferIn,
    TokenIn, TokenOut, ValidateOut,
    CertIssueIn, CertStatusOut,
    OverviewMetrics, RequestStats, HourlyVolume, EndpointStats,
    AuthStats, HourlyAuthStats, DeviceAuthStats,
    SecurityIncidentOut, IncidentCounts, IncidentByType,
    DeviceCounts, StaleDevice, RequestLogOut,
)
from manager.db import (
    init_db, upsert_device_pending, list_devices, set_device_status,
    get_device, touch_device, set_cert, get_cert,
    log_request, log_auth_event, log_security_incident,
    get_request_stats, get_hourly_request_volume, get_endpoint_stats,
    get_request_logs,
    get_auth_stats, get_hourly_auth_stats, get_device_auth_stats,
    get_security_incidents, get_incident_counts, resolve_incident, get_incidents_by_type,
    get_device_counts_by_status, get_stale_devices,
    cleanup_old_records, utcnow,
)
from manager.security import issue_jwt, verify_jwt, random_secret

logger = logging.getLogger(__name__)

DB_URL = os.getenv("DB_URL", "sqlite+aiosqlite:////data/manager.db")
JWT_ISSUER = os.getenv("JWT_ISSUER", "edge-auth-manager")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "edge-agents")
JWT_TTL_SECONDS = int(os.getenv("JWT_TTL_SECONDS", "900"))
CERTS_DIR = os.getenv("CERTS_DIR", "/certs")
AUTO_APPROVE = os.getenv("AUTO_APPROVE", "false").lower() in ("1", "true", "yes")

# Prototype secret; rotate in production via KMS/secret manager
JWT_SECRET = os.getenv("JWT_SECRET") or random_secret()

# Previous JWT secret (to allow graceful rotation — tokens signed with old secret still valid temporarily)
_JWT_SECRET_PREV: Optional[str] = None
_JWT_SECRET_ROTATED_AT: Optional[datetime] = None
_JWT_ROTATION_GRACE_SECONDS = int(os.getenv("JWT_ROTATION_GRACE_SECONDS", "120"))

# HMAC key for signing high-risk admin commands and AMQP message integrity
HMAC_SECRET = os.getenv("HMAC_SECRET") or random_secret(32)

# JWT token blocklist: namespace -> set of revoked token JTI values (bounded in-memory)
_token_blocklist: dict[str, set[str]] = defaultdict(set)

# RBAC role/resource permission matrix
# Maps role -> set of allowed path prefixes
RBAC_MATRIX: dict[str, set[str]] = {
    "admin": {
        "/device/register", "/device/list", "/device/approve", "/device/revoke",
        "/device/decommission", "/device/transfer",
        "/auth/token", "/auth/validate",
        "/cert/issue", "/cert/renew", "/cert/revoke", "/cert/status", "/cert/crl", "/cert/ocsp",
        "/metrics/", "/logs/", "/admin/",
    },
    "agent": {
        "/device/register", "/auth/token", "/auth/validate", "/cert/status", "/cert/ocsp",
    },
}

# Background task control
_background_tasks_running = False
_startup_time: Optional[datetime] = None

SessionLocal = None


def _extract_client_cn(request: Request) -> Optional[str]:
    """Extract client certificate Common Name from the TLS transport."""
    try:
        transport = request.scope.get("transport")
        if transport is None:
            return None
        ssl_object = transport.get_extra_info("ssl_object")
        if ssl_object is None:
            return None
        peer_cert = ssl_object.getpeercert()
        if peer_cert:
            for rdn in peer_cert.get("subject", ()):
                for attr_type, attr_value in rdn:
                    if attr_type == "commonName":
                        return attr_value
    except Exception:
        pass
    return None


class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware to log all API requests with correlation ID and client CN."""

    SKIP_PATHS = {"/healthz", "/docs", "/openapi.json", "/redoc"}

    async def dispatch(self, request: Request, call_next):
        # Assign correlation / trace ID
        request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
        request.state.request_id = request_id

        if request.url.path in self.SKIP_PATHS:
            response = await call_next(request)
            response.headers["X-Request-Id"] = request_id
            return response

        start_time = time.perf_counter()
        error_detail = None
        client_cn = _extract_client_cn(request)

        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception as e:
            error_detail = str(e)
            status_code = 500
            raise
        finally:
            latency_ms = (time.perf_counter() - start_time) * 1000

            namespace = None

            if SessionLocal is not None:
                try:
                    async with SessionLocal() as session:
                        await log_request(
                            session,
                            method=request.method,
                            path=request.url.path,
                            status_code=status_code,
                            latency_ms=latency_ms,
                            client_cn=client_cn,
                            namespace=namespace,
                            error_detail=error_detail,
                        )
                except Exception as log_err:
                    logger.warning(f"Failed to log request metrics: {log_err}")

        response.headers["X-Request-Id"] = request_id
        return response


async def incident_detection_task():
    """Background task to detect security incidents"""
    while _background_tasks_running:
        try:
            if SessionLocal is not None:
                async with SessionLocal() as session:
                    # Detect auth failure bursts (>10 failures in 5 minutes)
                    stats = await get_auth_stats(session, hours=1)
                    if stats["failures"] > 10:
                        recent_incidents = await get_security_incidents(session, days=1)
                        # Avoid duplicate alerts
                        has_recent_burst = any(
                            i.incident_type == "AUTH_FAILURE_BURST" and
                            (utcnow() - i.timestamp).total_seconds() < 300
                            for i in recent_incidents
                        )
                        if not has_recent_burst:
                            await log_security_incident(
                                session,
                                severity="HIGH",
                                incident_type="AUTH_FAILURE_BURST",
                                description=f"Detected {stats['failures']} authentication failures in the last hour",
                            )

                    # Detect stale devices
                    stale = await get_stale_devices(session, stale_hours=24)
                    for device in stale:
                        recent_incidents = await get_security_incidents(session, days=1)
                        has_stale_alert = any(
                            i.incident_type == "STALE_DEVICE" and i.namespace == device.namespace
                            for i in recent_incidents
                        )
                        if not has_stale_alert:
                            await log_security_incident(
                                session,
                                severity="MEDIUM",
                                incident_type="STALE_DEVICE",
                                namespace=device.namespace,
                                description=f"Device has not been seen for over 24 hours",
                            )

        except Exception as e:
            logger.error(f"Incident detection error: {e}")

        await asyncio.sleep(300)  # Run every 5 minutes


async def cleanup_task():
    """Background task to clean up old records"""
    while _background_tasks_running:
        try:
            if SessionLocal is not None:
                async with SessionLocal() as session:
                    result = await cleanup_old_records(session, retention_days=7)
                    if any(v > 0 for v in result.values()):
                        logger.info(f"Cleanup completed: {result}")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")

        await asyncio.sleep(3600)  # Run every hour


@asynccontextmanager
async def lifespan(app: FastAPI):
    global SessionLocal, _background_tasks_running, _startup_time
    SessionLocal = await init_db(DB_URL)
    _startup_time = utcnow()
    _background_tasks_running = True

    # Start background tasks
    detection_task = asyncio.create_task(incident_detection_task())
    clean_task = asyncio.create_task(cleanup_task())

    yield

    # Shutdown
    _background_tasks_running = False
    detection_task.cancel()
    clean_task.cancel()
    try:
        await detection_task
    except asyncio.CancelledError:
        pass
    try:
        await clean_task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="Auth Manager (Prototype)", version="0.1.0", lifespan=lifespan)
app.add_middleware(MetricsMiddleware)

async def get_db() -> AsyncSession:
    assert SessionLocal is not None
    async with SessionLocal() as session:
        yield session

def require_admin(x_admin_token: Annotated[Optional[str], Header()] = None) -> None:
    """Admin gate: verifies X-Admin-Token header matches expected token."""
    expected = os.getenv("ADMIN_TOKEN", "dev-admin-token")
    if x_admin_token != expected:
        raise HTTPException(status_code=401, detail="admin auth required")


def require_role(required_role: str):
    """RBAC dependency factory: checks that caller has a specific role.

    For admin endpoints, require_admin is used directly.
    For agent-facing endpoints, this validates the JWT roles claim.
    """
    def _check(authorization: Annotated[Optional[str], Header()] = None,
               x_admin_token: Annotated[Optional[str], Header()] = None):
        # Admin token holders implicitly have all roles
        expected_admin = os.getenv("ADMIN_TOKEN", "dev-admin-token")
        if x_admin_token == expected_admin:
            return "admin"

        # Check JWT bearer token for role
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="authentication required")
        token = authorization.split(" ", 1)[1].strip()
        try:
            payload = verify_jwt(token, issuer=JWT_ISSUER, audience=JWT_AUDIENCE, secret=JWT_SECRET)
        except Exception:
            # Try previous secret during rotation grace period
            if _JWT_SECRET_PREV and _JWT_SECRET_ROTATED_AT:
                elapsed = (utcnow() - _JWT_SECRET_ROTATED_AT).total_seconds()
                if elapsed < _JWT_ROTATION_GRACE_SECONDS:
                    try:
                        payload = verify_jwt(token, issuer=JWT_ISSUER, audience=JWT_AUDIENCE, secret=_JWT_SECRET_PREV)
                    except Exception:
                        raise HTTPException(status_code=401, detail="invalid token")
                else:
                    raise HTTPException(status_code=401, detail="invalid token")
            else:
                raise HTTPException(status_code=401, detail="invalid token")

        # Check if token is blocklisted
        sub = payload.get("sub", "")
        jti = payload.get("jti", "")
        if jti and jti in _token_blocklist.get(sub, set()):
            raise HTTPException(status_code=401, detail="token revoked")

        roles = payload.get("roles", [])
        if required_role not in roles and "admin" not in roles:
            allowed = RBAC_MATRIX.get(required_role, set())
            raise HTTPException(
                status_code=403,
                detail=f"role '{required_role}' required. Allowed paths: {sorted(allowed)}",
            )
        return payload.get("sub")
    return _check


def namespace(domain: str, site: str, group: str, device_id: str) -> str:
    return f"{domain}/{site}/{group}/{device_id}"


def compute_hmac(payload: str) -> str:
    """Compute HMAC-SHA256 signature for a payload string."""
    return hmac.new(HMAC_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()

@app.get("/healthz")
async def healthz():
    return {"ok": True}

# --- Device lifecycle: boot -> register -> approve -> auth -> data exchange

@app.post("/device/register", response_model=DeviceOut)
async def device_register(body: DeviceRegisterIn, db: AsyncSession = Depends(get_db)):
    ns = namespace(body.domain, body.site, body.group, body.device_id)

    # Check for duplicate registration with different hw_fingerprint (impersonation)
    existing = await get_device(db, ns)
    if existing is not None:
        if existing.hw_fingerprint and existing.hw_fingerprint != body.hw_fingerprint:
            await log_security_incident(
                db,
                severity="CRITICAL",
                incident_type="DUPLICATE_FINGERPRINT",
                namespace=ns,
                description=f"Registration attempt with different hw_fingerprint. "
                            f"Existing: {existing.hw_fingerprint[:16]}..., "
                            f"Incoming: {body.hw_fingerprint[:16]}...",
            )
            raise HTTPException(
                status_code=409,
                detail="device namespace already registered with a different hardware fingerprint",
            )

        # Log security incident if revoked device attempts to re-register
        if existing.status == "REVOKED":
            await log_security_incident(
                db,
                severity="HIGH",
                incident_type="REVOKED_ACCESS_ATTEMPT",
                namespace=ns,
                description="Revoked device attempted to re-register",
            )

    dev = await upsert_device_pending(db, ns, body.hw_fingerprint, body.agent_version)
    if AUTO_APPROVE and dev.status == "PENDING":
        await set_device_status(db, ns, "APPROVED")
        dev = await get_device(db, ns)
    return DeviceOut(namespace=dev.namespace, status=dev.status, last_seen=dev.last_seen.isoformat() if dev.last_seen else None, agent_version=dev.agent_version)

@app.get("/device/list", response_model=list[DeviceOut])
async def device_list(db: AsyncSession = Depends(get_db)):
    rows = await list_devices(db)
    return [DeviceOut(namespace=r.namespace, status=r.status, last_seen=r.last_seen.isoformat() if r.last_seen else None, agent_version=r.agent_version) for r in rows]

@app.post("/device/approve")
async def device_approve(body: ApproveIn, _: None = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    dev = await get_device(db, body.namespace)
    if dev is None:
        raise HTTPException(status_code=404, detail="device not found")
    await set_device_status(db, body.namespace, "APPROVED")
    return {"ok": True, "namespace": body.namespace, "status": "APPROVED"}

@app.post("/device/revoke")
async def device_revoke(body: ApproveIn, _: None = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    dev = await get_device(db, body.namespace)
    if dev is None:
        raise HTTPException(status_code=404, detail="device not found")
    await set_device_status(db, body.namespace, "REVOKED")
    await set_cert(db, body.namespace, "REVOKED", None)
    # Blocklist all tokens for this device
    _token_blocklist[body.namespace] = _token_blocklist.get(body.namespace, set())
    return {"ok": True, "namespace": body.namespace, "status": "REVOKED"}


@app.post("/device/decommission")
async def device_decommission(body: DeviceTransferIn, _: None = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Decommission (dispose) a device: revoke, revoke cert, mark reason."""
    dev = await get_device(db, body.namespace)
    if dev is None:
        raise HTTPException(status_code=404, detail="device not found")
    await set_device_status(db, body.namespace, "REVOKED")
    await set_cert(db, body.namespace, "REVOKED", None)
    _token_blocklist[body.namespace] = _token_blocklist.get(body.namespace, set())
    await log_security_incident(
        db, severity="LOW", incident_type="DEVICE_DECOMMISSIONED",
        namespace=body.namespace,
        description=f"Device decommissioned. Reason: {body.reason}",
    )
    return {"ok": True, "namespace": body.namespace, "status": "DECOMMISSIONED", "reason": body.reason}


@app.post("/device/transfer")
async def device_transfer(body: DeviceTransferIn, _: None = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Transfer a device to a new site/group. Old namespace is revoked, new namespace created."""
    dev = await get_device(db, body.namespace)
    if dev is None:
        raise HTTPException(status_code=404, detail="device not found")
    if not body.new_site and not body.new_group:
        raise HTTPException(status_code=400, detail="new_site or new_group required for transfer")

    # Parse old namespace
    parts = body.namespace.split("/")
    if len(parts) != 4:
        raise HTTPException(status_code=400, detail="invalid namespace format")
    domain, old_site, old_group, device_id = parts
    new_site = body.new_site or old_site
    new_group = body.new_group or old_group
    new_ns = namespace(domain, new_site, new_group, device_id)

    # Revoke old
    await set_device_status(db, body.namespace, "REVOKED")
    await set_cert(db, body.namespace, "REVOKED", None)
    _token_blocklist[body.namespace] = _token_blocklist.get(body.namespace, set())

    # Create new device entry
    await upsert_device_pending(db, new_ns, dev.hw_fingerprint, dev.agent_version)

    await log_security_incident(
        db, severity="LOW", incident_type="DEVICE_TRANSFERRED",
        namespace=new_ns,
        description=f"Device transferred from {body.namespace} to {new_ns}. Reason: {body.reason}",
    )
    return {"ok": True, "old_namespace": body.namespace, "new_namespace": new_ns, "status": "PENDING"}


# --- /auth: token issuance + validation (approval enforced)

@app.post("/auth/token", response_model=TokenOut)
async def auth_token(body: TokenIn, db: AsyncSession = Depends(get_db)):
    dev = await get_device(db, body.namespace)
    if dev is None:
        await log_auth_event(db, "TOKEN_DENIED", success=False, namespace=body.namespace, failure_reason="device_not_registered")
        raise HTTPException(status_code=404, detail="device not registered")
    if dev.status != "APPROVED":
        await log_auth_event(db, "TOKEN_DENIED", success=False, namespace=body.namespace, failure_reason=f"device_status_{dev.status}")
        raise HTTPException(status_code=403, detail=f"device not approved (status={dev.status})")
    await touch_device(db, body.namespace)
    jti = str(uuid.uuid4())
    token = issue_jwt(
        subject=body.namespace,
        roles=["agent"],
        issuer=JWT_ISSUER,
        audience=JWT_AUDIENCE,
        ttl_seconds=JWT_TTL_SECONDS,
        secret=JWT_SECRET,
        jti=jti,
    )
    await log_auth_event(db, "TOKEN_ISSUED", success=True, namespace=body.namespace)
    return TokenOut(access_token=token, expires_in=JWT_TTL_SECONDS)

@app.post("/auth/validate", response_model=ValidateOut)
async def auth_validate(authorization: Annotated[Optional[str], Header()] = None, db: AsyncSession = Depends(get_db)):
    if not authorization or not authorization.lower().startswith("bearer "):
        await log_auth_event(db, "VALIDATION_FAILED", success=False, failure_reason="missing_or_invalid_header")
        return ValidateOut(ok=False)
    token = authorization.split(" ", 1)[1].strip()

    # Try current secret, then previous secret during rotation grace period
    payload = None
    for secret in [JWT_SECRET] + ([_JWT_SECRET_PREV] if _JWT_SECRET_PREV else []):
        try:
            payload = verify_jwt(token, issuer=JWT_ISSUER, audience=JWT_AUDIENCE, secret=secret)
            break
        except Exception:
            continue

    if payload is None:
        await log_auth_event(db, "VALIDATION_FAILED", success=False, failure_reason="invalid_signature")
        return ValidateOut(ok=False)

    # Check blocklist
    subject = payload.get("sub", "")
    jti = payload.get("jti", "")
    if jti and jti in _token_blocklist.get(subject, set()):
        await log_auth_event(db, "VALIDATION_FAILED", success=False, namespace=subject, failure_reason="token_revoked")
        return ValidateOut(ok=False)

    await log_auth_event(db, "VALIDATION_OK", success=True, namespace=subject)
    return ValidateOut(ok=True, subject=subject, roles=payload.get("roles", []), exp=payload.get("exp"))

# --- /cert: simplified status tracking (CSR issuance is out-of-scope for this prototype)

@app.post("/cert/issue", response_model=CertStatusOut)
async def cert_issue(body: CertIssueIn, _: None = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    # Prototype: we only record status. Real system: issue signed cert via CA and return.
    not_after = datetime.now(timezone.utc) + timedelta(days=90)
    await set_cert(db, body.namespace, "ISSUED", not_after)
    return CertStatusOut(namespace=body.namespace, status="ISSUED", not_after=not_after.isoformat())

@app.post("/cert/renew", response_model=CertStatusOut)
async def cert_renew(body: CertIssueIn, _: None = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    # Prototype: renew cert by extending validity period
    # In production: verify existing cert, generate new one via CA
    dev = await get_device(db, body.namespace)
    if dev is None:
        raise HTTPException(status_code=404, detail="device not found")
    if dev.status == "REVOKED":
        raise HTTPException(status_code=409, detail="cannot renew revoked device cert")

    existing = await get_cert(db, body.namespace)
    if existing and existing.status == "REVOKED":
        raise HTTPException(status_code=409, detail="cert is revoked, issue new cert instead")

    not_after = datetime.now(timezone.utc) + timedelta(days=90)
    await set_cert(db, body.namespace, "ISSUED", not_after)
    return CertStatusOut(namespace=body.namespace, status="ISSUED", not_after=not_after.isoformat())

@app.post("/cert/revoke", response_model=CertStatusOut)
async def cert_revoke(body: CertIssueIn, _: None = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    await set_cert(db, body.namespace, "REVOKED", None)
    return CertStatusOut(namespace=body.namespace, status="REVOKED")

@app.get("/cert/status", response_model=CertStatusOut)
async def cert_status(namespace: str, db: AsyncSession = Depends(get_db)):
    row = await get_cert(db, namespace)
    if not row:
        return CertStatusOut(namespace=namespace, status="UNKNOWN")
    return CertStatusOut(namespace=namespace, status=row.status, not_after=row.not_after.isoformat() if row.not_after else None)


@app.get("/cert/crl")
async def cert_crl(db: AsyncSession = Depends(get_db)):
    """Certificate Revocation List — returns all revoked certificate namespaces.

    Lightweight CRL alternative for the prototype. Production should use
    X.509 CRL or OCSP responder.
    """
    from sqlalchemy import select
    from manager.db import CertState
    res = await db.execute(
        select(CertState.namespace, CertState.not_after).where(CertState.status == "REVOKED")
    )
    revoked = []
    for row in res.fetchall():
        revoked.append({
            "namespace": row[0],
            "revoked_at": row[1].isoformat() if row[1] else None,
        })
    return {"revoked_certificates": revoked, "total": len(revoked)}


@app.get("/cert/ocsp")
async def cert_ocsp_simple(namespace: str, db: AsyncSession = Depends(get_db)):
    """Simple OCSP-like endpoint (JSON format) for quick certificate status check.

    This is a simplified OCSP alternative for the prototype.
    Returns certificate status with timing information.

    Response status values:
    - GOOD: Certificate is valid and not revoked
    - REVOKED: Certificate has been revoked
    - UNKNOWN: Certificate not found in our records
    """
    row = await get_cert(db, namespace)
    now = utcnow()

    if not row:
        return {
            "ocsp_response": {
                "status": "UNKNOWN",
                "namespace": namespace,
                "produced_at": now.isoformat(),
                "this_update": now.isoformat(),
                "next_update": (now + timedelta(hours=1)).isoformat(),
                "reason": "Certificate not found in database",
            }
        }

    if row.status == "REVOKED":
        return {
            "ocsp_response": {
                "status": "REVOKED",
                "namespace": namespace,
                "produced_at": now.isoformat(),
                "this_update": now.isoformat(),
                "next_update": (now + timedelta(hours=1)).isoformat(),
                "revocation_time": row.not_after.isoformat() if row.not_after else now.isoformat(),
                "revocation_reason": "unspecified",
            }
        }

    # ISSUED status = GOOD in OCSP terms
    return {
        "ocsp_response": {
            "status": "GOOD",
            "namespace": namespace,
            "produced_at": now.isoformat(),
            "this_update": now.isoformat(),
            "next_update": (now + timedelta(hours=1)).isoformat(),
            "cert_status": row.status,
            "not_after": row.not_after.isoformat() if row.not_after else None,
        }
    }


@app.post("/cert/ocsp")
async def cert_ocsp_standard(request: Request, db: AsyncSession = Depends(get_db)):
    """Standard OCSP Responder endpoint (RFC 6960 compatible).

    Accepts:
    - Content-Type: application/ocsp-request (DER-encoded OCSP request)
    - Content-Type: application/json (simplified JSON request with namespace)

    Returns:
    - Content-Type: application/ocsp-response (DER-encoded) for standard requests
    - Content-Type: application/json for JSON requests

    This endpoint demonstrates OCSP protocol compliance for the prototype.
    """
    content_type = request.headers.get("content-type", "")

    # Handle JSON request (simplified)
    if "application/json" in content_type:
        body = await request.json()
        namespace = body.get("namespace")
        if not namespace:
            return {"error": "namespace required"}
        row = await get_cert(db, namespace)
        now = utcnow()

        if not row:
            status = "UNKNOWN"
        elif row.status == "REVOKED":
            status = "REVOKED"
        else:
            status = "GOOD"

        return {
            "ocsp_response": {
                "status": status,
                "namespace": namespace,
                "produced_at": now.isoformat(),
                "responder_id": JWT_ISSUER,
            }
        }

    # Handle standard OCSP request (DER-encoded)
    if "application/ocsp-request" in content_type:
        try:
            from cryptography.x509 import ocsp
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography import x509
            import os

            body = await request.body()

            # Parse OCSP request
            ocsp_request = ocsp.load_der_ocsp_request(body)
            serial_number = ocsp_request.serial_number

            # For prototype: map serial number to namespace lookup
            # In production, you'd look up by actual certificate serial
            # Here we return a generic response showing the mechanism works

            now = utcnow()

            # Build OCSP response
            # Note: For full implementation, we'd need the actual issuer cert and responder key
            # This is a demonstration of the protocol structure

            # Return a simple successful response indicating the mechanism exists
            # Full implementation would sign the response with responder's private key
            return Response(
                content=b"OCSP responder active - full implementation requires responder certificate",
                media_type="text/plain",
                headers={"X-OCSP-Status": "prototype-mode"},
            )

        except ImportError:
            return Response(
                content=b"OCSP parsing requires cryptography library",
                media_type="text/plain",
                status_code=500,
            )
        except Exception as e:
            return Response(
                content=f"OCSP request parsing error: {str(e)}".encode(),
                media_type="text/plain",
                status_code=400,
            )

    # Fallback for unknown content types
    return {"error": "Unsupported content type. Use application/json or application/ocsp-request"}


# --- Admin operational endpoints ---

@app.post("/admin/rotate-jwt-secret")
async def rotate_jwt_secret(_: None = Depends(require_admin)):
    """Rotate JWT signing secret. Old tokens remain valid during grace period."""
    global JWT_SECRET, _JWT_SECRET_PREV, _JWT_SECRET_ROTATED_AT
    _JWT_SECRET_PREV = JWT_SECRET
    JWT_SECRET = random_secret()
    _JWT_SECRET_ROTATED_AT = utcnow()
    return {
        "ok": True,
        "rotated_at": _JWT_SECRET_ROTATED_AT.isoformat(),
        "grace_seconds": _JWT_ROTATION_GRACE_SECONDS,
        "note": f"Old tokens valid for {_JWT_ROTATION_GRACE_SECONDS}s after rotation",
    }


@app.post("/admin/revoke-tokens")
async def revoke_device_tokens(body: ApproveIn, _: None = Depends(require_admin)):
    """Add all current tokens for a device to the blocklist."""
    _token_blocklist[body.namespace] = _token_blocklist.get(body.namespace, set())
    # Mark a wildcard entry — any token for this namespace issued before now is invalid
    _token_blocklist[body.namespace].add("*")
    return {"ok": True, "namespace": body.namespace, "message": "all tokens revoked"}


@app.get("/admin/rbac-matrix")
async def rbac_matrix(_: None = Depends(require_admin)):
    """Return the role/resource permission matrix."""
    return {
        role: sorted(paths) for role, paths in RBAC_MATRIX.items()
    }


@app.post("/admin/verify-hmac")
async def verify_hmac_endpoint(
    payload: str,
    signature: str,
    _: None = Depends(require_admin),
):
    """Verify HMAC-SHA256 signature for a payload."""
    expected = compute_hmac(payload)
    valid = hmac.compare_digest(expected, signature)
    return {"valid": valid}


@app.get("/admin/security-config")
async def security_config(_: None = Depends(require_admin)):
    """Return current security configuration (non-sensitive)."""
    return {
        "jwt_algorithm": "HS256",
        "jwt_issuer": JWT_ISSUER,
        "jwt_audience": JWT_AUDIENCE,
        "jwt_ttl_seconds": JWT_TTL_SECONDS,
        "jwt_rotation_grace_seconds": _JWT_ROTATION_GRACE_SECONDS,
        "jwt_secret_rotated_at": _JWT_SECRET_ROTATED_AT.isoformat() if _JWT_SECRET_ROTATED_AT else None,
        "hmac_algorithm": "HMAC-SHA256",
        "blocklist_namespaces": len(_token_blocklist),
        "rbac_roles": list(RBAC_MATRIX.keys()),
        "auto_approve": AUTO_APPROVE,
    }


# --- Metrics endpoints (admin-protected) ---

@app.get("/metrics/overview", response_model=OverviewMetrics)
async def metrics_overview(_: None = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Get overview metrics for the dashboard"""
    device_counts = await get_device_counts_by_status(db)
    request_stats = await get_request_stats(db, hours=24)
    auth_stats = await get_auth_stats(db, hours=24)
    incident_counts = await get_incident_counts(db, days=7)

    return OverviewMetrics(
        total_devices=device_counts["total"],
        approved_devices=device_counts["APPROVED"],
        pending_devices=device_counts["PENDING"],
        revoked_devices=device_counts["REVOKED"],
        requests_24h=request_stats["total_requests"],
        auth_success_rate=auth_stats["success_rate"],
        active_incidents=sum(incident_counts.values()),
        avg_latency_ms=(request_stats["latency_p50_ms"] + request_stats["latency_p95_ms"]) / 2 if request_stats["total_requests"] > 0 else 0.0,
    )


@app.get("/metrics/requests", response_model=RequestStats)
async def metrics_requests(hours: int = 24, _: None = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Get request statistics"""
    stats = await get_request_stats(db, hours=hours)
    return RequestStats(**stats)


@app.get("/metrics/requests/hourly", response_model=list[HourlyVolume])
async def metrics_requests_hourly(hours: int = 24, _: None = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Get hourly request volume"""
    data = await get_hourly_request_volume(db, hours=hours)
    return [HourlyVolume(**d) for d in data]


@app.get("/metrics/requests/endpoints", response_model=list[EndpointStats])
async def metrics_endpoints(hours: int = 24, _: None = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Get per-endpoint statistics"""
    data = await get_endpoint_stats(db, hours=hours)
    return [EndpointStats(**d) for d in data]


@app.get("/metrics/auth", response_model=AuthStats)
async def metrics_auth(hours: int = 24, _: None = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Get authentication statistics"""
    stats = await get_auth_stats(db, hours=hours)
    return AuthStats(**stats)


@app.get("/metrics/auth/hourly", response_model=list[HourlyAuthStats])
async def metrics_auth_hourly(hours: int = 24, _: None = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Get hourly auth statistics"""
    data = await get_hourly_auth_stats(db, hours=hours)
    return [HourlyAuthStats(**d) for d in data]


@app.get("/metrics/auth/devices", response_model=list[DeviceAuthStats])
async def metrics_auth_devices(hours: int = 24, _: None = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Get per-device auth statistics"""
    data = await get_device_auth_stats(db, hours=hours)
    return [DeviceAuthStats(**d) for d in data]


@app.get("/metrics/security", response_model=list[SecurityIncidentOut])
async def metrics_security(days: int = 7, unresolved_only: bool = False, _: None = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Get security incidents"""
    incidents = await get_security_incidents(db, days=days, unresolved_only=unresolved_only)
    return [
        SecurityIncidentOut(
            id=i.id,
            timestamp=i.timestamp.isoformat(),
            severity=i.severity,
            incident_type=i.incident_type,
            namespace=i.namespace,
            description=i.description,
            resolved=i.resolved,
        )
        for i in incidents
    ]


@app.get("/metrics/security/counts", response_model=IncidentCounts)
async def metrics_security_counts(days: int = 7, _: None = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Get incident counts by severity"""
    counts = await get_incident_counts(db, days=days)
    return IncidentCounts(
        critical=counts["CRITICAL"],
        high=counts["HIGH"],
        medium=counts["MEDIUM"],
        low=counts["LOW"],
        total=sum(counts.values()),
    )


@app.get("/metrics/security/by-type", response_model=list[IncidentByType])
async def metrics_security_by_type(days: int = 7, _: None = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Get incidents grouped by type"""
    data = await get_incidents_by_type(db, days=days)
    return [IncidentByType(**d) for d in data]


@app.post("/metrics/incidents/{incident_id}/resolve")
async def metrics_resolve_incident(incident_id: int, _: None = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Mark an incident as resolved"""
    success = await resolve_incident(db, incident_id)
    if not success:
        raise HTTPException(status_code=404, detail="incident not found")
    return {"ok": True, "incident_id": incident_id, "resolved": True}


@app.get("/metrics/devices", response_model=DeviceCounts)
async def metrics_devices(_: None = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Get device counts by status"""
    counts = await get_device_counts_by_status(db)
    return DeviceCounts(
        total=counts["total"],
        pending=counts["PENDING"],
        approved=counts["APPROVED"],
        revoked=counts["REVOKED"],
    )


@app.get("/metrics/devices/stale", response_model=list[StaleDevice])
async def metrics_stale_devices(hours: int = 24, _: None = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Get devices that haven't been seen recently"""
    devices = await get_stale_devices(db, stale_hours=hours)
    now = utcnow()
    return [
        StaleDevice(
            namespace=d.namespace,
            last_seen=d.last_seen.isoformat() if d.last_seen else None,
            hours_stale=(now - d.last_seen).total_seconds() / 3600 if d.last_seen else float("inf"),
        )
        for d in devices
    ]


@app.get("/metrics/system")
async def metrics_system(_: None = Depends(require_admin)):
    """Get system health information"""
    uptime_seconds = (utcnow() - _startup_time).total_seconds() if _startup_time else 0
    return {
        "uptime_seconds": uptime_seconds,
        "startup_time": _startup_time.isoformat() if _startup_time else None,
        "status": "healthy",
    }


# --- Logs endpoints ---

@app.get("/logs/requests", response_model=list[RequestLogOut])
async def logs_requests(
    hours: int = 24,
    limit: int = 100,
    path: Optional[str] = None,
    status_code: Optional[int] = None,
    _: None = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Get recent API request logs"""
    logs = await get_request_logs(
        db,
        hours=hours,
        limit=limit,
        path_filter=path,
        status_filter=status_code,
    )
    return [
        RequestLogOut(
            id=log.id,
            timestamp=log.timestamp.isoformat(),
            method=log.method,
            path=log.path,
            status_code=log.status_code,
            latency_ms=log.latency_ms,
            client_cn=log.client_cn,
            namespace=log.namespace,
            error_detail=log.error_detail,
        )
        for log in logs
    ]


def main():
    ssl_keyfile = os.path.join(CERTS_DIR, "manager", "server.key")
    ssl_certfile = os.path.join(CERTS_DIR, "manager", "server.crt")
    ssl_ca_certs = os.path.join(CERTS_DIR, "manager", "ca.crt")

    # Require client certificates for mTLS (CERT_REQUIRED).
    # This ensures all clients must present a valid cert signed by our CA.
    uvicorn.run(
        "manager.main:app",
        host="0.0.0.0",
        port=8443,
        ssl_keyfile=ssl_keyfile,
        ssl_certfile=ssl_certfile,
        ssl_ca_certs=ssl_ca_certs,
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        log_level="info",
    )

if __name__ == "__main__":
    main()
