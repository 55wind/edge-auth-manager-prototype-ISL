from __future__ import annotations

import os
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy import String, DateTime, Integer, Float, Boolean, Text, select, update, delete, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

class Base(DeclarativeBase):
    pass

class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    namespace: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(16), default="PENDING")
    hw_fingerprint: Mapped[str] = mapped_column(String(128))
    agent_version: Mapped[str] = mapped_column(String(32), default="0.1.0")
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

class CertState(Base):
    __tablename__ = "certs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    namespace: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    not_after: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class RequestLog(Base):
    """API request tracking for metrics"""
    __tablename__ = "request_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    method: Mapped[str] = mapped_column(String(10))
    path: Mapped[str] = mapped_column(String(255), index=True)
    status_code: Mapped[int] = mapped_column(Integer)
    latency_ms: Mapped[float] = mapped_column(Float)
    client_cn: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    namespace: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    error_detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class AuthEvent(Base):
    """Authentication event tracking"""
    __tablename__ = "auth_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    namespace: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(32))  # TOKEN_ISSUED, TOKEN_DENIED, VALIDATION_OK, VALIDATION_FAILED
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    failure_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)


class SecurityIncident(Base):
    """Security incident tracking"""
    __tablename__ = "security_incidents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    severity: Mapped[str] = mapped_column(String(16))  # LOW, MEDIUM, HIGH, CRITICAL
    incident_type: Mapped[str] = mapped_column(String(64), index=True)
    namespace: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    description: Mapped[str] = mapped_column(Text)
    resolved: Mapped[bool] = mapped_column(Boolean, default=False)

async def init_db(db_url: str) -> async_sessionmaker[AsyncSession]:
    engine = create_async_engine(db_url, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return async_sessionmaker(engine, expire_on_commit=False)

async def get_device(session: AsyncSession, namespace: str) -> Optional[Device]:
    res = await session.execute(select(Device).where(Device.namespace == namespace))
    return res.scalar_one_or_none()

async def upsert_device_pending(session: AsyncSession, namespace: str, hw_fingerprint: str, agent_version: str) -> Device:
    dev = await get_device(session, namespace)
    if dev is None:
        dev = Device(namespace=namespace, status="PENDING", hw_fingerprint=hw_fingerprint, agent_version=agent_version)
        session.add(dev)
    else:
        # keep existing status; update fields
        dev.hw_fingerprint = hw_fingerprint
        dev.agent_version = agent_version
    dev.last_seen = utcnow()
    await session.commit()
    await session.refresh(dev)
    return dev

async def set_device_status(session: AsyncSession, namespace: str, status: str) -> None:
    await session.execute(update(Device).where(Device.namespace == namespace).values(status=status))
    await session.commit()

async def list_devices(session: AsyncSession) -> list[Device]:
    res = await session.execute(select(Device).order_by(Device.namespace))
    return list(res.scalars().all())

async def touch_device(session: AsyncSession, namespace: str) -> None:
    await session.execute(update(Device).where(Device.namespace == namespace).values(last_seen=utcnow()))
    await session.commit()

async def set_cert(session: AsyncSession, namespace: str, status: str, not_after: Optional[datetime]) -> None:
    res = await session.execute(select(CertState).where(CertState.namespace == namespace))
    row = res.scalar_one_or_none()
    if row is None:
        row = CertState(namespace=namespace, status=status, not_after=not_after)
        session.add(row)
    else:
        row.status = status
        row.not_after = not_after
    await session.commit()

async def get_cert(session: AsyncSession, namespace: str) -> Optional[CertState]:
    res = await session.execute(select(CertState).where(CertState.namespace == namespace))
    return res.scalar_one_or_none()


# --- Request logging functions ---

async def log_request(
    session: AsyncSession,
    method: str,
    path: str,
    status_code: int,
    latency_ms: float,
    client_cn: Optional[str] = None,
    namespace: Optional[str] = None,
    error_detail: Optional[str] = None,
) -> None:
    """Log an API request for metrics tracking"""
    log = RequestLog(
        method=method,
        path=path,
        status_code=status_code,
        latency_ms=latency_ms,
        client_cn=client_cn,
        namespace=namespace,
        error_detail=error_detail,
    )
    session.add(log)
    await session.commit()


async def get_request_stats(session: AsyncSession, hours: int = 24) -> dict:
    """Get request statistics for the specified time period"""
    since = utcnow() - timedelta(hours=hours)

    # Total requests
    total_res = await session.execute(
        select(func.count(RequestLog.id)).where(RequestLog.timestamp >= since)
    )
    total = total_res.scalar() or 0

    # Error count (5xx)
    error_res = await session.execute(
        select(func.count(RequestLog.id)).where(
            RequestLog.timestamp >= since,
            RequestLog.status_code >= 500
        )
    )
    errors = error_res.scalar() or 0

    # Latency percentiles
    latency_res = await session.execute(
        select(RequestLog.latency_ms).where(RequestLog.timestamp >= since).order_by(RequestLog.latency_ms)
    )
    latencies = [r[0] for r in latency_res.fetchall()]

    p50, p95, p99 = 0.0, 0.0, 0.0
    if latencies:
        n = len(latencies)
        p50 = latencies[int(n * 0.50)] if n > 0 else 0.0
        p95 = latencies[int(n * 0.95)] if n > 0 else 0.0
        p99 = latencies[int(n * 0.99)] if n > 0 else 0.0

    return {
        "total_requests": total,
        "error_count": errors,
        "error_rate": (errors / total * 100) if total > 0 else 0.0,
        "latency_p50_ms": p50,
        "latency_p95_ms": p95,
        "latency_p99_ms": p99,
    }


async def get_hourly_request_volume(session: AsyncSession, hours: int = 24) -> list[dict]:
    """Get request volume grouped by hour"""
    since = utcnow() - timedelta(hours=hours)

    res = await session.execute(
        select(RequestLog).where(RequestLog.timestamp >= since).order_by(RequestLog.timestamp)
    )
    logs = res.scalars().all()

    # Group by hour
    hourly: dict[str, dict] = {}
    for log in logs:
        hour_key = log.timestamp.strftime("%Y-%m-%d %H:00")
        if hour_key not in hourly:
            hourly[hour_key] = {"hour": hour_key, "total": 0, "errors": 0}
        hourly[hour_key]["total"] += 1
        if log.status_code >= 500:
            hourly[hour_key]["errors"] += 1

    return list(hourly.values())


async def get_request_logs(
    session: AsyncSession,
    hours: int = 24,
    limit: int = 100,
    path_filter: Optional[str] = None,
    status_filter: Optional[int] = None,
) -> list[RequestLog]:
    """Get recent request logs"""
    since = utcnow() - timedelta(hours=hours)

    query = select(RequestLog).where(RequestLog.timestamp >= since)

    if path_filter:
        query = query.where(RequestLog.path.contains(path_filter))
    if status_filter:
        query = query.where(RequestLog.status_code == status_filter)

    query = query.order_by(RequestLog.timestamp.desc()).limit(limit)

    res = await session.execute(query)
    return list(res.scalars().all())


async def get_endpoint_stats(session: AsyncSession, hours: int = 24) -> list[dict]:
    """Get statistics grouped by endpoint"""
    since = utcnow() - timedelta(hours=hours)

    res = await session.execute(
        select(RequestLog).where(RequestLog.timestamp >= since)
    )
    logs = res.scalars().all()

    # Group by path
    by_path: dict[str, dict] = {}
    for log in logs:
        if log.path not in by_path:
            by_path[log.path] = {"path": log.path, "count": 0, "errors": 0, "latencies": []}
        by_path[log.path]["count"] += 1
        by_path[log.path]["latencies"].append(log.latency_ms)
        if log.status_code >= 400:
            by_path[log.path]["errors"] += 1

    result = []
    for path, data in by_path.items():
        latencies = sorted(data["latencies"])
        n = len(latencies)
        result.append({
            "path": path,
            "count": data["count"],
            "errors": data["errors"],
            "error_rate": (data["errors"] / data["count"] * 100) if data["count"] > 0 else 0.0,
            "avg_latency_ms": sum(latencies) / n if n > 0 else 0.0,
            "p95_latency_ms": latencies[int(n * 0.95)] if n > 0 else 0.0,
        })

    return sorted(result, key=lambda x: x["count"], reverse=True)


# --- Auth event functions ---

async def log_auth_event(
    session: AsyncSession,
    event_type: str,
    success: bool,
    namespace: Optional[str] = None,
    failure_reason: Optional[str] = None,
) -> None:
    """Log an authentication event"""
    event = AuthEvent(
        event_type=event_type,
        namespace=namespace,
        success=success,
        failure_reason=failure_reason,
    )
    session.add(event)
    await session.commit()


async def get_auth_stats(session: AsyncSession, hours: int = 24) -> dict:
    """Get authentication statistics"""
    since = utcnow() - timedelta(hours=hours)

    # Total auth attempts
    total_res = await session.execute(
        select(func.count(AuthEvent.id)).where(AuthEvent.timestamp >= since)
    )
    total = total_res.scalar() or 0

    # Successful auth
    success_res = await session.execute(
        select(func.count(AuthEvent.id)).where(
            AuthEvent.timestamp >= since,
            AuthEvent.success == True
        )
    )
    successes = success_res.scalar() or 0

    failures = total - successes

    # Failure reasons breakdown
    reason_res = await session.execute(
        select(AuthEvent.failure_reason, func.count(AuthEvent.id)).where(
            AuthEvent.timestamp >= since,
            AuthEvent.success == False
        ).group_by(AuthEvent.failure_reason)
    )
    failure_reasons = {(r[0] or "unknown"): r[1] for r in reason_res.fetchall()}

    # Event type breakdown
    type_res = await session.execute(
        select(AuthEvent.event_type, func.count(AuthEvent.id)).where(
            AuthEvent.timestamp >= since
        ).group_by(AuthEvent.event_type)
    )
    by_type = {r[0]: r[1] for r in type_res.fetchall()}

    return {
        "total_attempts": total,
        "successes": successes,
        "failures": failures,
        "success_rate": (successes / total * 100) if total > 0 else 100.0,
        "failure_reasons": failure_reasons,
        "by_event_type": by_type,
    }


async def get_hourly_auth_stats(session: AsyncSession, hours: int = 24) -> list[dict]:
    """Get auth events grouped by hour"""
    since = utcnow() - timedelta(hours=hours)

    res = await session.execute(
        select(AuthEvent).where(AuthEvent.timestamp >= since).order_by(AuthEvent.timestamp)
    )
    events = res.scalars().all()

    hourly: dict[str, dict] = {}
    for event in events:
        hour_key = event.timestamp.strftime("%Y-%m-%d %H:00")
        if hour_key not in hourly:
            hourly[hour_key] = {"hour": hour_key, "success": 0, "failure": 0}
        if event.success:
            hourly[hour_key]["success"] += 1
        else:
            hourly[hour_key]["failure"] += 1

    return list(hourly.values())


async def get_device_auth_stats(session: AsyncSession, hours: int = 24) -> list[dict]:
    """Get auth statistics per device"""
    since = utcnow() - timedelta(hours=hours)

    res = await session.execute(
        select(
            AuthEvent.namespace,
            func.count(AuthEvent.id).label("total"),
            func.sum(func.cast(AuthEvent.success, Integer)).label("successes")
        ).where(
            AuthEvent.timestamp >= since,
            AuthEvent.namespace.isnot(None)
        ).group_by(AuthEvent.namespace)
    )

    result = []
    for row in res.fetchall():
        total = row[1]
        successes = row[2] or 0
        result.append({
            "namespace": row[0],
            "total": total,
            "successes": successes,
            "failures": total - successes,
            "success_rate": (successes / total * 100) if total > 0 else 100.0,
        })

    return sorted(result, key=lambda x: x["total"], reverse=True)


# --- Security incident functions ---

async def log_security_incident(
    session: AsyncSession,
    severity: str,
    incident_type: str,
    description: str,
    namespace: Optional[str] = None,
) -> SecurityIncident:
    """Log a security incident"""
    incident = SecurityIncident(
        severity=severity,
        incident_type=incident_type,
        namespace=namespace,
        description=description,
    )
    session.add(incident)
    await session.commit()
    await session.refresh(incident)
    return incident


async def get_security_incidents(session: AsyncSession, days: int = 7, unresolved_only: bool = False) -> list[SecurityIncident]:
    """Get security incidents for the specified period"""
    since = utcnow() - timedelta(days=days)

    query = select(SecurityIncident).where(SecurityIncident.timestamp >= since)
    if unresolved_only:
        query = query.where(SecurityIncident.resolved == False)
    query = query.order_by(SecurityIncident.timestamp.desc())

    res = await session.execute(query)
    return list(res.scalars().all())


async def get_incident_counts(session: AsyncSession, days: int = 7) -> dict:
    """Get incident counts by severity"""
    since = utcnow() - timedelta(days=days)

    res = await session.execute(
        select(SecurityIncident.severity, func.count(SecurityIncident.id)).where(
            SecurityIncident.timestamp >= since,
            SecurityIncident.resolved == False
        ).group_by(SecurityIncident.severity)
    )

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for row in res.fetchall():
        counts[row[0]] = row[1]

    return counts


async def resolve_incident(session: AsyncSession, incident_id: int) -> bool:
    """Mark an incident as resolved"""
    result = await session.execute(
        update(SecurityIncident).where(SecurityIncident.id == incident_id).values(resolved=True)
    )
    await session.commit()
    return result.rowcount > 0


async def get_incidents_by_type(session: AsyncSession, days: int = 7) -> list[dict]:
    """Get incident counts by type"""
    since = utcnow() - timedelta(days=days)

    res = await session.execute(
        select(SecurityIncident.incident_type, func.count(SecurityIncident.id)).where(
            SecurityIncident.timestamp >= since
        ).group_by(SecurityIncident.incident_type)
    )

    return [{"type": r[0], "count": r[1]} for r in res.fetchall()]


# --- Device statistics functions ---

async def get_device_counts_by_status(session: AsyncSession) -> dict:
    """Get device counts grouped by status"""
    res = await session.execute(
        select(Device.status, func.count(Device.id)).group_by(Device.status)
    )

    counts = {"PENDING": 0, "APPROVED": 0, "REVOKED": 0}
    for row in res.fetchall():
        counts[row[0]] = row[1]

    counts["total"] = sum(counts.values())
    return counts


async def get_stale_devices(session: AsyncSession, stale_hours: int = 24) -> list[Device]:
    """Get devices that haven't been seen recently"""
    cutoff = utcnow() - timedelta(hours=stale_hours)

    res = await session.execute(
        select(Device).where(
            Device.status == "APPROVED",
            Device.last_seen < cutoff
        )
    )
    return list(res.scalars().all())


# --- Cleanup functions ---

async def cleanup_old_records(session: AsyncSession, retention_days: int = 7) -> dict:
    """Remove records older than retention period"""
    cutoff = utcnow() - timedelta(days=retention_days)

    # Clean request logs
    req_result = await session.execute(
        delete(RequestLog).where(RequestLog.timestamp < cutoff)
    )
    req_deleted = req_result.rowcount

    # Clean auth events
    auth_result = await session.execute(
        delete(AuthEvent).where(AuthEvent.timestamp < cutoff)
    )
    auth_deleted = auth_result.rowcount

    # Clean resolved incidents
    incident_result = await session.execute(
        delete(SecurityIncident).where(
            SecurityIncident.timestamp < cutoff,
            SecurityIncident.resolved == True
        )
    )
    incident_deleted = incident_result.rowcount

    await session.commit()

    return {
        "request_logs_deleted": req_deleted,
        "auth_events_deleted": auth_deleted,
        "incidents_deleted": incident_deleted,
    }
