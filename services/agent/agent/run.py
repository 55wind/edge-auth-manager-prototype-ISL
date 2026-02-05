from __future__ import annotations

import argparse
import math
import os
import asyncio
import hashlib
import logging
import platform
import random
import time
from datetime import datetime, timezone

import httpx
from agent.client import register, get_token
from agent.amqp_pub import SecurePublisher
from agent.discovery import discover_manager
from agent.cert_check import check_cert_expiry

logger = logging.getLogger(__name__)

_CERT_CHECK_INTERVAL = 3600  # re-check cert expiry every hour


def hw_fingerprint() -> str:
    # Lightweight fingerprint for prototype; in production use TPM/TEE attestation or signed measurements.
    raw = f"{platform.node()}|{platform.system()}|{platform.machine()}|{platform.processor()}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

async def agent_loop(args) -> None:
    base_url = os.getenv("MANAGER_BASE_URL", "https://localhost:8443")
    amqp_url = os.getenv("AMQP_URL", "amqps://guest:guest@localhost:5671/")
    certs_dir = os.getenv("CERTS_DIR", "./certs")
    buffer_dir = os.getenv("AGENT_BUFFER_DIR", "./buffer")

    # --- Step 0: Check client certificate expiry at startup ---
    cert_path = os.path.join(certs_dir, "agent", "client.crt")
    check_cert_expiry(cert_path)
    last_cert_check = time.time()

    # --- Step 1: Discover manager endpoint ---
    base_url = discover_manager(base_url, certs_dir)

    # --- Step 2: Register device ---
    payload = {
        "domain": "default",
        "site": args.site,
        "group": args.group,
        "device_id": args.device_id,
        "hw_fingerprint": hw_fingerprint(),
        "agent_version": "0.1.0",
    }

    try:
        dev = register(base_url, certs_dir, payload)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 409:
            logger.error("Registration rejected (409 Conflict): %s", exc.response.text)
            print("Registration rejected — possible duplicate hw_fingerprint or revoked device. Exiting.")
            return
        raise

    namespace = dev["namespace"]
    status = dev.get("status")
    print("registered:", namespace, "status=", status)

    # --- Step 2b: Handle REVOKED status immediately ---
    if status == "REVOKED":
        logger.error("Device %s is REVOKED. Agent will not continue.", namespace)
        print("Device is REVOKED. Stopping agent.")
        return

    pub = SecurePublisher(
        amqp_url,
        ca_path=os.path.join(certs_dir, "rabbitmq", "ca.crt"),
        buffer_dir=buffer_dir,
        client_cert=os.path.join(certs_dir, "agent", "client.crt"),
        client_key=os.path.join(certs_dir, "agent", "client.key"),
    )

    token = None
    token_expires_at = None
    token_ttl = None

    while True:
        # Periodic certificate expiry check
        if time.time() - last_cert_check >= _CERT_CHECK_INTERVAL:
            check_cert_expiry(cert_path)
            last_cert_check = time.time()

        # Check if token needs refresh (refresh at 80% of TTL)
        if token is None or (token_expires_at and time.time() >= token_expires_at - (token_ttl * 0.2)):
            if token is not None:
                print("refreshing token before expiration...")

            t = get_token(base_url, certs_dir, namespace)
            if t.get("error"):
                status_code = t.get("status")
                detail = t.get("detail") or ""

                # If device is revoked, stop the agent loop
                if status_code == 403 and "REVOKED" in detail.upper():
                    logger.error("Device %s has been REVOKED. Stopping agent.", namespace)
                    print("Device REVOKED. Stopping agent.")
                    return

                print(f"waiting approval... HTTP {status_code} {detail[:200]}")
                await asyncio.sleep(2.0)
                continue

            token = t["access_token"]
            token_ttl = t.get("expires_in", 900)  # default to 900s if not provided
            token_expires_at = time.time() + token_ttl
            print(f"token obtained (expires_in={token_ttl}s, refresh at {int(token_ttl * 0.8)}s)")

        # Send sensor metadata
        sensor_type = os.getenv("AGENT_SENSOR_TYPE", "temperature")
        t_sec = time.time()
        if sensor_type == "humidity":
            value = 45.0 + 10.0 * math.cos(t_sec / 30.0) + random.uniform(-1.5, 1.5)
            metrics = {"humidity_pct": round(value, 2)}
        else:
            value = 20.0 + 5.0 * math.sin(t_sec / 30.0) + random.uniform(-0.5, 0.5)
            metrics = {"temperature_c": round(value, 2)}
        msg = {
            "namespace": namespace,
            "device_id": args.device_id,
            "sensor_type": sensor_type,
            "ts": now_iso(),
            "token_hint": token[:16],
            "metrics": metrics,
        }
        await pub.publish(msg)
        await asyncio.sleep(1.5)

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--device-id", required=True)
    ap.add_argument("--site", required=True)
    ap.add_argument("--group", required=True)
    args = ap.parse_args()

    asyncio.run(agent_loop(args))

if __name__ == "__main__":
    main()
