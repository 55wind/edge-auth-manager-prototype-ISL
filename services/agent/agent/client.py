from __future__ import annotations

import os
import ssl
import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential_jitter


def _not_409(exc: BaseException) -> bool:
    """Don't retry HTTP 409 Conflict — it's a definitive rejection."""
    if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 409:
        return False
    return True

def _mtls_client(base_url: str, certs_dir: str) -> httpx.Client:
    ca = os.path.join(certs_dir, "agent", "ca.crt")
    crt = os.path.join(certs_dir, "agent", "client.crt")
    key = os.path.join(certs_dir, "agent", "client.key")

    # Verify server with CA; present client cert for mTLS.
    return httpx.Client(
        base_url=base_url,
        verify=ca,
        cert=(crt, key),
        timeout=10.0,
    )

@retry(stop=stop_after_attempt(5), wait=wait_exponential_jitter(initial=0.5, max=8), retry=retry_if_exception(_not_409))
def register(base_url: str, certs_dir: str, payload: dict) -> dict:
    with _mtls_client(base_url, certs_dir) as c:
        r = c.post("/device/register", json=payload)
        r.raise_for_status()
        return r.json()

@retry(stop=stop_after_attempt(5), wait=wait_exponential_jitter(initial=0.5, max=8))
def get_token(base_url: str, certs_dir: str, namespace: str) -> dict:
    with _mtls_client(base_url, certs_dir) as c:
        r = c.post("/auth/token", json={"namespace": namespace})
        # token requires approval; keep error body for the agent loop
        if r.status_code >= 400:
            return {"error": True, "status": r.status_code, "detail": r.text}
        return r.json()
