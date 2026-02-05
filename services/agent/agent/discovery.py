"""Manager endpoint discovery - validates connectivity before registration."""
from __future__ import annotations

import logging
from tenacity import retry, stop_after_attempt, wait_exponential_jitter

from agent.client import _mtls_client

logger = logging.getLogger(__name__)


@retry(stop=stop_after_attempt(5), wait=wait_exponential_jitter(initial=1.0, max=15))
def discover_manager(base_url: str, certs_dir: str) -> str:
    """Probe the manager /healthz endpoint with mTLS to confirm reachability.

    Returns the verified base_url or raises on failure.
    """
    logger.info("Discovering manager at %s ...", base_url)
    with _mtls_client(base_url, certs_dir) as c:
        r = c.get("/healthz")
        r.raise_for_status()
        data = r.json()
        if not data.get("ok"):
            raise RuntimeError("Manager /healthz returned unexpected payload")
    logger.info("Manager discovered successfully at %s", base_url)
    return base_url
