"""X.509 certificate expiry monitoring for agent client certificates."""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

_EXPIRY_WARNING_DAYS = 7


def check_cert_expiry(cert_path: str) -> Optional[datetime]:
    """Read an X.509 PEM certificate and return its notAfter datetime.

    Logs a warning if the certificate expires within _EXPIRY_WARNING_DAYS days.
    Returns None if the file cannot be parsed.
    """
    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        not_after = cert.not_valid_after_utc
        remaining = not_after - datetime.now(timezone.utc)
        if remaining < timedelta(days=_EXPIRY_WARNING_DAYS):
            logger.warning(
                "Certificate %s expires in %s (at %s)",
                cert_path,
                remaining,
                not_after.isoformat(),
            )
        else:
            logger.info(
                "Certificate %s valid until %s (%s remaining)",
                cert_path,
                not_after.isoformat(),
                remaining,
            )
        return not_after
    except Exception:
        logger.exception("Failed to check certificate expiry for %s", cert_path)
        return None
