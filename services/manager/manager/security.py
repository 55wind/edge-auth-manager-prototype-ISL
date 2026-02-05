from __future__ import annotations

import base64
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from jose import jwt

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def issue_jwt(*, subject: str, roles: list[str], issuer: str, audience: str, ttl_seconds: int, secret: str, jti: Optional[str] = None) -> str:
    now = utcnow()
    payload: Dict[str, Any] = {
        "sub": subject,
        "roles": roles,
        "iss": issuer,
        "aud": audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
    }
    if jti:
        payload["jti"] = jti
    return jwt.encode(payload, secret, algorithm="HS256")

def verify_jwt(token: str, *, issuer: str, audience: str, secret: str) -> dict:
    return jwt.decode(token, secret, algorithms=["HS256"], issuer=issuer, audience=audience)

def random_secret(n_bytes: int = 32) -> str:
    return base64.urlsafe_b64encode(os.urandom(n_bytes)).decode("utf-8").rstrip("=")
