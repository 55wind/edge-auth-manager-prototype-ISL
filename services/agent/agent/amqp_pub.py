from __future__ import annotations

import asyncio
import hashlib
import hmac as hmac_mod
import json
import os
import ssl
from typing import Optional

import aiormq
from tenacity import AsyncRetrying, stop_after_attempt, wait_exponential_jitter

from agent.buffer import JsonlBuffer


class SecurePublisher:
    """AMQP TLS publisher with reconnect, local buffering, and HMAC message signing."""

    def __init__(self, amqp_url: str, ca_path: str, buffer_dir: str,
                 client_cert: Optional[str] = None, client_key: Optional[str] = None):
        self.amqp_url = amqp_url
        self.ca_path = ca_path
        self.client_cert = client_cert
        self.client_key = client_key
        self.buffer = JsonlBuffer(buffer_dir)
        self.conn: Optional[aiormq.Connection] = None
        self.chan: Optional[aiormq.Channel] = None
        self._hmac_secret = os.getenv("HMAC_SECRET", "").encode() or None

    def _ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context(cafile=self.ca_path)
        ctx.check_hostname = False
        # Present client certificate for mTLS with RabbitMQ
        if self.client_cert and self.client_key:
            ctx.load_cert_chain(certfile=self.client_cert, keyfile=self.client_key)
        return ctx

    def _sign_message(self, payload_bytes: bytes) -> str:
        """Compute HMAC-SHA256 signature for message integrity."""
        if not self._hmac_secret:
            return ""
        return hmac_mod.new(self._hmac_secret, payload_bytes, hashlib.sha256).hexdigest()

    async def connect(self) -> None:
        ctx = self._ssl_context()
        # Use amqp:// scheme with explicit ssl context to avoid
        # duplicate ssl argument when amqps:// auto-creates one.
        url = self.amqp_url.replace("amqps://", "amqp://", 1)
        self.conn = await aiormq.connect(url, ssl=ctx)
        self.chan = await self.conn.channel()
        # durable queue for prototype
        await self.chan.queue_declare("agent.metadata", durable=True)

    async def close(self) -> None:
        try:
            if self.chan:
                await self.chan.close()
        finally:
            self.chan = None
        try:
            if self.conn:
                await self.conn.close()
        finally:
            self.conn = None

    async def publish(self, msg: dict) -> None:
        # Always attempt flush first
        await self.flush()

        if not self.chan:
            await self._reconnect()

        try:
            body = json.dumps(msg, ensure_ascii=False).encode("utf-8")
            # Add HMAC signature header for message integrity
            sig = self._sign_message(body)
            if sig:
                msg["_hmac"] = sig
                body = json.dumps(msg, ensure_ascii=False).encode("utf-8")
            await self.chan.basic_publish(body, routing_key="agent.metadata")
        except Exception:
            # Buffer and reconnect later
            self.buffer.append(msg)
            await self._reconnect()

    async def flush(self) -> None:
        # Try to drain buffer
        drained = self.buffer.drain(limit=200)
        if not drained:
            return
        if not self.chan:
            await self._reconnect()
        for item in drained:
            try:
                body = json.dumps(item, ensure_ascii=False).encode("utf-8")
                await self.chan.basic_publish(body, routing_key="agent.metadata")
            except Exception:
                # Put back and stop flushing
                self.buffer.append(item)
                await self._reconnect()
                break

    async def _reconnect(self) -> None:
        await self.close()
        await self._reconnect_with_backoff()

    async def _reconnect_with_backoff(self) -> None:
        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(30),
            wait=wait_exponential_jitter(initial=0.5, max=20),
            reraise=False,
        ):
            with attempt:
                await self.connect()
                return
        # if still failing, keep offline; caller will buffer
        return
