"""Connection gating via Pushover notifications and one-time allow URLs.

Flow
----
1. A new peer (server or client) sends its first packet.
2. GateKeeper fires a Pushover notification containing a signed, time-limited
   allow URL (e.g. http://my-proxy.example.com:8080/allow?token=…).
3. All packets from that peer are silently dropped until the user taps
   "Allow" in the notification, which GETs the allow endpoint.
4. After approval the peer's *IP address* is permanently whitelisted
   for the lifetime of the proxy process.  Port changes (NAT roaming)
   do not require re-approval.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

_PUSHOVER_API = "https://api.pushover.net/1/messages.json"


@dataclass
class _PendingToken:
    ip: str
    label: str
    expires_at: float


class GateKeeper:
    """Approves new connections via a Pushover-based allow-URL workflow."""

    def __init__(
        self,
        pushover_token: str,
        pushover_user: str,
        public_url: str,
        http_port: int = 8080,
        token_ttl: int = 600,
    ) -> None:
        self._pushover_token = pushover_token
        self._pushover_user = pushover_user
        self._public_url = public_url.rstrip("/")
        self._http_port = http_port
        self._token_ttl = token_ttl

        # token -> _PendingToken (one-time, time-limited)
        self._pending: dict[str, _PendingToken] = {}
        # IPs permanently approved for this process lifetime
        self._approved: set[str] = set()

        self._http_server: Optional[asyncio.Server] = None

    # ------------------------------------------------------------------
    # Public API used by UDPProxy
    # ------------------------------------------------------------------

    def is_approved(self, ip: str) -> bool:
        """Return True if *ip* has been approved by the user."""
        return ip in self._approved

    def has_pending_token(self, ip: str) -> bool:
        """Return True if a still-valid token for *ip* was already issued."""
        now = time.monotonic()
        return any(
            e.ip == ip and e.expires_at > now for e in self._pending.values()
        )

    async def request_approval(self, ip: str, label: str) -> None:
        """Issue a token and send a Pushover notification for *ip*."""
        token = secrets.token_urlsafe(24)
        self._pending[token] = _PendingToken(
            ip=ip,
            label=label,
            expires_at=time.monotonic() + self._token_ttl,
        )
        allow_url = f"{self._public_url}:{self._http_port}/allow?token={token}"
        logger.info("Approval pending for %s  allow-URL: %s", label, allow_url)
        await self._send_push(
            title="WireGuard Proxy: new connection",
            message=f"{label} is trying to connect.",
            url=allow_url,
            url_title="Allow connection",
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        self._http_server = await asyncio.start_server(
            self._handle_http, "0.0.0.0", self._http_port
        )
        logger.info("Gate HTTP server on 0.0.0.0:%d", self._http_port)

    async def stop(self) -> None:
        if self._http_server is not None:
            self._http_server.close()
            await self._http_server.wait_closed()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _send_push(
        self, title: str, message: str, url: str, url_title: str
    ) -> None:
        loop = asyncio.get_running_loop()
        payload = urllib.parse.urlencode(
            {
                "token": self._pushover_token,
                "user": self._pushover_user,
                "title": title,
                "message": message,
                "url": url,
                "url_title": url_title,
                "priority": 0,
            }
        ).encode()

        def _post() -> None:
            req = urllib.request.Request(
                _PUSHOVER_API, data=payload, method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                logger.debug("Pushover response: HTTP %d", resp.status)

        try:
            await loop.run_in_executor(None, _post)
        except Exception as exc:
            logger.error("Pushover notification failed: %s", exc)

    async def _handle_http(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        try:
            raw = await asyncio.wait_for(reader.readline(), timeout=5.0)
            request_line = raw.decode(errors="replace").strip()

            # Consume and discard headers.
            while True:
                hdr = await asyncio.wait_for(reader.readline(), timeout=5.0)
                if hdr in (b"\r\n", b"\n", b""):
                    break

            parts = request_line.split(" ")
            path = parts[1] if len(parts) >= 2 else "/"
            parsed = urllib.parse.urlparse(path)
            qs = urllib.parse.parse_qs(parsed.query)

            if parsed.path == "/allow" and "token" in qs:
                label = self._activate(qs["token"][0])
                if label is not None:
                    logger.info("Gate opened for %r (approved by %s)", label, peer)
                    body = (
                        b"<html><body>"
                        b"<h2>Connection approved</h2>"
                        b"<p>The proxy will now forward traffic.</p>"
                        b"</body></html>"
                    )
                    status = b"200 OK"
                else:
                    body = b"<html><body><h2>Token invalid or expired.</h2></body></html>"
                    status = b"400 Bad Request"
            else:
                body = b"<html><body><h2>Not found.</h2></body></html>"
                status = b"404 Not Found"

            response = (
                b"HTTP/1.1 " + status + b"\r\n"
                b"Content-Type: text/html; charset=utf-8\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n"
                b"\r\n" + body
            )
            writer.write(response)
            await writer.drain()
        except Exception as exc:
            logger.debug("HTTP handler error from %s: %s", peer, exc)
        finally:
            writer.close()

    def _activate(self, token: str) -> Optional[str]:
        """Whitelist the IP for *token*.  Returns the label or None on failure."""
        entry = self._pending.pop(token, None)
        if entry is None:
            logger.warning("Unknown or already-used token presented")
            return None
        if time.monotonic() > entry.expires_at:
            logger.warning("Expired token presented for %s", entry.label)
            return None
        self._approved.add(entry.ip)
        return entry.label
