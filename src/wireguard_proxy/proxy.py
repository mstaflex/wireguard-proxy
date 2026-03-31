"""Core UDP proxy logic.

Architecture
------------

Two UDP sockets are opened on the cloud host:

  server_port  – the home WireGuard server connects here.  Since the home
                 machine is behind CGNAT it cannot accept inbound connections,
                 so it reaches out to the proxy first.  The source address of
                 that initial (and any subsequent keepalive) packet is recorded
                 as the server address.

  client_port  – WireGuard clients connect here, believing it to be the
                 WireGuard server endpoint.

For every distinct client (ip, port) a dedicated *relay socket* is opened on
an ephemeral local port.  The relay socket forwards client packets to the home
server and receives the home server's responses, routing them back to the
correct client.

Using per-client relay sockets means the home WireGuard instance sees each
client as arriving from a different source port, which lets WireGuard's own
peer-tracking work correctly.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

_CLEANUP_INTERVAL = 60  # seconds between session-expiry sweeps


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ClientSession:
    """Tracks one active WireGuard client and its relay transport."""

    addr: tuple[str, int]
    transport: asyncio.DatagramTransport
    last_seen: float = field(default_factory=time.monotonic)

    def touch(self) -> None:
        self.last_seen = time.monotonic()

    def is_expired(self, timeout: float) -> bool:
        return time.monotonic() - self.last_seen > timeout


# ---------------------------------------------------------------------------
# asyncio protocol implementations
# ---------------------------------------------------------------------------


class _ServerSideProtocol(asyncio.DatagramProtocol):
    """Listens on server_port for home-server registration / keepalives."""

    def __init__(self, proxy: UDPProxy) -> None:
        self._proxy = proxy
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self._proxy._on_server_packet(data, addr)

    def error_received(self, exc: Exception) -> None:
        logger.error("Server-side socket error: %s", exc)


class _ClientSideProtocol(asyncio.DatagramProtocol):
    """Listens on client_port for WireGuard client traffic."""

    def __init__(self, proxy: UDPProxy) -> None:
        self._proxy = proxy

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self._proxy._client_transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        asyncio.get_running_loop().create_task(self._proxy._on_client_packet(data, addr))

    def error_received(self, exc: Exception) -> None:
        logger.error("Client-side socket error: %s", exc)


class _RelayProtocol(asyncio.DatagramProtocol):
    """Per-client relay socket – tunnels traffic between a client and the server."""

    def __init__(self, proxy: UDPProxy, client_addr: tuple[str, int]) -> None:
        self._proxy = proxy
        self._client_addr = client_addr
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        # Response from home server → forward to the WireGuard client.
        self._proxy._forward_to_client(self._client_addr, data)

    def error_received(self, exc: Exception) -> None:
        logger.error("Relay socket error for %s: %s", self._client_addr, exc)


# ---------------------------------------------------------------------------
# Proxy
# ---------------------------------------------------------------------------


class UDPProxy:
    """UDP relay proxy for WireGuard through CGNAT."""

    def __init__(
        self,
        server_port: int,
        client_port: int,
        host: str = "0.0.0.0",
        session_timeout: int = 300,
    ) -> None:
        self.server_port = server_port
        self.client_port = client_port
        self.host = host
        self.session_timeout = session_timeout

        self._server_addr: Optional[tuple[str, int]] = None
        self._sessions: dict[tuple[str, int], ClientSession] = {}
        # Addresses of clients whose session is currently being opened so we
        # do not race into _open_session() twice for the same client.
        self._pending_sessions: set[tuple[str, int]] = set()

        self._client_transport: Optional[asyncio.DatagramTransport] = None
        self._server_transport: Optional[asyncio.DatagramTransport] = None
        self._cleanup_task: Optional[asyncio.Task[None]] = None

    # ------------------------------------------------------------------
    # Packet callbacks
    # ------------------------------------------------------------------

    def _on_server_packet(self, data: bytes, addr: tuple[str, int]) -> None:
        """Record (or update) the home server's public address."""
        if self._server_addr != addr:
            logger.info("Home server registered/updated: %s", addr)
        self._server_addr = addr

    def _forward_to_client(self, client_addr: tuple[str, int], data: bytes) -> None:
        """Send a packet received from the home server back to a WireGuard client."""
        if self._client_transport is not None:
            self._client_transport.sendto(data, client_addr)

    async def _on_client_packet(self, data: bytes, addr: tuple[str, int]) -> None:
        """Handle a packet arriving from a WireGuard client."""
        if self._server_addr is None:
            logger.warning("Dropping packet from %s – no server registered yet", addr)
            return

        if addr not in self._sessions:
            if addr in self._pending_sessions:
                # Session is being set up; drop this packet (UDP delivery is
                # best-effort, WireGuard will retransmit).
                return
            self._pending_sessions.add(addr)
            try:
                await self._open_session(addr)
            finally:
                self._pending_sessions.discard(addr)

        if addr in self._sessions:
            session = self._sessions[addr]
            session.touch()
            session.transport.sendto(data, self._server_addr)

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    async def _open_session(self, client_addr: tuple[str, int]) -> None:
        loop = asyncio.get_running_loop()
        relay = _RelayProtocol(self, client_addr)
        transport, _ = await loop.create_datagram_endpoint(
            lambda: relay,
            local_addr=(self.host, 0),
        )
        self._sessions[client_addr] = ClientSession(addr=client_addr, transport=transport)
        logger.info("Opened relay session for client %s", client_addr)

    async def _cleanup_loop(self) -> None:
        """Periodically close relay sockets for inactive clients."""
        while True:
            expired = [
                addr
                for addr, session in list(self._sessions.items())
                if session.is_expired(self.session_timeout)
            ]
            for addr in expired:
                session = self._sessions.pop(addr)
                session.transport.close()
                logger.info("Session expired for %s", addr)
            await asyncio.sleep(_CLEANUP_INTERVAL)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Bind both listening sockets and start the background cleanup task."""
        loop = asyncio.get_running_loop()

        server_transport, _ = await loop.create_datagram_endpoint(
            lambda: _ServerSideProtocol(self),
            local_addr=(self.host, self.server_port),
        )
        self._server_transport = server_transport
        logger.info("Server listener on %s:%d", self.host, self.server_port)

        await loop.create_datagram_endpoint(
            lambda: _ClientSideProtocol(self),
            local_addr=(self.host, self.client_port),
        )
        # _client_transport is populated via _ClientSideProtocol.connection_made
        logger.info("Client listener on %s:%d", self.host, self.client_port)

        self._cleanup_task = loop.create_task(self._cleanup_loop())
        logger.info(
            "Proxy started (server_port=%d, client_port=%d, timeout=%ds)",
            self.server_port,
            self.client_port,
            self.session_timeout,
        )

    async def stop(self) -> None:
        """Cancel the cleanup task, close all relay sockets, and close listeners."""
        if self._cleanup_task is not None:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        for session in self._sessions.values():
            session.transport.close()
        self._sessions.clear()

        if self._client_transport is not None:
            self._client_transport.close()
        if self._server_transport is not None:
            self._server_transport.close()

        logger.info("Proxy stopped")
