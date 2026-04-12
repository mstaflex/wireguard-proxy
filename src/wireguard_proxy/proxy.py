"""Core UDP proxy logic.

Architecture
------------

Two UDP sockets are opened on the cloud host:

  server_port  – the home WireGuard server connects here.  Since the home
                 machine is behind CGNAT it cannot accept inbound connections,
                 so it reaches out to the proxy first.  The source address of
                 that initial (and any subsequent keepalive) packet is recorded
                 as the server address.  Data packets received on this port
                 are forwarded to all currently active clients.

  client_port  – WireGuard clients connect here, believing it to be the
                 WireGuard server endpoint.

Client packets are forwarded to the home server via the *same* server_port
socket.  This is critical: the server is registered via an outbound UDP packet
through its NAT/CGNAT, which creates a mapping only for the source address and
port the server originally sent to (server_port).  Forwarding from any other
source port (e.g. an ephemeral relay socket) would be blocked by that NAT
mapping.

Server responses arrive back on server_port and are broadcast to all active
client sessions.  WireGuard on each client silently drops packets it cannot
decrypt, so only the intended recipient processes each datagram.

Session tracking records each client's (ip, port) and last-seen time for
periodic cleanup of stale entries.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

_CLEANUP_INTERVAL = 60  # seconds between session-expiry sweeps

# Socket buffer size for both send and receive queues.  Sized to handle
# several hundred maximum-size WireGuard datagrams without dropping.
_SOCKET_BUFFER_SIZE = 4 * 1024 * 1024  # 4 MiB


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ClientSession:
    """Tracks one active WireGuard client."""

    addr: tuple[str, int]
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
        self._proxy._on_client_packet(data, addr)

    def error_received(self, exc: Exception) -> None:
        logger.error("Client-side socket error: %s", exc)


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

        self._client_transport: Optional[asyncio.DatagramTransport] = None
        self._server_transport: Optional[asyncio.DatagramTransport] = None
        self._cleanup_task: Optional[asyncio.Task[None]] = None

    # ------------------------------------------------------------------
    # Packet callbacks
    # ------------------------------------------------------------------

    def _on_server_packet(self, data: bytes, addr: tuple[str, int]) -> None:
        """Record (or update) the home server's address and forward data to all active clients."""
        if self._server_addr != addr:
            logger.info("Home server registered/updated: %s", addr)
        self._server_addr = addr

        if self._client_transport is not None and self._sessions:
            for client_addr in list(self._sessions.keys()):
                logger.debug("Forwarding server packet to client %s", client_addr)
                self._client_transport.sendto(data, client_addr)

    def _on_client_packet(self, data: bytes, addr: tuple[str, int]) -> None:
        """Handle a packet arriving from a WireGuard client."""
        if self._server_addr is None:
            logger.warning("Dropping packet from %s – no server registered yet", addr)
            return

        if addr not in self._sessions:
            # WireGuard roams: same IP may reappear on a new source port after a
            # NAT rebinding.  Drop the old stale entry so the broadcast set stays
            # lean and the client only receives traffic on its current port.
            stale = [a for a in self._sessions if a[0] == addr[0] and a != addr]
            for old_addr in stale:
                logger.info("Client %s roamed to %s – removing stale session", old_addr, addr)
                self._sessions.pop(old_addr)
            self._sessions[addr] = ClientSession(addr=addr)
            logger.info("New client session: %s", addr)

        self._sessions[addr].touch()

        # Forward via the server_port socket so the source port matches the
        # NAT mapping that the server registered with.
        if self._server_transport is not None:
            logger.debug("Forwarding client packet from %s to server %s", addr, self._server_addr)
            self._server_transport.sendto(data, self._server_addr)

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    async def _cleanup_loop(self) -> None:
        """Periodically remove inactive client sessions."""
        while True:
            expired = [
                addr
                for addr, session in list(self._sessions.items())
                if session.is_expired(self.session_timeout)
            ]
            for addr in expired:
                self._sessions.pop(addr)
                logger.info("Session expired for %s", addr)
            await asyncio.sleep(_CLEANUP_INTERVAL)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_socket(host: str, port: int) -> socket.socket:
        """Create a UDP socket with generous buffers and no PMTU discovery.

        Disabling PMTU discovery (IP_PMTUDISC_DONT on Linux) prevents the
        kernel from setting the DF bit on outgoing datagrams.  Without this,
        large WireGuard data packets (≈1368 B) are silently dropped when the
        path MTU to the next hop is lower than the datagram size — a common
        occurrence when the network path traverses an overlay (e.g. another
        WireGuard tunnel, PPPoE, or similar).  With DF disabled the kernel
        fragments instead of drops, allowing the far end to reassemble.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _SOCKET_BUFFER_SIZE)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, _SOCKET_BUFFER_SIZE)
        # IP_MTU_DISCOVER / IP_PMTUDISC_DONT is Linux-specific.
        if hasattr(socket, "IP_MTU_DISCOVER") and hasattr(socket, "IP_PMTUDISC_DONT"):
            sock.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_MTU_DISCOVER,
                socket.IP_PMTUDISC_DONT,
            )
        sock.bind((host, port))
        return sock

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Bind both listening sockets and start the background cleanup task."""
        loop = asyncio.get_running_loop()

        server_sock = self._make_socket(self.host, self.server_port)
        server_transport, _ = await loop.create_datagram_endpoint(
            lambda: _ServerSideProtocol(self),
            sock=server_sock,
        )
        self._server_transport = server_transport
        logger.info("Server listener on %s:%d", self.host, self.server_port)

        client_sock = self._make_socket(self.host, self.client_port)
        await loop.create_datagram_endpoint(
            lambda: _ClientSideProtocol(self),
            sock=client_sock,
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
        """Cancel the cleanup task and close both listening sockets."""
        if self._cleanup_task is not None:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        self._sessions.clear()

        if self._client_transport is not None:
            self._client_transport.close()
        if self._server_transport is not None:
            self._server_transport.close()

        logger.info("Proxy stopped")
