"""Tests for the core proxy logic."""

from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from wireguard_proxy.proxy import ClientSession, UDPProxy

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SERVER_ADDR = ("1.2.3.4", 51820)
CLIENT_A = ("10.0.0.1", 12345)
CLIENT_B = ("10.0.0.2", 12346)
DATA = b"wireguard-test-packet"


def make_transport() -> MagicMock:
    t: MagicMock = MagicMock()
    t.sendto = MagicMock()
    t.close = MagicMock()
    return t


def _patch_create_endpoint(
    loop: asyncio.AbstractEventLoop,
    transport: MagicMock,
) -> Any:
    """Return a context-manager patch that makes create_datagram_endpoint return
    the given transport without touching the real network."""

    async def _fake(factory: Any, **kwargs: Any) -> tuple[MagicMock, Any]:
        proto = factory()
        proto.connection_made(transport)
        return transport, proto

    return patch.object(loop, "create_datagram_endpoint", side_effect=_fake)


# ---------------------------------------------------------------------------
# ClientSession
# ---------------------------------------------------------------------------


class TestClientSession:
    def test_is_expired_when_old(self) -> None:
        session = ClientSession(
            addr=CLIENT_A,
            transport=make_transport(),
            last_seen=time.monotonic() - 400,
        )
        assert session.is_expired(300)

    def test_not_expired_when_fresh(self) -> None:
        session = ClientSession(addr=CLIENT_A, transport=make_transport())
        assert not session.is_expired(300)

    def test_touch_resets_expiry(self) -> None:
        session = ClientSession(
            addr=CLIENT_A,
            transport=make_transport(),
            last_seen=time.monotonic() - 400,
        )
        session.touch()
        assert not session.is_expired(300)


# ---------------------------------------------------------------------------
# Server registration
# ---------------------------------------------------------------------------


class TestServerRegistration:
    def test_registers_server_address(self) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821)
        proxy._on_server_packet(b"keepalive", SERVER_ADDR)
        assert proxy._server_addr == SERVER_ADDR

    def test_updates_server_address(self) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821)
        proxy._on_server_packet(b"keepalive", SERVER_ADDR)
        new_addr = ("9.9.9.9", 4321)
        proxy._on_server_packet(b"keepalive", new_addr)
        assert proxy._server_addr == new_addr

    def test_initial_server_addr_is_none(self) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821)
        assert proxy._server_addr is None


# ---------------------------------------------------------------------------
# Client packet handling
# ---------------------------------------------------------------------------


class TestClientPacketHandling:
    async def test_drops_packet_when_no_server_registered(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821)
        import logging

        with caplog.at_level(logging.WARNING):
            await proxy._on_client_packet(DATA, CLIENT_A)

        assert CLIENT_A not in proxy._sessions
        assert "no server registered" in caplog.text.lower()

    async def test_creates_session_for_new_client(self) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821)
        proxy._server_addr = SERVER_ADDR
        loop = asyncio.get_running_loop()

        with _patch_create_endpoint(loop, make_transport()):
            await proxy._on_client_packet(DATA, CLIENT_A)

        assert CLIENT_A in proxy._sessions

    async def test_forwards_packet_to_server(self) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821)
        proxy._server_addr = SERVER_ADDR
        relay_transport = make_transport()
        loop = asyncio.get_running_loop()

        with _patch_create_endpoint(loop, relay_transport):
            await proxy._on_client_packet(DATA, CLIENT_A)

        relay_transport.sendto.assert_called_once_with(DATA, SERVER_ADDR)

    async def test_reuses_existing_session(self) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821)
        proxy._server_addr = SERVER_ADDR
        relay_transport = make_transport()
        loop = asyncio.get_running_loop()
        create_count = 0

        async def _fake_once(factory: Any, **kwargs: Any) -> tuple[MagicMock, Any]:
            nonlocal create_count
            create_count += 1
            proto = factory()
            proto.connection_made(relay_transport)
            return relay_transport, proto

        with patch.object(loop, "create_datagram_endpoint", side_effect=_fake_once):
            await proxy._on_client_packet(DATA, CLIENT_A)
            await proxy._on_client_packet(DATA, CLIENT_A)

        assert create_count == 1
        assert relay_transport.sendto.call_count == 2

    async def test_independent_sessions_for_different_clients(self) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821)
        proxy._server_addr = SERVER_ADDR
        transports: list[MagicMock] = []
        loop = asyncio.get_running_loop()

        async def _fake(factory: Any, **kwargs: Any) -> tuple[MagicMock, Any]:
            t = make_transport()
            transports.append(t)
            proto = factory()
            proto.connection_made(t)
            return t, proto

        with patch.object(loop, "create_datagram_endpoint", side_effect=_fake):
            await proxy._on_client_packet(DATA, CLIENT_A)
            await proxy._on_client_packet(DATA, CLIENT_B)

        assert CLIENT_A in proxy._sessions
        assert CLIENT_B in proxy._sessions
        assert len(transports) == 2

    async def test_pending_guard_prevents_double_session(self) -> None:
        """Second packet for the same client while a session is being opened
        must not create a duplicate session."""
        proxy = UDPProxy(server_port=51820, client_port=51821)
        proxy._server_addr = SERVER_ADDR
        relay_transport = make_transport()
        loop = asyncio.get_running_loop()
        create_count = 0

        async def _slow_create(factory: Any, **kwargs: Any) -> tuple[MagicMock, Any]:
            nonlocal create_count
            create_count += 1
            await asyncio.sleep(0)  # yield – lets a second task try to create a session
            proto = factory()
            proto.connection_made(relay_transport)
            return relay_transport, proto

        with patch.object(loop, "create_datagram_endpoint", side_effect=_slow_create):
            await asyncio.gather(
                proxy._on_client_packet(DATA, CLIENT_A),
                proxy._on_client_packet(DATA, CLIENT_A),
            )

        assert create_count == 1


# ---------------------------------------------------------------------------
# Response routing
# ---------------------------------------------------------------------------


class TestResponseRouting:
    def test_forwards_server_response_to_correct_client(self) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821)
        client_transport = make_transport()
        proxy._client_transport = client_transport

        proxy._forward_to_client(CLIENT_A, DATA)

        client_transport.sendto.assert_called_once_with(DATA, CLIENT_A)

    def test_routes_to_correct_client_among_multiple(self) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821)
        client_transport = make_transport()
        proxy._client_transport = client_transport

        proxy._forward_to_client(CLIENT_A, b"for-a")
        proxy._forward_to_client(CLIENT_B, b"for-b")

        calls = client_transport.sendto.call_args_list
        assert calls[0].args == (b"for-a", CLIENT_A)
        assert calls[1].args == (b"for-b", CLIENT_B)

    def test_noop_when_client_transport_not_ready(self) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821)
        # Must not raise even though _client_transport is None.
        proxy._forward_to_client(CLIENT_A, DATA)


# ---------------------------------------------------------------------------
# Session cleanup
# ---------------------------------------------------------------------------


class TestSessionCleanup:
    async def test_expired_sessions_closed_in_cleanup_loop(self) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821, session_timeout=300)
        relay_transport = make_transport()
        proxy._sessions[CLIENT_A] = ClientSession(
            addr=CLIENT_A,
            transport=relay_transport,
            last_seen=time.monotonic() - 400,
        )

        async def _immediate_sleep(_: float) -> None:
            raise asyncio.CancelledError

        with patch("wireguard_proxy.proxy.asyncio.sleep", side_effect=_immediate_sleep):
            with pytest.raises(asyncio.CancelledError):
                await proxy._cleanup_loop()

        assert CLIENT_A not in proxy._sessions
        relay_transport.close.assert_called_once()

    async def test_fresh_sessions_not_removed(self) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821, session_timeout=300)
        relay_transport = make_transport()
        proxy._sessions[CLIENT_A] = ClientSession(
            addr=CLIENT_A,
            transport=relay_transport,
        )

        async def _immediate_sleep(_: float) -> None:
            raise asyncio.CancelledError

        with patch("wireguard_proxy.proxy.asyncio.sleep", side_effect=_immediate_sleep):
            with pytest.raises(asyncio.CancelledError):
                await proxy._cleanup_loop()

        assert CLIENT_A in proxy._sessions
        relay_transport.close.assert_not_called()

    async def test_stop_closes_all_relay_sockets(self) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821)
        t_a, t_b = make_transport(), make_transport()
        proxy._sessions[CLIENT_A] = ClientSession(addr=CLIENT_A, transport=t_a)
        proxy._sessions[CLIENT_B] = ClientSession(addr=CLIENT_B, transport=t_b)
        proxy._cleanup_task = asyncio.get_running_loop().create_task(asyncio.sleep(9999))

        await proxy.stop()

        t_a.close.assert_called_once()
        t_b.close.assert_called_once()
        assert not proxy._sessions
