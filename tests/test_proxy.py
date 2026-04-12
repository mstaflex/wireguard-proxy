"""Tests for the core proxy logic."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import MagicMock, patch

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


# ---------------------------------------------------------------------------
# ClientSession
# ---------------------------------------------------------------------------


class TestClientSession:
    def test_is_expired_when_old(self) -> None:
        session = ClientSession(
            addr=CLIENT_A,
            last_seen=time.monotonic() - 400,
        )
        assert session.is_expired(300)

    def test_not_expired_when_fresh(self) -> None:
        session = ClientSession(addr=CLIENT_A)
        assert not session.is_expired(300)

    def test_touch_resets_expiry(self) -> None:
        session = ClientSession(
            addr=CLIENT_A,
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

    def test_forwards_data_to_active_clients(self) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821)
        client_transport = make_transport()
        proxy._client_transport = client_transport
        proxy._sessions[CLIENT_A] = ClientSession(addr=CLIENT_A)
        proxy._sessions[CLIENT_B] = ClientSession(addr=CLIENT_B)

        proxy._on_server_packet(DATA, SERVER_ADDR)

        calls = {c.args for c in client_transport.sendto.call_args_list}
        assert (DATA, CLIENT_A) in calls
        assert (DATA, CLIENT_B) in calls

    def test_no_forward_when_no_clients(self) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821)
        client_transport = make_transport()
        proxy._client_transport = client_transport

        proxy._on_server_packet(DATA, SERVER_ADDR)

        client_transport.sendto.assert_not_called()

    def test_no_forward_when_client_transport_not_ready(self) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821)
        proxy._sessions[CLIENT_A] = ClientSession(addr=CLIENT_A)
        # Must not raise even though _client_transport is None.
        proxy._on_server_packet(DATA, SERVER_ADDR)


# ---------------------------------------------------------------------------
# Client packet handling
# ---------------------------------------------------------------------------


class TestClientPacketHandling:
    def test_drops_packet_when_no_server_registered(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821)
        import logging

        with caplog.at_level(logging.WARNING):
            proxy._on_client_packet(DATA, CLIENT_A)

        assert CLIENT_A not in proxy._sessions
        assert "no server registered" in caplog.text.lower()

    def test_creates_session_for_new_client(self) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821)
        proxy._server_addr = SERVER_ADDR
        proxy._server_transport = make_transport()

        proxy._on_client_packet(DATA, CLIENT_A)

        assert CLIENT_A in proxy._sessions

    def test_forwards_packet_to_server_via_server_transport(self) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821)
        proxy._server_addr = SERVER_ADDR
        server_transport = make_transport()
        proxy._server_transport = server_transport

        proxy._on_client_packet(DATA, CLIENT_A)

        server_transport.sendto.assert_called_once_with(DATA, SERVER_ADDR)

    def test_reuses_existing_session(self) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821)
        proxy._server_addr = SERVER_ADDR
        server_transport = make_transport()
        proxy._server_transport = server_transport

        proxy._on_client_packet(DATA, CLIENT_A)
        proxy._on_client_packet(DATA, CLIENT_A)

        assert len(proxy._sessions) == 1
        assert server_transport.sendto.call_count == 2

    def test_independent_sessions_for_different_clients(self) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821)
        proxy._server_addr = SERVER_ADDR
        proxy._server_transport = make_transport()

        proxy._on_client_packet(DATA, CLIENT_A)
        proxy._on_client_packet(DATA, CLIENT_B)

        assert CLIENT_A in proxy._sessions
        assert CLIENT_B in proxy._sessions

    def test_roaming_replaces_stale_session(self) -> None:
        """When the same client IP reappears on a new source port (NAT roam),
        the old session must be evicted so broadcast traffic is not duplicated."""
        proxy = UDPProxy(server_port=51820, client_port=51821)
        proxy._server_addr = SERVER_ADDR
        proxy._server_transport = make_transport()

        old_addr = ("10.0.0.1", 11111)
        new_addr = ("10.0.0.1", 22222)

        proxy._on_client_packet(DATA, old_addr)
        assert old_addr in proxy._sessions

        proxy._on_client_packet(DATA, new_addr)

        assert new_addr in proxy._sessions
        assert old_addr not in proxy._sessions
        assert len(proxy._sessions) == 1

    def test_noop_when_server_transport_not_ready(self) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821)
        proxy._server_addr = SERVER_ADDR
        # _server_transport is None — must not raise.
        proxy._on_client_packet(DATA, CLIENT_A)


# ---------------------------------------------------------------------------
# Session cleanup
# ---------------------------------------------------------------------------


class TestSessionCleanup:
    async def test_expired_sessions_removed_in_cleanup_loop(self) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821, session_timeout=300)
        proxy._sessions[CLIENT_A] = ClientSession(
            addr=CLIENT_A,
            last_seen=time.monotonic() - 400,
        )

        async def _immediate_sleep(_: float) -> None:
            raise asyncio.CancelledError

        with patch("wireguard_proxy.proxy.asyncio.sleep", side_effect=_immediate_sleep):
            with pytest.raises(asyncio.CancelledError):
                await proxy._cleanup_loop()

        assert CLIENT_A not in proxy._sessions

    async def test_fresh_sessions_not_removed(self) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821, session_timeout=300)
        proxy._sessions[CLIENT_A] = ClientSession(addr=CLIENT_A)

        async def _immediate_sleep(_: float) -> None:
            raise asyncio.CancelledError

        with patch("wireguard_proxy.proxy.asyncio.sleep", side_effect=_immediate_sleep):
            with pytest.raises(asyncio.CancelledError):
                await proxy._cleanup_loop()

        assert CLIENT_A in proxy._sessions

    async def test_stop_clears_sessions(self) -> None:
        proxy = UDPProxy(server_port=51820, client_port=51821)
        proxy._sessions[CLIENT_A] = ClientSession(addr=CLIENT_A)
        proxy._sessions[CLIENT_B] = ClientSession(addr=CLIENT_B)
        proxy._cleanup_task = asyncio.get_running_loop().create_task(asyncio.sleep(9999))

        await proxy.stop()

        assert not proxy._sessions
