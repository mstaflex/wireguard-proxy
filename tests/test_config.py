"""Tests for ProxyConfig validation."""

from __future__ import annotations

import pytest

from wireguard_proxy.config import ProxyConfig


class TestProxyConfigDefaults:
    def test_default_values(self) -> None:
        cfg = ProxyConfig()
        assert cfg.server_port == 51820
        assert cfg.client_port == 51821
        assert cfg.host == "0.0.0.0"
        assert cfg.session_timeout == 300
        assert cfg.log_level == "INFO"


class TestProxyConfigValidation:
    def test_server_port_too_low(self) -> None:
        with pytest.raises(ValueError, match="server_port"):
            ProxyConfig(server_port=0)

    def test_server_port_too_high(self) -> None:
        with pytest.raises(ValueError, match="server_port"):
            ProxyConfig(server_port=65536)

    def test_client_port_too_low(self) -> None:
        with pytest.raises(ValueError, match="client_port"):
            ProxyConfig(client_port=0)

    def test_client_port_too_high(self) -> None:
        with pytest.raises(ValueError, match="client_port"):
            ProxyConfig(client_port=65536)

    def test_same_ports_rejected(self) -> None:
        with pytest.raises(ValueError, match="different"):
            ProxyConfig(server_port=51820, client_port=51820)

    def test_session_timeout_zero_rejected(self) -> None:
        with pytest.raises(ValueError, match="session_timeout"):
            ProxyConfig(session_timeout=0)

    def test_session_timeout_negative_rejected(self) -> None:
        with pytest.raises(ValueError, match="session_timeout"):
            ProxyConfig(session_timeout=-1)

    def test_boundary_ports_valid(self) -> None:
        cfg = ProxyConfig(server_port=1, client_port=65535)
        assert cfg.server_port == 1
        assert cfg.client_port == 65535

    def test_session_timeout_one_is_valid(self) -> None:
        cfg = ProxyConfig(session_timeout=1)
        assert cfg.session_timeout == 1
