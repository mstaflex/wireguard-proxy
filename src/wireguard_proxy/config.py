"""Proxy configuration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass
class ProxyConfig:
    """All tuneable parameters for the UDP proxy.

    server_port:      Port the home WireGuard server connects to (outbound through
                      CGNAT).  Periodic keepalives on this port maintain the NAT
                      mapping.
    client_port:      Port WireGuard clients connect to.
    host:             Local address to bind both listening sockets to.
    session_timeout:  Seconds of inactivity after which a client relay socket is
                      closed.  Should be shorter than the WireGuard persistent-
                      keepalive interval to avoid stale relay sockets accumulating.
    log_level:        Python logging level name.
    """

    server_port: int = 51820
    client_port: int = 51821
    host: str = "0.0.0.0"
    session_timeout: int = 300
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    def __post_init__(self) -> None:
        for name, value in (("server_port", self.server_port), ("client_port", self.client_port)):
            if not 1 <= value <= 65535:
                raise ValueError(f"{name} must be 1–65535, got {value}")
        if self.server_port == self.client_port:
            raise ValueError("server_port and client_port must be different")
        if self.session_timeout < 1:
            raise ValueError(f"session_timeout must be ≥ 1, got {self.session_timeout}")
