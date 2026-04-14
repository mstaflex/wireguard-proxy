"""Proxy configuration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional


@dataclass
class ProxyConfig:
    """All tuneable parameters for the UDP proxy.

    server_port:      Port the home WireGuard server connects to (outbound through
                      CGNAT).  Periodic keepalives on this port maintain the NAT
                      mapping.
    client_port:      Port WireGuard clients connect to.
    host:             Local address to bind both listening sockets to.
    session_timeout:  Seconds of inactivity after which a client session is
                      removed.
    log_level:        Python logging level name.

    Gate (all optional – gating is disabled when pushover credentials are absent):
    pushover_token:   Pushover application API token.
    pushover_user:    Pushover user/group key.
    gate_public_url:  Publicly reachable base URL of this proxy, e.g.
                      "http://my-proxy.example.com".  Used to build allow-links.
    gate_http_port:   Port for the allow-URL HTTP endpoint (default 8080).
    gate_token_ttl:   Seconds before an unclicked allow token expires (default 600).
    """

    server_port: int = 51820
    client_port: int = 51821
    host: str = "0.0.0.0"
    session_timeout: int = 300
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # Gate / Pushover — all optional
    pushover_token: Optional[str] = None
    pushover_user: Optional[str] = None
    gate_public_url: str = ""
    gate_http_port: int = 8080
    gate_token_ttl: int = 600

    def __post_init__(self) -> None:
        for name, value in (("server_port", self.server_port), ("client_port", self.client_port)):
            if not 1 <= value <= 65535:
                raise ValueError(f"{name} must be 1–65535, got {value}")
        if self.server_port == self.client_port:
            raise ValueError("server_port and client_port must be different")
        if self.session_timeout < 1:
            raise ValueError(f"session_timeout must be ≥ 1, got {self.session_timeout}")
        if not 1 <= self.gate_http_port <= 65535:
            raise ValueError(f"gate_http_port must be 1–65535, got {self.gate_http_port}")
        if self.gate_token_ttl < 30:
            raise ValueError(f"gate_token_ttl must be ≥ 30, got {self.gate_token_ttl}")
        if (self.pushover_token or self.pushover_user) and not (
            self.pushover_token and self.pushover_user and self.gate_public_url
        ):
            raise ValueError(
                "Gate requires all three of: pushover_token, pushover_user, gate_public_url"
            )

    @property
    def gate_enabled(self) -> bool:
        return bool(self.pushover_token and self.pushover_user and self.gate_public_url)
