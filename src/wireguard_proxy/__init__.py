"""wireguard-proxy: UDP relay proxy for WireGuard connections through CGNAT."""

__version__ = "0.1.0"

from wireguard_proxy.config import ProxyConfig
from wireguard_proxy.proxy import UDPProxy

__all__ = ["UDPProxy", "ProxyConfig"]
