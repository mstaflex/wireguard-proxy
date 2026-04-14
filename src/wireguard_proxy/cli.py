"""Command-line entry point."""

from __future__ import annotations

import asyncio
import logging
import signal
import sys

import click

from wireguard_proxy.config import ProxyConfig
from wireguard_proxy.gate import GateKeeper
from wireguard_proxy.proxy import UDPProxy


@click.command()
@click.option(
    "--server-port",
    default=51820,
    show_default=True,
    help="Port the home WireGuard server connects to (outbound through CGNAT).",
)
@click.option(
    "--client-port",
    default=51821,
    show_default=True,
    help="Port WireGuard clients connect to.",
)
@click.option(
    "--host",
    default="0.0.0.0",
    show_default=True,
    help="Host/address to bind both sockets to.",
)
@click.option(
    "--session-timeout",
    default=300,
    show_default=True,
    help="Seconds of inactivity before a client session is removed.",
)
@click.option(
    "--log-level",
    default="INFO",
    show_default=True,
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    help="Logging verbosity.",
)
@click.option(
    "--pushover-token",
    default=None,
    envvar="PUSHOVER_TOKEN",
    help="Pushover application API token.  Enables connection-approval gating.",
)
@click.option(
    "--pushover-user",
    default=None,
    envvar="PUSHOVER_USER",
    help="Pushover user/group key.",
)
@click.option(
    "--gate-public-url",
    default="",
    envvar="GATE_PUBLIC_URL",
    help="Publicly reachable base URL of this host, e.g. http://my-proxy.example.com",
)
@click.option(
    "--gate-http-port",
    default=8080,
    show_default=True,
    envvar="GATE_HTTP_PORT",
    help="Port for the allow-URL HTTP endpoint.",
)
@click.option(
    "--gate-token-ttl",
    default=600,
    show_default=True,
    envvar="GATE_TOKEN_TTL",
    help="Seconds before an unclicked allow token expires.",
)
def main(
    server_port: int,
    client_port: int,
    host: str,
    session_timeout: int,
    log_level: str,
    pushover_token: str | None,
    pushover_user: str | None,
    gate_public_url: str,
    gate_http_port: int,
    gate_token_ttl: int,
) -> None:
    """UDP relay proxy for WireGuard connections through CGNAT.

    \b
    Typical setup
    -------------
    On the cloud host run:

        wireguard-proxy --server-port 51820 --client-port 51821

    Configure the home WireGuard server's [Peer] endpoint as:

        Endpoint = <cloud-host>:51820
        PersistentKeepalive = 25

    Configure WireGuard clients to use:

        Endpoint = <cloud-host>:51821

    \b
    Connection gating (optional)
    ----------------------------
    Provide Pushover credentials to require manual approval for every new
    connection.  Each new peer triggers a push notification with an allow-link:

        wireguard-proxy \\
            --pushover-token <APP_TOKEN> \\
            --pushover-user  <USER_KEY>  \\
            --gate-public-url http://my-proxy.example.com

    The allow-link endpoint listens on --gate-http-port (default 8080).
    Make sure that port is reachable from your phone.
    Credentials can also be supplied via environment variables:
    PUSHOVER_TOKEN, PUSHOVER_USER, GATE_PUBLIC_URL.
    """
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format="%(asctime)s %(levelname)-8s %(name)s – %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stdout,
    )

    try:
        config = ProxyConfig(
            server_port=server_port,
            client_port=client_port,
            host=host,
            session_timeout=session_timeout,
            log_level=log_level.upper(),  # type: ignore[arg-type]
            pushover_token=pushover_token,
            pushover_user=pushover_user,
            gate_public_url=gate_public_url,
            gate_http_port=gate_http_port,
            gate_token_ttl=gate_token_ttl,
        )
    except ValueError as exc:
        raise click.BadParameter(str(exc)) from exc

    gate: GateKeeper | None = None
    if config.gate_enabled:
        gate = GateKeeper(
            pushover_token=config.pushover_token,  # type: ignore[arg-type]
            pushover_user=config.pushover_user,  # type: ignore[arg-type]
            public_url=config.gate_public_url,
            http_port=config.gate_http_port,
            token_ttl=config.gate_token_ttl,
        )

    proxy = UDPProxy(
        server_port=config.server_port,
        client_port=config.client_port,
        host=config.host,
        session_timeout=config.session_timeout,
        gate=gate,
    )

    asyncio.run(_run(proxy))


async def _run(proxy: UDPProxy) -> None:
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _handle_signal() -> None:
        stop_event.set()

    # SIGINT / SIGTERM are not available on Windows via add_signal_handler.
    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, _handle_signal)
    except (NotImplementedError, AttributeError):
        pass  # Windows – KeyboardInterrupt will propagate naturally

    await proxy.start()
    logging.getLogger(__name__).info("Press Ctrl-C to stop.")

    try:
        await stop_event.wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await proxy.stop()
