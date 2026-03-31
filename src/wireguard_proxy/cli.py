"""Command-line entry point."""

from __future__ import annotations

import asyncio
import logging
import signal
import sys

import click

from wireguard_proxy.config import ProxyConfig
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
    help="Seconds of inactivity before a client relay socket is closed.",
)
@click.option(
    "--log-level",
    default="INFO",
    show_default=True,
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    help="Logging verbosity.",
)
def main(
    server_port: int,
    client_port: int,
    host: str,
    session_timeout: int,
    log_level: str,
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
        )
    except ValueError as exc:
        raise click.BadParameter(str(exc)) from exc

    proxy = UDPProxy(
        server_port=config.server_port,
        client_port=config.client_port,
        host=config.host,
        session_timeout=config.session_timeout,
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
