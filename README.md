# wireguard-proxy

A UDP relay proxy that lets a home WireGuard server behind CGNAT be reached by
clients anywhere on the internet.

## Problem

Home networks served by CGNAT cannot receive inbound connections.  Standard
WireGuard solutions require the server to be reachable, which rules out
consumer ISPs that share public IPs across many subscribers.

## Solution

Run **wireguard-proxy** on any cloud VM with a public IP.  The proxy opens two
UDP ports:

| Port | Purpose |
|------|---------|
| `server_port` (default 51820) | Home WireGuard server connects here (outbound, punching through CGNAT) |
| `client_port` (default 51821) | WireGuard clients connect here |

The proxy relays packets bidirectionally between clients and the home server.
For each distinct WireGuard client a dedicated ephemeral *relay socket* is
opened so the home WireGuard instance can track each client as a separate peer.

```
WireGuard client A ─────────────────────────────────────────────┐
WireGuard client B ──→  proxy:client_port ──→ relay socket A  ──┼──→ home WG server
                                           ──→ relay socket B ──┘   (behind CGNAT)
```

## Installation

Requires Python 3.11+ and [Poetry](https://python-poetry.org/).

```bash
git clone https://github.com/<your-org>/wireguard-proxy
cd wireguard-proxy
poetry install
```

## Usage

### Cloud proxy

```bash
wireguard-proxy \
  --server-port 51820 \
  --client-port 51821 \
  --session-timeout 300
```

Run as a systemd service on the cloud VM:

```ini
[Unit]
Description=WireGuard UDP Proxy
After=network.target

[Service]
ExecStart=/usr/local/bin/wireguard-proxy --server-port 51820 --client-port 51821
Restart=always

[Install]
WantedBy=multi-user.target
```

### Home WireGuard server (`wg0.conf`)

Add a peer section that points at the proxy's **server port**:

```ini
[Peer]
# Cloud proxy
PublicKey = <cloud-proxy-pubkey>
Endpoint = <cloud-ip>:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

`PersistentKeepalive = 25` is essential – it keeps the CGNAT mapping alive and
registers the home server's current public address with the proxy.

### WireGuard clients

Configure clients to use the proxy's **client port**:

```ini
[Peer]
# Home server via proxy
PublicKey = <home-server-pubkey>
Endpoint = <cloud-ip>:51821
AllowedIPs = 10.0.0.0/8
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--server-port` | 51820 | Port the home server connects to |
| `--client-port` | 51821 | Port clients connect to |
| `--host` | 0.0.0.0 | Bind address |
| `--session-timeout` | 300 | Seconds before an inactive client relay is closed |
| `--log-level` | INFO | DEBUG / INFO / WARNING / ERROR |

## Development

```bash
poetry install
poetry run pytest --cov=wireguard_proxy tests/
poetry run ruff check src tests
poetry run mypy src
```

## License

MIT
