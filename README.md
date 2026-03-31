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
WireGuard client A ──┐
                     ├──→  proxy:client_port ──→ relay socket A ──→ home WG server
WireGuard client B ──┘                      ──→ relay socket B ──┘  (behind CGNAT)

home WG server ──→ proxy:server_port   (registers home server's current public address)
```

## How address registration works

The proxy does not participate in WireGuard at all — it is a dumb UDP relay.
When the home server sends WireGuard handshake initiation packets toward
`proxy:server_port`, the proxy records their UDP source address as the current
home server endpoint.  No completed WireGuard session is needed; the handshake
retries WireGuard performs naturally are sufficient to keep the CGNAT mapping
alive and the address up to date.

There is no separate keepalive agent or out-of-band registration mechanism.

## Home server requirements

The home WireGuard server must be a standard Linux `wg`/`wg-quick` instance
(not a Unifi UDM/UDM-Pro — their firmware does not expose outbound `Endpoint`
configuration in the GUI).  A small Linux machine (Raspberry Pi, mini-PC, old
laptop) works well, and it can be placed in a dedicated DMZ on the home router
for additional isolation.

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

Or with Docker:

```bash
cp .env.example .env   # adjust ports if needed
docker compose up -d
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

The home server needs one peer entry that points at the proxy's **server port**.
This causes WireGuard to proactively send handshake initiations outbound through
CGNAT, registering the home server's public address with the proxy.

```ini
[Interface]
ListenPort = 51820
PrivateKey = <home-server-private-key>

[Peer]
# Proxy registration peer — the proxy does not complete the handshake;
# WireGuard's retry traffic is what keeps the CGNAT mapping alive.
PublicKey = <any-valid-wg-public-key>
Endpoint = <cloud-ip>:51820
AllowedIPs = 192.0.2.0/32   # unreachable test range — no real traffic
PersistentKeepalive = 25

# Add one [Peer] block per WireGuard client below
```

> **Note:** because the proxy does not complete WireGuard handshakes, the peer
> public key and `AllowedIPs` in the registration peer block do not matter
> practically — you can generate a fresh throwaway key pair.

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
