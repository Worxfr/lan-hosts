# lan-hosts

A small container to manage the hosts of a LAN: see which ones are up, wake them with Wake-on-LAN, add them by hand or detect them.

- **Status**: ARP probe (`arping`), ICMP ping as fallback. Refreshed every 30 s.
- **Wake-on-LAN**: magic packet broadcast.
- **Discovery**: ARP scan (`arp-scan`) of the host's networks, from a button in the UI.
- **Access control**: only the network the container runs on is allowed by default. Add more with `ALLOWED_NETWORKS` or from the UI. Anyone else gets a 403.
- **Storage**: SQLite file in the `/data` volume.

## Run

```bash
docker compose up -d
```

Then open `http://<docker-host>:8088`.

The container uses `network_mode: host`: ARP and broadcasts only work on the real LAN.
No authentication: do not expose it outside your LAN.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `HOST` | `0.0.0.0` | listen address |
| `PORT` | `8088` | HTTP port |
| `ALLOWED_NETWORKS` | empty | extra CIDRs allowed, comma separated |
| `TRUSTED_PROXIES` | empty | reverse proxies whose `X-Forwarded-For` is trusted |
| `POLL_INTERVAL` | `30` | seconds between status checks |
| `SCAN_INTERFACE` | auto | interface used by the scan |
| `WOL_BROADCAST` | `255.255.255.255` | broadcast address for Wake-on-LAN |
| `DB_PATH` | `/data/lan-hosts.db` | SQLite file |

To make all traffic go through a reverse proxy (Caddy, nginx...), set `HOST` to the Docker bridge gateway the proxy can reach (e.g. `172.18.0.1`) so the port is not reachable directly, and `TRUSTED_PROXIES` to the proxy container address.

Behind a reverse proxy the server sees the proxy's address: declare it in `TRUSTED_PROXIES` and allow the real clients' network.

## Development

```bash
python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

## License

MIT
