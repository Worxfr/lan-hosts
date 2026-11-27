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
| `ROOT_PATH` | empty | sub-path when behind a proxy |
| `API_KEYS_BYPASS_ACL` | `true` | a valid API key works from any network |
| `POLL_INTERVAL` | `30` | seconds between status checks |
| `RESCAN_INTERVAL` | `300` | seconds between ARP rescans that follow DHCP IP changes (0 disables) |
| `SCAN_INTERFACE` | auto | interface used by the scan |
| `WOL_BROADCAST` | `255.255.255.255` | broadcast address for Wake-on-LAN |
| `DB_PATH` | `/data/lan-hosts.db` | SQLite file |

To make all traffic go through a reverse proxy (Caddy, nginx...), set `HOST` to the Docker bridge gateway the proxy can reach (e.g. `172.18.0.1`) so the port is not reachable directly, and `TRUSTED_PROXIES` to the proxy container address.

Behind a reverse proxy the server sees the proxy's address: declare it in `TRUSTED_PROXIES` and allow the real clients' network.

## API

The web page uses the same JSON API. Interactive documentation: `/api/docs` (OpenAPI at `/api/openapi.json`).

Create a key in the web page (shield icon, "Access and API keys"). It is shown once and stored hashed.
A key is either `read` (GET only) or `write` (also add, edit, delete, wake, scan).
Keys cannot create or revoke other keys.

```bash
KEY=lh_xxxxxxxx
curl -H "X-API-Key: $KEY" http://HOST:8088/api/hosts              # list
curl -H "Authorization: Bearer $KEY" http://HOST:8088/api/hosts/1  # one host
curl -X POST -H "X-API-Key: $KEY" http://HOST:8088/api/hosts/1/wake
curl -X POST -H "X-API-Key: $KEY" http://HOST:8088/api/rescan      # follow DHCP changes
curl -X POST -H "X-API-Key: $KEY" http://HOST:8088/api/refresh     # re-test status
```

By default a valid key works from any network (the network allow-list is bypassed). Set `API_KEYS_BYPASS_ACL=false` to require both.
An invalid key always gets a 401. Set `ROOT_PATH` (e.g. `/lan-hosts`) when the app is served under a sub-path so `/api/docs` works.

## Development

```bash
python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

## License

MIT
