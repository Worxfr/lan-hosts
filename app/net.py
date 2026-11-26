"""Network helpers: ACL, Wake-on-LAN, ARP status check, ARP discovery."""
import asyncio
import ipaddress
import json
import re
import socket
import subprocess

MAC_RE = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)


def normalize_mac(mac: str) -> str:
    mac = mac.strip().lower().replace("-", ":")
    if not MAC_RE.match(mac):
        raise ValueError("invalid MAC address")
    return mac


def parse_networks(text: str) -> list:
    out = []
    for part in (text or "").split(","):
        part = part.strip()
        if part:
            out.append(ipaddress.ip_network(part, strict=False))
    return out


SKIP_SCAN_IF = ("docker", "br-", "veth", "tailscale", "virbr", "cni", "flannel")


def local_networks(for_scan: bool = False) -> list:
    """IPv4 networks of the machine's non-loopback interfaces (host network mode)."""
    try:
        data = json.loads(subprocess.run(["ip", "-j", "-4", "addr"], capture_output=True,
                                         text=True, timeout=5).stdout or "[]")
    except Exception:
        return []
    nets = []
    for itf in data:
        name = itf.get("ifname", "")
        if name == "lo" or (for_scan and name.startswith(SKIP_SCAN_IF)):
            continue
        for a in itf.get("addr_info", []):
            nets.append(ipaddress.ip_network(f"{a['local']}/{a['prefixlen']}", strict=False))
    return nets


def client_ip(peer: str, xff: str, trusted: list):
    """Real client IP. X-Forwarded-For is honoured only when the peer is a trusted proxy."""
    try:
        ip = ipaddress.ip_address(peer)
    except ValueError:
        return None
    if xff and any(ip in n for n in trusted):
        for hop in reversed([h.strip() for h in xff.split(",")]):
            try:
                cand = ipaddress.ip_address(hop)
            except ValueError:
                return None
            if not any(cand in n for n in trusted):
                return cand
    return ip


def is_allowed(ip, networks: list) -> bool:
    return ip is not None and any(ip in n for n in networks)


def wol_packet(mac: str) -> bytes:
    raw = bytes.fromhex(normalize_mac(mac).replace(":", ""))
    return b"\xff" * 6 + raw * 16


def send_wol(mac: str, broadcast: str = "255.255.255.255", port: int = 9) -> None:
    pkt = wol_packet(mac)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(pkt, (broadcast, port))


async def _run(*cmd, timeout=10):
    try:
        p = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE,
                                                 stderr=asyncio.subprocess.PIPE)
        out, _ = await asyncio.wait_for(p.communicate(), timeout)
        return p.returncode, out.decode(errors="replace")
    except (FileNotFoundError, asyncio.TimeoutError):
        return 127, ""


async def is_up(ip: str) -> bool:
    """ARP probe first (reliable on the same LAN), ICMP ping as a fallback."""
    ipaddress.ip_address(ip)  # validates input, nothing else reaches the command line
    rc, _ = await _run("arping", "-c", "1", "-w", "1", ip, timeout=4)
    if rc == 0:
        return True
    rc, _ = await _run("ping", "-c", "1", "-W", "1", ip, timeout=4)
    return rc == 0


def parse_arp_scan(text: str) -> list:
    found = []
    for line in text.splitlines():
        cols = line.split("\t")
        if len(cols) >= 2 and MAC_RE.match(cols[1]):
            found.append({"ip": cols[0], "mac": cols[1].lower(),
                          "vendor": cols[2] if len(cols) > 2 else ""})
    return found


async def scan(networks: list, interface: str = "") -> list:
    results = {}
    for net in networks:
        if net.prefixlen < 20 or net.prefixlen > 30:
            continue  # refuse huge ranges and single addresses
        cmd = ["arp-scan", "-x"]
        if interface:
            cmd += ["-I", interface]
        cmd.append(str(net))
        _, out = await _run(*cmd, timeout=60)
        for h in parse_arp_scan(out):
            results[h["mac"]] = h
    return sorted(results.values(), key=lambda h: ipaddress.ip_address(h["ip"]))
