import asyncio
import hashlib
import ipaddress
import os
import secrets
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import net
from .db import DB

STATIC = os.path.join(os.path.dirname(__file__), "static")


class HostIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    mac: Optional[str] = None
    ip: Optional[str] = None


class KeyIn(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    scope: str = Field(default="write", pattern="^(read|write)$")


def hash_key(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def extract_key(request: Request):
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip() or None
    return request.headers.get("x-api-key", "").strip() or None


class NetworksIn(BaseModel):
    networks: list[str]


def create_app(db_path=None, poll_interval=None, start_poller=True) -> FastAPI:
    db = DB(db_path or os.environ.get("DB_PATH", "/data/lan-hosts.db"))
    interval = poll_interval or int(os.environ.get("POLL_INTERVAL", "30"))
    env_nets = net.parse_networks(os.environ.get("ALLOWED_NETWORKS", ""))
    trusted = net.parse_networks(os.environ.get("TRUSTED_PROXIES", ""))
    iface = os.environ.get("SCAN_INTERFACE", "")
    broadcast = os.environ.get("WOL_BROADCAST", "255.255.255.255")
    keys_bypass_acl = os.environ.get("API_KEYS_BYPASS_ACL", "true").lower() in ("1", "true", "yes")

    def extra_nets():
        return net.parse_networks(",".join(db.get_setting("extra_networks", [])))

    def allowed_nets():
        return net.local_networks() + env_nets + extra_nets()

    async def refresh_all():
        sem = asyncio.Semaphore(20)

        async def one(h):
            async with sem:
                db.set_status(h["id"], await net.is_up(h["ip"]))
        await asyncio.gather(*[one(h) for h in db.hosts() if h["ip"]])

    scan_lock = asyncio.Lock()
    rescan_every = int(os.environ.get("RESCAN_INTERVAL", "300"))

    async def rescan():
        """ARP-scan the LAN and follow known hosts (by MAC) whose IP changed (DHCP)."""
        async with scan_lock:
            found = await net.scan(net.local_networks(for_scan=True) + extra_nets(), iface)
            ip_of = {f["mac"]: f["ip"] for f in found}
            changes = []
            for h in db.hosts():
                new = ip_of.get(h["mac"]) if h["mac"] else None
                if not new:
                    continue
                if new != h["ip"]:
                    db.set_ip(h["id"], new)
                    changes.append({"name": h["name"], "old": h["ip"], "new": new})
                db.set_status(h["id"], True)  # it answered ARP
            return found, changes

    async def poller():
        while True:
            try:
                await refresh_all()
            except Exception:
                pass
            await asyncio.sleep(interval)

    async def rescanner():
        while rescan_every > 0:
            await asyncio.sleep(rescan_every)
            try:
                await rescan()
            except Exception:
                pass

    @asynccontextmanager
    async def lifespan(app):
        tasks = [asyncio.create_task(poller()), asyncio.create_task(rescanner())] if start_poller else []
        yield
        for t in tasks:
            t.cancel()

    app = FastAPI(title="lan-hosts", lifespan=lifespan, root_path=os.environ.get("ROOT_PATH", ""),
                  docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")
    app.state.db = db

    @app.middleware("http")
    async def acl(request: Request, call_next):
        peer = request.client.host if request.client else ""
        ip = net.client_ip(peer, request.headers.get("x-forwarded-for", ""), trusted)
        request.state.ip = ip
        request.state.key = None
        token = extract_key(request)
        if token:
            k = db.find_key(hash_key(token))
            if not k:
                return JSONResponse({"detail": "invalid API key"}, status_code=401)
            request.state.key = k
            if request.url.path.startswith("/api/keys"):
                return JSONResponse({"detail": "API keys cannot manage API keys"}, status_code=403)
            if request.method not in ("GET", "HEAD") and k["scope"] != "write":
                return JSONResponse({"detail": "read-only API key"}, status_code=403)
            if not k["last_used"] or time.time() - k["last_used"] > 60:
                db.touch_key(k["id"])
            if keys_bypass_acl:
                return await call_next(request)
        if not net.is_allowed(ip, allowed_nets()):
            return JSONResponse({"detail": "forbidden"}, status_code=403)
        return await call_next(request)

    def clean(h: HostIn):
        mac = ip = None
        try:
            if h.mac:
                mac = net.normalize_mac(h.mac)
            if h.ip:
                ip = str(ipaddress.IPv4Address(h.ip.strip()))
        except ValueError as e:
            raise HTTPException(422, str(e))
        if not mac and not ip:
            raise HTTPException(422, "MAC or IP required")
        return h.name.strip(), mac, ip

    @app.get("/api/hosts")
    def list_hosts():
        return db.hosts()

    @app.get("/api/hosts/{hid}")
    def get_host(hid: int):
        h = db.host(hid)
        if not h:
            raise HTTPException(404)
        return h

    @app.get("/api/keys")
    def list_keys():
        return db.keys()

    @app.post("/api/keys", status_code=201)
    def create_key(body: KeyIn):
        token = "lh_" + secrets.token_urlsafe(32)
        kid = db.add_key(body.name.strip(), token[:8], hash_key(token), body.scope)
        return {"id": kid, "name": body.name.strip(), "scope": body.scope, "key": token,
                "note": "Store this key now, it cannot be shown again."}

    @app.delete("/api/keys/{kid}", status_code=204)
    def delete_key(kid: int):
        db.delete_key(kid)

    @app.post("/api/hosts", status_code=201)
    def add_host(h: HostIn):
        name, mac, ip = clean(h)
        try:
            hid = db.add(name, mac, ip)
        except Exception:
            raise HTTPException(409, "MAC already registered")
        return db.host(hid)

    @app.put("/api/hosts/{hid}")
    def edit_host(hid: int, h: HostIn):
        if not db.host(hid):
            raise HTTPException(404)
        name, mac, ip = clean(h)
        try:
            db.update(hid, name, mac, ip)
        except Exception:
            raise HTTPException(409, "MAC already registered")
        return db.host(hid)

    @app.delete("/api/hosts/{hid}", status_code=204)
    def del_host(hid: int):
        db.delete(hid)

    @app.post("/api/hosts/{hid}/wake")
    def wake(hid: int):
        h = db.host(hid)
        if not h:
            raise HTTPException(404)
        if not h["mac"]:
            raise HTTPException(422, "host has no MAC address")
        net.send_wol(h["mac"], broadcast)
        return {"sent": True}

    @app.post("/api/refresh")
    async def refresh():
        await refresh_all()
        return db.hosts()

    @app.post("/api/rescan")
    async def force_rescan():
        _, changes = await rescan()
        return {"changes": changes, "hosts": db.hosts()}

    @app.post("/api/scan")
    async def scan():
        nets = net.local_networks(for_scan=True) + extra_nets()
        known = {h["mac"] for h in db.hosts() if h["mac"]}
        found = await net.scan(nets, iface)
        for f in found:
            f["known"] = f["mac"] in known
        return found

    @app.get("/api/networks")
    def get_networks(request: Request):
        return {"your_ip": str(request.state.ip), "detected": [str(n) for n in net.local_networks()],
                "from_env": [str(n) for n in env_nets],
                "extra": db.get_setting("extra_networks", [])}

    @app.put("/api/networks")
    def put_networks(body: NetworksIn, request: Request):
        try:
            nets = net.parse_networks(",".join(body.networks))
        except ValueError as e:
            raise HTTPException(422, str(e))
        future = net.local_networks() + env_nets + nets
        if not net.is_allowed(request.state.ip, future):
            raise HTTPException(409, "this would lock you out")
        db.set_setting("extra_networks", [str(n) for n in nets])
        return {"extra": [str(n) for n in nets]}

    @app.get("/")
    def index():
        return FileResponse(os.path.join(STATIC, "index.html"))

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app


def app_factory():
    return create_app()
