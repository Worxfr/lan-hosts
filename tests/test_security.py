import asyncio
import httpx
import pytest
from app import net
from app.main import create_app
from tests.test_app import client, mk


def test_cross_site_write_refused(tmp_path, monkeypatch):
    c = client(mk(tmp_path, monkeypatch))
    assert c.post("/api/refresh", headers={"Origin": "https://evil.example"}).status_code == 403
    assert c.post("/api/refresh", headers={"Origin": "null"}).status_code == 403
    assert c.post("/api/refresh", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert c.post("/api/refresh", headers={"Origin": "http://testserver"}).status_code == 200
    assert c.post("/api/refresh").status_code == 200  # curl, scripts: no Origin
    assert c.get("/api/hosts", headers={"Origin": "https://evil.example"}).status_code == 200


def test_api_key_not_subject_to_origin_check(tmp_path, monkeypatch):
    app = mk(tmp_path, monkeypatch)
    c = client(app)
    key = c.post("/api/keys", json={"name": "k"}).json()["key"]
    r = c.post("/api/refresh", headers={"X-API-Key": key, "Origin": "https://other.example"})
    assert r.status_code == 200


def test_allowed_hosts(tmp_path, monkeypatch):
    c = client(mk(tmp_path, monkeypatch, ALLOWED_HOSTS="lan.home.arpa, box.example.net"))
    assert c.get("/api/hosts", headers={"Host": "evil.example"}).status_code == 403
    assert c.get("/api/hosts", headers={"Host": "lan.home.arpa"}).status_code == 200
    assert c.get("/api/hosts", headers={"Host": "BOX.example.net:8443"}).status_code == 200
    assert c.get("/api/hosts", headers={"Host": "192.168.1.5:8088"}).status_code == 200


def test_security_headers(tmp_path, monkeypatch):
    c = client(mk(tmp_path, monkeypatch))
    for r in (c.get("/"), c.get("/api/hosts"), client(mk(tmp_path, monkeypatch), "8.8.8.8").get("/")):
        assert r.headers["x-frame-options"] == "DENY"
        assert r.headers["x-content-type-options"] == "nosniff"
        assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert c.get("/api/hosts").headers["cache-control"] == "no-store"
    assert "jsdelivr" not in c.get("/").headers["content-security-policy"]


def test_too_wide_networks_refused(tmp_path, monkeypatch):
    c = client(mk(tmp_path, monkeypatch))
    for bad in ("0.0.0.0/0", "10.0.0.0/7", "::/0"):
        assert c.put("/api/networks", json={"networks": [bad]}).status_code == 422
    assert c.put("/api/networks", json={"networks": ["192.168.0.0/16"]}).status_code == 200
    monkeypatch.setenv("ALLOWED_NETWORKS", "0.0.0.0/0")
    with pytest.raises(ValueError):
        create_app(str(tmp_path / "x.db"), start_poller=False)


def test_local_networks_cached(monkeypatch):
    calls = []
    monkeypatch.setattr(net, "_local_networks", lambda for_scan=False: calls.append(1) or [])
    net._NET_CACHE.clear()
    for _ in range(5):
        net.local_networks()
    assert len(calls) == 1


def test_only_one_scan_at_a_time(tmp_path, monkeypatch):
    async def slow(nets, iface=""):
        await asyncio.sleep(0.4)
        return []
    monkeypatch.setattr(net, "scan", slow)
    app = mk(tmp_path, monkeypatch)

    async def go():
        t = httpx.ASGITransport(app=app, client=("10.1.2.3", 5000))
        async with httpx.AsyncClient(transport=t, base_url="http://testserver") as c:
            first = asyncio.create_task(c.post("/api/scan"))
            await asyncio.sleep(0.1)
            second = await c.post("/api/rescan")
            third = await c.post("/api/scan")
            return (await first).status_code, second.status_code, third.status_code
    assert asyncio.run(go()) == (200, 409, 409)
