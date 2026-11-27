import ipaddress
import pytest
from fastapi.testclient import TestClient
from app import net
from app.main import create_app


def mk(tmp_path, monkeypatch, nets="testclient/32", **env):
    monkeypatch.setattr(net, "local_networks", lambda for_scan=False: [])
    monkeypatch.setenv("ALLOWED_NETWORKS", "10.0.0.0/8")
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return create_app(str(tmp_path / "t.db"), start_poller=False)


def client(app, ip="10.1.2.3"):
    return TestClient(app, client=(ip, 5000))


def test_wol_packet():
    p = net.wol_packet("AA-BB-CC-DD-EE-FF")
    assert len(p) == 102 and p[:6] == b"\xff" * 6 and p[6:12] == bytes.fromhex("aabbccddeeff")


def test_bad_mac():
    with pytest.raises(ValueError):
        net.normalize_mac("zz")


def test_acl_blocks_outside(tmp_path, monkeypatch):
    c = client(mk(tmp_path, monkeypatch), "8.8.8.8")
    assert c.get("/api/hosts").status_code == 403


def test_xff_ignored_without_trusted_proxy(tmp_path, monkeypatch):
    c = client(mk(tmp_path, monkeypatch), "8.8.8.8")
    assert c.get("/api/hosts", headers={"x-forwarded-for": "10.1.1.1"}).status_code == 403


def test_xff_with_trusted_proxy(tmp_path, monkeypatch):
    app = mk(tmp_path, monkeypatch, TRUSTED_PROXIES="10.9.9.9/32")
    c = client(app, "10.9.9.9")
    assert c.get("/api/hosts", headers={"x-forwarded-for": "8.8.8.8"}).status_code == 403
    assert c.get("/api/hosts", headers={"x-forwarded-for": "10.2.2.2"}).status_code == 200


def test_crud_and_wake(tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr(net, "send_wol", lambda mac, b: sent.append(mac))
    c = client(mk(tmp_path, monkeypatch))
    r = c.post("/api/hosts", json={"name": "nas", "ip": "10.0.0.5", "mac": "AA:BB:CC:DD:EE:FF"})
    assert r.status_code == 201 and r.json()["mac"] == "aa:bb:cc:dd:ee:ff"
    assert c.post("/api/hosts", json={"name": "x", "mac": "aa:bb:cc:dd:ee:ff"}).status_code == 409
    assert c.post("/api/hosts", json={"name": "x"}).status_code == 422
    assert c.post("/api/hosts", json={"name": "x", "ip": "nope"}).status_code == 422
    hid = r.json()["id"]
    assert c.post(f"/api/hosts/{hid}/wake").json() == {"sent": True} and sent == ["aa:bb:cc:dd:ee:ff"]
    assert c.delete(f"/api/hosts/{hid}").status_code == 204
    assert c.get("/api/hosts").json() == []


def test_status_refresh(tmp_path, monkeypatch):
    async def fake(ip):
        return ip == "10.0.0.5"
    monkeypatch.setattr(net, "is_up", fake)
    c = client(mk(tmp_path, monkeypatch))
    c.post("/api/hosts", json={"name": "a", "ip": "10.0.0.5"})
    c.post("/api/hosts", json={"name": "b", "ip": "10.0.0.6"})
    ups = {h["name"]: h["up"] for h in c.post("/api/refresh").json()}
    assert ups == {"a": 1, "b": 0}


def test_scan_marks_known(tmp_path, monkeypatch):
    async def fake(nets, iface=""):
        return [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "X"},
                {"ip": "10.0.0.7", "mac": "11:22:33:44:55:66", "vendor": ""}]
    monkeypatch.setattr(net, "scan", fake)
    c = client(mk(tmp_path, monkeypatch))
    c.post("/api/hosts", json={"name": "a", "mac": "aa:bb:cc:dd:ee:ff"})
    assert [f["known"] for f in c.post("/api/scan").json()] == [True, False]


def test_networks_lockout_guard(tmp_path, monkeypatch):
    c = client(mk(tmp_path, monkeypatch))
    assert c.put("/api/networks", json={"networks": ["192.168.0.0/24"]}).status_code == 200
    assert c.put("/api/networks", json={"networks": []}).status_code == 200
    assert c.put("/api/networks", json={"networks": ["bad"]}).status_code == 422


def test_extra_network_grants_access(tmp_path, monkeypatch):
    app = mk(tmp_path, monkeypatch)
    client(app).put("/api/networks", json={"networks": ["192.168.0.0/24"]})
    assert client(app, "192.168.0.9").get("/api/hosts").status_code == 200


def test_parse_arp_scan():
    out = "192.168.1.1\t00:11:22:33:44:55\tFreebox\n192.168.1.9\taa:bb:cc:dd:ee:ff\t(Unknown)\nfoo\n"
    assert [h["ip"] for h in net.parse_arp_scan(out)] == ["192.168.1.1", "192.168.1.9"]


def test_index_served(tmp_path, monkeypatch):
    r = client(mk(tmp_path, monkeypatch)).get("/")
    assert r.status_code == 200 and "LAN Hosts" in r.text


def test_ui_uses_relative_api_paths(tmp_path, monkeypatch):
    html = client(mk(tmp_path, monkeypatch)).get("/").text
    assert "'/api/" not in html and "`/api/" not in html


def test_edit_host(tmp_path, monkeypatch):
    c = client(mk(tmp_path, monkeypatch))
    hid = c.post("/api/hosts", json={"name": "a", "mac": "aa:bb:cc:dd:ee:ff"}).json()["id"]
    r = c.put(f"/api/hosts/{hid}", json={"name": "b", "ip": "10.0.0.9", "mac": "AA:BB:CC:DD:EE:00"})
    assert r.status_code == 200 and r.json()["name"] == "b" and r.json()["mac"] == "aa:bb:cc:dd:ee:00"
    assert c.put("/api/hosts/999", json={"name": "x", "ip": "10.0.0.1"}).status_code == 404


def test_rescan_follows_dhcp_change(tmp_path, monkeypatch):
    async def fake(nets, iface=""):
        return [{"ip": "10.0.0.99", "mac": "aa:bb:cc:dd:ee:ff", "vendor": ""},
                {"ip": "10.0.0.7", "mac": "11:22:33:44:55:66", "vendor": ""}]
    monkeypatch.setattr(net, "scan", fake)
    c = client(mk(tmp_path, monkeypatch))
    c.post("/api/hosts", json={"name": "moved", "ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff"})
    c.post("/api/hosts", json={"name": "absent", "ip": "10.0.0.6", "mac": "de:ad:be:ef:00:01"})
    r = c.post("/api/rescan").json()
    assert r["changes"] == [{"name": "moved", "old": "10.0.0.5", "new": "10.0.0.99"}]
    h = {x["name"]: x for x in r["hosts"]}
    assert h["moved"]["ip"] == "10.0.0.99" and h["moved"]["up"] == 1
    assert h["absent"]["ip"] == "10.0.0.6" and h["absent"]["up"] is None
