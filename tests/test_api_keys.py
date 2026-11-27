from fastapi.testclient import TestClient
from app import net
from tests.test_app import client, mk


def newkey(c, scope="write", name="script"):
    r = c.post("/api/keys", json={"name": name, "scope": scope})
    assert r.status_code == 201
    return r.json()["key"]


def test_key_created_stored_hashed(tmp_path, monkeypatch):
    app = mk(tmp_path, monkeypatch)
    c = client(app)
    key = newkey(c)
    assert key.startswith("lh_")
    listed = c.get("/api/keys").json()
    assert listed[0]["prefix"] == key[:8] and "key" not in listed[0] and "hash" not in listed[0]
    row = app.state.db.c.execute("SELECT hash FROM api_keys").fetchone()
    assert key not in row["hash"] and len(row["hash"]) == 64


def test_key_works_from_outside_network(tmp_path, monkeypatch):
    app = mk(tmp_path, monkeypatch)
    key = newkey(client(app))
    out = client(app, "8.8.8.8")
    assert out.get("/api/hosts").status_code == 403
    assert out.get("/api/hosts", headers={"Authorization": f"Bearer {key}"}).status_code == 200
    assert out.get("/api/hosts", headers={"X-API-Key": key}).status_code == 200


def test_invalid_key_is_401_even_on_lan(tmp_path, monkeypatch):
    c = client(mk(tmp_path, monkeypatch))
    assert c.get("/api/hosts", headers={"X-API-Key": "nope"}).status_code == 401


def test_read_key_cannot_write(tmp_path, monkeypatch):
    app = mk(tmp_path, monkeypatch)
    key = newkey(client(app), "read")
    h = {"X-API-Key": key}
    c = client(app, "8.8.8.8")
    assert c.get("/api/hosts", headers=h).status_code == 200
    assert c.post("/api/hosts", headers=h, json={"name": "x", "ip": "10.0.0.1"}).status_code == 403
    assert c.post("/api/hosts/1/wake", headers=h).status_code == 403


def test_key_cannot_manage_keys(tmp_path, monkeypatch):
    app = mk(tmp_path, monkeypatch)
    key = newkey(client(app))
    c = client(app, "8.8.8.8")
    assert c.get("/api/keys", headers={"X-API-Key": key}).status_code == 403
    assert c.post("/api/keys", headers={"X-API-Key": key}, json={"name": "y"}).status_code == 403


def test_revoked_key(tmp_path, monkeypatch):
    app = mk(tmp_path, monkeypatch)
    c = client(app)
    key = newkey(c)
    c.delete("/api/keys/1")
    assert client(app, "8.8.8.8").get("/api/hosts", headers={"X-API-Key": key}).status_code == 401


def test_bypass_can_be_disabled(tmp_path, monkeypatch):
    app = mk(tmp_path, monkeypatch, API_KEYS_BYPASS_ACL="false")
    key = newkey(client(app))
    assert client(app, "8.8.8.8").get("/api/hosts", headers={"X-API-Key": key}).status_code == 403
    assert client(app).get("/api/hosts", headers={"X-API-Key": key}).status_code == 200


def test_key_cannot_be_created_from_outside(tmp_path, monkeypatch):
    c = client(mk(tmp_path, monkeypatch), "8.8.8.8")
    assert c.post("/api/keys", json={"name": "x"}).status_code == 403


def test_docs_and_get_host(tmp_path, monkeypatch):
    c = client(mk(tmp_path, monkeypatch))
    assert c.get("/api/openapi.json").status_code == 200
    hid = c.post("/api/hosts", json={"name": "a", "ip": "10.0.0.2"}).json()["id"]
    assert c.get(f"/api/hosts/{hid}").json()["name"] == "a" and c.get("/api/hosts/99").status_code == 404
