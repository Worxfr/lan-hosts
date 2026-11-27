import json
import sqlite3
import time


class DB:
    def __init__(self, path: str):
        self.c = sqlite3.connect(path, check_same_thread=False)
        self.c.row_factory = sqlite3.Row
        self.c.executescript("""
        CREATE TABLE IF NOT EXISTS hosts(
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
          mac TEXT UNIQUE, ip TEXT, up INTEGER, last_seen REAL, checked REAL);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
        """)

    def hosts(self):
        return [dict(r) for r in self.c.execute("SELECT * FROM hosts ORDER BY name COLLATE NOCASE")]

    def host(self, hid):
        r = self.c.execute("SELECT * FROM hosts WHERE id=?", (hid,)).fetchone()
        return dict(r) if r else None

    def add(self, name, mac, ip):
        cur = self.c.execute("INSERT INTO hosts(name,mac,ip) VALUES(?,?,?)", (name, mac, ip))
        self.c.commit()
        return cur.lastrowid

    def update(self, hid, name, mac, ip):
        self.c.execute("UPDATE hosts SET name=?,mac=?,ip=? WHERE id=?", (name, mac, ip, hid))
        self.c.commit()

    def delete(self, hid):
        self.c.execute("DELETE FROM hosts WHERE id=?", (hid,))
        self.c.commit()

    def set_status(self, hid, up):
        now = time.time()
        if up:
            self.c.execute("UPDATE hosts SET up=1,last_seen=?,checked=? WHERE id=?", (now, now, hid))
        else:
            self.c.execute("UPDATE hosts SET up=0,checked=? WHERE id=?", (now, hid))
        self.c.commit()

    def set_ip(self, hid, ip):
        self.c.execute("UPDATE hosts SET ip=? WHERE id=?", (ip, hid))
        self.c.commit()

    def get_setting(self, key, default=None):
        r = self.c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return json.loads(r["value"]) if r else default

    def set_setting(self, key, value):
        self.c.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (key, json.dumps(value)))
        self.c.commit()
