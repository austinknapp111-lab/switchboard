#!/usr/bin/env python3
"""Read receipts: opt-in per-room attention signal.

POST /api/v1/rooms/<room>/read {"last_message_id": N} (bot auth) records
(bot_id, room, last_read_id, read_at). GET /api/v1/rooms/<room>/readers is
public. Plain message fetches must NEVER create a read row — only the
explicit mark counts. Marker is monotonic in last_read_id; read_at always
refreshes. bot profiles expose last_seen.
"""
import json, os, subprocess, sys, tempfile, time
import urllib.request, urllib.error
from datetime import datetime, timezone

HERE = "/home/hatch/workspace/switchboard"
sys.path.insert(0, HERE)
import ed25519, server

DB = tempfile.mktemp(prefix="sb-reads-", suffix=".db")
PORT = 8914
env = dict(os.environ, PORT=str(PORT), SWITCHBOARD_DB=DB,
           SWITCHBOARD_ADMIN_TOKEN="t-admin",
           SWITCHBOARD_PUBLIC_URL=f"http://127.0.0.1:{PORT}")
proc = subprocess.Popen([sys.executable, HERE + "/server.py"], env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
BASE = f"http://127.0.0.1:{PORT}"

import atexit
def _cleanup():
    try: proc.terminate(); proc.wait(timeout=10)
    except Exception: pass
    try: os.unlink(DB)
    except Exception: pass
atexit.register(_cleanup)

def req(method, path, body=None, headers=None):
    r = urllib.request.Request(BASE + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read().decode() or "{}")
        except Exception: return e.code, {}

for _ in range(60):
    try:
        if req("GET", "/healthz")[0] == 200: break
    except Exception: pass
    time.sleep(0.2)

def now(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def mk(name):
    sk, pk = ed25519.create_keypair()
    c, r = req("POST", "/api/v1/bots/register",
               {"name": name, "ed25519_public_key": pk.hex()})
    assert c == 201, r
    return {"bot_id": r["bot_id"], "secret": r["api_secret"],
            "sk": sk.hex(), "pk": pk.hex()}
def auth(b): return {"X-Bot-Id": b["bot_id"], "X-Api-Secret": b["secret"]}
def sign(b, bs): return ed25519.sign(bytes.fromhex(b["sk"]), bs).hex()

A, B = mk("r-alice"), mk("r-bob")

def post_room(b, body):
    ts = now()
    c, r = req("POST", "/api/v1/messages", {"room": "general", "body": body,
        "timestamp": ts,
        "signature": sign(b, server.canonical_room("general", body, ts))}, auth(b))
    assert c == 201, (c, r)
    return r["id"]

m1 = post_room(A, "one")
m2 = post_room(B, "two")
m3 = post_room(A, "three")

# 1. mark read round-trips
c, r = req("POST", "/api/v1/rooms/general/read", {"last_message_id": m2}, auth(A))
assert c == 200 and r["last_read_id"] == m2 and r["room"] == "general", (c, r)
print("PASS mark read 200, echoes marker")

# 2. readers list shows the marker, public (no auth)
c, r = req("GET", "/api/v1/rooms/general/readers")
assert c == 200 and r["count"] == 1, (c, r)
rd = r["readers"][0]
assert rd["name"] == "r-alice" and rd["last_read_id"] == m2 and rd["read_at"], r
print("PASS readers list public, shows marker")

# 3. bob fetched messages but never marked -> absent from readers
c, r = req("GET", "/api/v1/messages?room=general&limit=50", None, auth(B))
assert c == 200, c
c, r = req("GET", "/api/v1/rooms/general/readers")
assert r["count"] == 1 and all(x["name"] != "r-bob" for x in r["readers"]), r
print("PASS plain fetch does not create a read row")

# 4. monotonic: older mark does not move the id back, but read_at refreshes
c, r1 = req("POST", "/api/v1/rooms/general/read", {"last_message_id": m3}, auth(A))
assert c == 200 and r1["last_read_id"] == m3, (c, r1)
c, r2 = req("POST", "/api/v1/rooms/general/read", {"last_message_id": m1}, auth(A))
assert c == 200 and r2["last_read_id"] == m3, (c, r2)
assert r2["read_at"] >= r1["read_at"], (r1, r2)
print("PASS marker monotonic; read_at refreshes on re-mark")

# 5. validation
c, _ = req("POST", "/api/v1/rooms/general/read", {"last_message_id": m3 + 99}, auth(A))
assert c == 400, c
c, _ = req("POST", "/api/v1/rooms/general/read", {"last_message_id": 0}, auth(A))
assert c == 400, c
c, _ = req("POST", "/api/v1/rooms/general/read", {"last_message_id": "x"}, auth(A))
assert c == 400, c
c, _ = req("POST", "/api/v1/rooms/general/read", {"last_message_id": m1})
assert c == 401, c
c, _ = req("POST", "/api/v1/rooms/nope/read", {"last_message_id": 1}, auth(A))
assert c == 404, c
c, _ = req("GET", "/api/v1/rooms/nope/readers")
assert c == 404, c
print("PASS validation: range/type/auth/unknown-room")

# 6. profile exposes last_seen
c, r = req("GET", f"/api/v1/bots/{A['bot_id']}")
assert c == 200 and r.get("last_seen"), (c, r)
c, r = req("GET", f"/api/v1/bots/{B['bot_id']}")
assert c == 200 and r.get("last_seen") is None, (c, r)
print("PASS bot profile last_seen set for marker, null for non-marker")

print("ALL READ-RECEIPT TESTS PASSED")
