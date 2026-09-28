#!/usr/bin/env python3
"""DM unread indicator: unread_count per thread + ?since cursor.

Additive v1 feature: GET /api/v1/dm/threads gains unread_count;
GET /api/v1/dm?with= marks the thread read (monotone mark)."""
import json, os, subprocess, sys, tempfile, time
import urllib.request, urllib.error
from datetime import datetime, timezone

HERE = "/home/hatch/workspace/switchboard"
sys.path.insert(0, HERE)
import ed25519, server

DB = tempfile.mktemp(prefix="sb-unread-", suffix=".db")
PORT = 8911
env = dict(os.environ, PORT=str(PORT), SWITCHBOARD_DB=DB,
           SWITCHBOARD_ADMIN_TOKEN="u-admin",
           SWITCHBOARD_PUBLIC_URL=f"http://127.0.0.1:{PORT}")
proc = subprocess.Popen([sys.executable, HERE + "/server.py"], env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
BASE = f"http://127.0.0.1:{PORT}"

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
    req("POST", "/api/v1/admin/subscribe",
        {"bot_id": r["bot_id"], "tier": "trial", "days": 30},
        {"X-Admin-Token": "u-admin"})
    return {"bot_id": r["bot_id"], "secret": r["api_secret"], "sk": sk.hex()}
def auth(b): return {"X-Bot-Id": b["bot_id"], "X-Api-Secret": b["secret"]}
def sign(b, bs): return ed25519.sign(bytes.fromhex(b["sk"]), bs).hex()

A, B = mk("u-alice"), mk("u-bob")
def send(frm, to, body):
    thread = server.dm_thread(frm["bot_id"], to["bot_id"])
    ts = now()
    return req("POST", "/api/v1/dm",
               {"recipient": to["bot_id"], "body": body, "timestamp": ts,
                "signature": sign(frm, server.canonical_dm(thread, body, ts))},
               auth(frm))

send(A, B, "hi bob")
send(A, B, "second msg")
send(B, A, "hey alice")

c, t = req("GET", "/api/v1/dm/threads", headers=auth(A))
c2, t2 = req("GET", "/api/v1/dm/threads", headers=auth(B))
ta, tb = t["threads"][0], t2["threads"][0]
print("A sees:", ta)
print("B sees:", tb)
assert ta["unread_count"] == 1, ta   # B's one msg
assert tb["unread_count"] == 2, tb   # A's two msgs

# A reads thread -> mark read
c, r = req("GET", f"/api/v1/dm?with={B['bot_id']}", headers=auth(A))
assert c == 200, r
c, t = req("GET", "/api/v1/dm/threads", headers=auth(A))
assert t["threads"][0]["unread_count"] == 0, t
c, t2 = req("GET", "/api/v1/dm/threads", headers=auth(B))
assert t2["threads"][0]["unread_count"] == 2, t2  # B untouched

# since filter
c, t = req("GET", "/api/v1/dm/threads?since=2999-01-01T00:00:00Z", headers=auth(A))
assert t["threads"] == [], t
c, t = req("GET", "/api/v1/dm/threads?since=2000-01-01T00:00:00Z", headers=auth(A))
assert len(t["threads"]) == 1, t

# mark is monotone: reading an older page must not unmark
c, r = req("GET", f"/api/v1/dm?with={B['bot_id']}&since_id=9999", headers=auth(A))
assert c == 200
c, t = req("GET", "/api/v1/dm/threads", headers=auth(A))
assert t["threads"][0]["unread_count"] == 0, t

# legacy shape preserved
assert set(["thread", "other_bot_id", "other_bot_name", "message_count",
            "last_at"]).issubset(ta.keys())

print("ALL DM-UNREAD CHECKS PASS")
proc.terminate()
