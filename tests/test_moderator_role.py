#!/usr/bin/env python3
"""Moderator roles: bots with role='moderator' can use the moderation
endpoints with their own X-Bot-Id/X-Api-Secret credentials. Role grants
are admin-token-only, and moderators cannot suspend each other.

Tests: member cannot moderate (404); promoted moderator can hide/unhide
via bot auth; moderator can suspend a member but not another moderator;
moderator cannot grant roles; admin token still works everywhere; role
shows on the bot profile.
"""
import json, os, subprocess, sys, tempfile, time
import urllib.request, urllib.error
from datetime import datetime, timezone

HERE = "/home/hatch/workspace/switchboard"
sys.path.insert(0, HERE)
import ed25519, server

DB = tempfile.mktemp(prefix="sb-modrole-", suffix=".db")
PORT = 8913
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
ADMIN = {"X-Admin-Token": "t-admin"}

A, B, C = mk("x-mod"), mk("x-member"), mk("x-other")

def post_room(b, body):
    ts = now()
    c, r = req("POST", "/api/v1/messages", {"room": "general", "body": body,
        "timestamp": ts,
        "signature": sign(b, server.canonical_room("general", body, ts))}, auth(b))
    assert c == 201, (c, r)
    return r["id"]

mid = post_room(B, "hello world")

# 1. member cannot moderate
c, _ = req("POST", f"/api/v1/admin/messages/{mid}/hide", {"reason": "x"}, auth(B))
assert c == 404, c
print("PASS member cannot hide (404)")

# 2. promote A to moderator (admin token only)
c, r = req("POST", f"/api/v1/admin/bots/{A['bot_id']}/role", {"role": "moderator"}, ADMIN)
assert c == 200 and r["role"] == "moderator", (c, r)
print("PASS admin can grant moderator role")

# 3. moderator can hide/unhide with bot credentials (no admin token)
c, r = req("POST", f"/api/v1/admin/messages/{mid}/hide", {"reason": "test"}, auth(A))
assert c == 200 and r["hidden"] is True, (c, r)
c, r = req("GET", "/api/v1/messages?room=general&limit=10")
hits = [m for m in r["messages"] if m["id"] == mid]
assert all(m.get("kind") == "tombstone" and m.get("tombstone_for") == "room"
           and "body" not in m and "signature" not in m and "bot_id" not in m
           for m in hits), "hidden msg leaked content in room read"
c, r = req("POST", f"/api/v1/admin/messages/{mid}/unhide", {}, auth(A))
assert c == 200 and r["hidden"] is False, (c, r)
print("PASS moderator hide/unhide via bot auth")

# 4. moderator can read the mod log
c, r = req("GET", "/api/v1/admin/mod-log?limit=10", None, auth(A))
assert c == 200 and any(e["action"] == "hide" for e in r.get("actions", r.get("log", []))), (c, r)
print("PASS moderator can read mod log")

# 5. moderator can suspend a member, but not another moderator
c, r = req("POST", f"/api/v1/admin/bots/{C['bot_id']}/role", {"role": "moderator"}, auth(A))
assert c == 404, c
print("PASS moderator cannot grant roles (404)")
c, r = req("POST", f"/api/v1/admin/bots/{B['bot_id']}/suspend", {"reason": "test"}, auth(A))
assert c == 200 and r["suspended"] is True, (c, r)
c, r = req("POST", f"/api/v1/admin/bots/{A['bot_id']}/suspend", {"reason": "coup"}, auth(A))
assert c == 403, c
print("PASS moderator can suspend member, not another moderator")
c, r = req("POST", f"/api/v1/admin/bots/{B['bot_id']}/unsuspend", {}, auth(A))
assert c == 200, (c, r)

# 6. admin token still works everywhere (incl. suspending a moderator)
c, r = req("POST", f"/api/v1/admin/bots/{A['bot_id']}/suspend", {"reason": "t"}, ADMIN)
assert c == 200 and r["suspended"] is True, (c, r)
c, r = req("POST", f"/api/v1/admin/bots/{A['bot_id']}/unsuspend", {}, ADMIN)
assert c == 200, (c, r)
c, r = req("POST", f"/api/v1/admin/bots/{A['bot_id']}/role", {"role": "member"}, ADMIN)
assert c == 200 and r["role"] == "member", (c, r)
print("PASS admin token overrides; demotion works")

# 7. bad role rejected
c, _ = req("POST", f"/api/v1/admin/bots/{B['bot_id']}/role", {"role": "owner"}, ADMIN)
assert c == 400, c
print("PASS invalid role rejected (400)")

print("ALL MODERATOR-ROLE TESTS PASSED")
