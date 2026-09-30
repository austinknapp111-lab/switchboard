#!/usr/bin/env python3
"""Chain export: independent verification of hash chains + Ed25519 signatures.

/api/v1/chain/verify is the server grading its own homework. /api/v1/chain/export
hands out the raw evidence so a client can recompute every hash link from genesis
and check every signature itself. A server that tampers with or forges records
cannot forge bot signatures, so tampering is detectable.

Tests: honest chain verifies; direct-DB body tamper is caught; forged-signature
insert is caught; hidden messages are redacted but links still chain; DM export
requires participant auth; listing event chains verify too.
"""
import hashlib, json, os, sqlite3, subprocess, sys, tempfile, time
import urllib.request, urllib.error
from datetime import datetime, timezone

HERE = "/home/hatch/workspace/switchboard"
sys.path.insert(0, HERE)
import ed25519, server

DB = tempfile.mktemp(prefix="sb-chainx-", suffix=".db")
PORT = 8912
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
    req("POST", "/api/v1/admin/subscribe",
        {"bot_id": r["bot_id"], "tier": "trial", "days": 30},
        {"X-Admin-Token": "t-admin"})
    return {"bot_id": r["bot_id"], "secret": r["api_secret"],
            "sk": sk.hex(), "pk": pk.hex()}
def auth(b): return {"X-Bot-Id": b["bot_id"], "X-Api-Secret": b["secret"]}
def sign(b, bs): return ed25519.sign(bytes.fromhex(b["sk"]), bs).hex()

A, B = mk("x-alice"), mk("x-bob")

def post_room2(b, body):
    ts = now()
    c, r = req("POST", "/api/v1/messages", {"room": "general", "body": body,
        "timestamp": ts,
        "signature": sign(b, server.canonical_room("general", body, ts))}, auth(b))
    assert c == 201, (c, r)
    return r

def dm(frm, to, body):
    ts = now()
    thread = server.dm_thread(frm["bot_id"], to["bot_id"])
    c, r = req("POST", "/api/v1/dm", {"recipient": to["bot_id"], "body": body,
        "timestamp": ts,
        "signature": sign(frm, server.canonical_dm(thread, body, ts))}, auth(frm))
    assert c == 201, (c, r)
    return r, thread

post_room2(A, "alice one")
post_room2(B, "bob one")
post_room2(A, "alice two")
(_, thread) = dm(A, B, "secret hello")

def signed_bytes(kind, scope, r):
    P = "switchboard-v1"
    ts, body, rk = r["client_timestamp"], r["body"], r["kind"]
    if kind in ("room", "dm"):
        if rk == "edit":
            return ("%s:edit:%s\n%s\n%s" % (P, r["edit_of"], body, ts)).encode()
        return ("%s:%s:%s\n%s\n%s" % (P, rk, scope, body, ts)).encode()
    payload = json.loads(body)
    if r["kind"] == "created":
        if kind == "listing":
            return ("%s:listing:create:%s\n%s\n%s\n%s\n%s\n%s" % (
                P, scope, payload["title"], payload["description"],
                payload["price"], payload["terms"], ts)).encode()
        return ("%s:project:create:%s\n%s\n%s\n%s\n%s" % (
            P, scope, payload["title"], payload["brief"],
            payload["coordinator_cut_pct"], ts)).encode()
    return ("%s:%s:event:%s\n%s\n%s\n%s" % (P, kind, scope, r["kind"], body, ts)).encode()

def verify_export(exp, pubkeys):
    """Independent verification. Returns (ok, detail)."""
    kind, scope = exp["kind"], exp["scope"]
    prev = exp["genesis"]
    for r in exp["records"]:
        if r["prev_hash"] != prev:
            return False, "link break at seq %s" % r["seq"]
        if not r["hidden"]:
            ck = kind if kind in ("listing", "project") else r["kind"]
            b = r["body"] if kind in ("room", "dm") else \
                "%s:%s" % (r["kind"], r["body"])
            h = hashlib.sha256(("%s\n%s\n%s\n%s\n%s\n%s" % (
                prev, ck, scope, r["actor"], b,
                r["client_timestamp"])).encode()).hexdigest()
            if h != r["hash"]:
                return False, "hash mismatch at seq %s" % r["seq"]
            pk = pubkeys.get(r["actor"])
            if pk is None:
                return False, "unknown actor at seq %s" % r["seq"]
            if not ed25519.verify(pk, signed_bytes(kind, scope, r),
                                  bytes.fromhex(r["signature"])):
                return False, "bad signature at seq %s" % r["seq"]
        prev = r["hash"]
    return True, "ok"

c, bots = req("GET", "/api/v1/bots")
assert c == 200
pubkeys = {b["bot_id"]: bytes.fromhex(b["public_key"]) for b in bots["bots"]}

passed = failed = 0
def check(name, cond, detail=""):
    global passed, failed
    if cond: passed += 1; print("ok -", name)
    else: failed += 1; print("FAIL -", name, detail)

# 1. honest room chain verifies
c, exp = req("GET", "/api/v1/chain/export?room=general")
ok, detail = verify_export(exp, pubkeys)
check("honest room chain verifies independently", c == 200 and ok, detail)
check("export has records with signatures", len(exp["records"]) == 3 and
      all(r["signature"] for r in exp["records"]))

# 2. honest DM chain verifies (as participant)
c, exp = req("GET", "/api/v1/chain/export?thread=" + thread, headers=auth(A))
ok, detail = verify_export(exp, pubkeys)
check("honest DM chain verifies as participant", c == 200 and ok, detail)

# 3. DM export auth: anonymous 401, non-participant 403
C = mk("x-carol")
c, _ = req("GET", "/api/v1/chain/export?thread=" + thread)
check("DM export anonymous -> 401", c == 401, c)
c, _ = req("GET", "/api/v1/chain/export?thread=" + thread, headers=auth(C))
check("DM export non-participant -> 403", c == 403, c)

# 4. feed chain removed: ?feed= no longer a valid export scope
c, _ = req("GET", "/api/v1/chain/export?feed=" + A["bot_id"])
check("feed export -> 400 (removed)", c == 400, c)

# 5. forge: insert a properly-chained but mis-signed record; sig check catches it
con = sqlite3.connect(DB)
row = con.execute("SELECT hash FROM messages WHERE scope='general' ORDER BY id DESC LIMIT 1").fetchone()
prevh = row[0]
ts = now()
fake_hash = server.message_hash(prevh, "room", "general", B["bot_id"], "forged!", ts)
con.execute("INSERT INTO messages (kind, scope, bot_id, body, client_timestamp, signature,"
            " prev_hash, hash, created_at) VALUES ('room','general',?,?,?,?,?,?,?)",
            (B["bot_id"], "forged!", ts, "00" * 64, prevh, fake_hash, ts))
con.commit(); con.close()
c, exp = req("GET", "/api/v1/chain/export?room=general")
ok, detail = verify_export(exp, pubkeys)
check("forged-signature insert detected", c == 200 and not ok, detail)
check("forge detail is signature failure", "signature" in detail, detail)

# 6. tamper: rewrite a body directly in the DB; export must expose it
con = sqlite3.connect(DB)
con.execute("UPDATE messages SET body='tampered by server' WHERE id=2")
con.commit(); con.close()
c, exp = req("GET", "/api/v1/chain/export?room=general")
ok, detail = verify_export(exp, pubkeys)
check("direct-DB body tamper detected", c == 200 and not ok, detail)
check("tamper detail names the record", "seq 2" in detail, detail)

# 7. hidden message: redacted but links still chain
con = sqlite3.connect(DB)
con.execute("UPDATE messages SET hidden=1 WHERE id=1")
con.commit(); con.close()
c, exp = req("GET", "/api/v1/chain/export?room=general")
rec1 = [r for r in exp["records"] if r["seq"] == 1][0]
check("hidden record redacts body+signature", rec1["body"] is None and
      rec1["signature"] is None and rec1["hidden"] == 1, rec1)
# links must still chain across the redaction: verify links only
prev = exp["genesis"]; links_ok = True
for r in exp["records"]:
    if r["prev_hash"] != prev: links_ok = False; break
    prev = r["hash"]
check("chain links intact across hidden redaction", links_ok)

# 8. listing event chain verifies (exercises event canonical forms)
ts = now(); lid = "lst_" + "ab12cd34ef56ab78"
c, r = req("POST", "/api/v1/marketplace/listings",
           {"listing_id": lid, "title": "Test data", "description": "desc",
            "price": "$5", "terms": "t", "timestamp": ts,
            "signature": sign(A, server.canonical_listing_create(
                lid, "Test data", "desc", "$5", "t", ts))}, auth(A))
check("listing created for event-chain test", c == 201, (c, r))
c, exp = req("GET", "/api/v1/chain/export?listing=" + lid)
ok, detail = verify_export(exp, pubkeys)
check("listing event chain verifies independently", c == 200 and ok, detail)

# 9. bad requests
c, _ = req("GET", "/api/v1/chain/export")
check("no scope -> 400", c == 400, c)
c, _ = req("GET", "/api/v1/chain/export?room=general&thread=x")
check("two scopes -> 400", c == 400, c)
c, _ = req("GET", "/api/v1/chain/export?room=nope")
check("unknown room -> 400", c == 400, c)

proc.terminate(); proc.wait(timeout=10)
os.unlink(DB)
print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
