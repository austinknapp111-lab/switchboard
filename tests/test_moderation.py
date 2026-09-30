#!/usr/bin/env python3
"""Switchboard moderation tests.

Spins up a throwaway server with a temp SQLite DB, then proves over HTTP:

  hide message -> tombstone in room reads (no body/signature/bot identity),
    excluded from DM reads,
    but hash chains still verify (rows are flagged, never deleted)
  unhide -> message visible again
  suspend bot -> 403 "account suspended" on room post, DM, listing
  unsuspend -> posting works again
  bad admin token -> 404 on all moderation endpoints (same as other admin routes)
  unknown message id / bot id -> 404
  mod-log -> records hide/unhide/suspend/unsuspend newest-first, actor=moderator

Run:  python3 tests/test_moderation.py
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import ed25519
import server  # canonical signing-byte builders (guarantees test/server match)

ADMIN = "test-admin-token"
PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name +
          (f"  -- {detail}" if detail and not cond else ""))


def now_ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


BASE = None


def req(method, path, body=None, headers=None):
    r = urllib.request.Request(
        BASE + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except Exception:
            return e.code, {}


def auth(bot):
    return {"X-Bot-Id": bot["bot_id"], "X-Api-Secret": bot["secret"]}


def get_html(path):
    """Raw HTML fetch (no auth) — /moderation is a public page."""
    r = urllib.request.Request(BASE + path, method="GET")
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


ADM = {"X-Admin-Token": ADMIN}
BAD_ADM = {"X-Admin-Token": "wrong-token"}


def register(name):
    sk, pk = ed25519.create_keypair()
    code, resp = req("POST", "/api/v1/bots/register",
                     {"name": name, "ed25519_public_key": pk.hex()})
    assert code == 201, f"register {name}: {code} {resp}"
    return {"bot_id": resp["bot_id"], "secret": resp["api_secret"],
            "sk": sk.hex(), "pk": pk.hex(), "name": name}


def subscribe(bot):
    c, r = req("POST", "/api/v1/admin/subscribe",
               {"bot_id": bot["bot_id"], "tier": "trial", "days": 30}, ADM)
    assert c == 200, f"subscribe: {c} {r}"


def esign(bot, msg_bytes):
    return ed25519.sign(bytes.fromhex(bot["sk"]), msg_bytes).hex()


def post_room(bot, room, body):
    ts = now_ts()
    return req("POST", "/api/v1/messages",
               {"room": room, "body": body, "timestamp": ts,
                "signature": esign(bot, server.canonical_room(room, body, ts))},
               auth(bot))


def post_dm(bot, recipient_id, body):
    ts = now_ts()
    thread = server.dm_thread(bot["bot_id"], recipient_id)
    return req("POST", "/api/v1/dm",
               {"recipient": recipient_id, "body": body, "timestamp": ts,
                "signature": esign(bot, server.canonical_dm(thread, body, ts))},
               auth(bot))


def create_listing(bot, lid, title, desc, price):
    ts = now_ts()
    return req("POST", "/api/v1/marketplace/listings",
               {"listing_id": lid, "title": title, "description": desc,
                "price": price, "terms": "",
                "timestamp": ts,
                "signature": esign(bot, server.canonical_listing_create(
                    lid, title, desc, price, "", ts))},
               auth(bot))


def start_server(port, db_path):
    global BASE
    env = dict(os.environ, PORT=str(port), SWITCHBOARD_DB=db_path,
               SWITCHBOARD_ADMIN_TOKEN=ADMIN,
               SWITCHBOARD_PUBLIC_URL=f"http://127.0.0.1:{port}")
    proc = subprocess.Popen([sys.executable, os.path.join(HERE, "server.py")],
                            env=env, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    BASE = f"http://127.0.0.1:{port}"
    for _ in range(60):
        try:
            if req("GET", "/healthz")[0] == 200:
                return proc
        except Exception:
            pass
        time.sleep(0.2)
    proc.terminate()
    sys.exit("server did not start on port %d" % port)


def main():
    global BASE
    db = tempfile.mktemp(prefix="sb-testmod-", suffix=".db")
    proc = start_server(8125, db)
    try:
        A = register("mod-alpha")
        B = register("mod-beta")
        subscribe(A)
        subscribe(B)

        # -- seed content --------------------------------------
        c, r = post_room(A, "general", "first visible message")
        check("A room post -> 201", c == 201, f"{c} {r}")
        room_msg = r["id"]
        c, r = post_room(A, "general", "second visible message")
        check("A second room post -> 201", c == 201, f"{c} {r}")
        c, r = post_room(A, "general", "A third visible message")
        check("A third room post -> 201", c == 201, f"{c} {r}")
        third_msg = r["id"]
        c, r = post_dm(A, B["bot_id"], "secret hello")
        check("A DM to B -> 201", c == 201, f"{c} {r}")
        dm_msg = r["id"]

        # -- hide: room read ------------------------------------
        c, r = req("POST", f"/api/v1/admin/messages/{room_msg}/hide",
                   {"reason": "test spam"}, ADM)
        check("admin hide room msg -> 200 hidden=true", c == 200
              and r.get("hidden") is True, f"{c} {r}")
        c, r = req("GET", "/api/v1/messages?room=general")
        msgs = r["messages"]
        tombs = [m for m in msgs if m.get("kind") == "tombstone"]
        check("hidden msg surfaces as tombstone in room read (no body/signature/bot)",
              c == 200 and len(msgs) == 3 and len(tombs) == 1
              and tombs[0]["tombstone_for"] == "room"
              and tombs[0]["hidden"] == 1 and tombs[0]["id"] == room_msg
              and "body" not in tombs[0] and "signature" not in tombs[0]
              and "bot_id" not in tombs[0] and "bot_name" not in tombs[0]
              and msgs[1]["body"] == "second visible message",
              str(r)[:300])
        # chain still intact: rows are flagged, not deleted
        c, r = req("GET", "/api/v1/chain/verify?room=general")
        ch = (r.get("chains") or [{}])[0]
        check("room chain verifies with hidden msg present (messages=3)",
              c == 200 and r.get("ok") is True and ch.get("messages") == 3,
              str(ch))
        # -- unhide restores ------------------------------------
        c, r = req("POST", f"/api/v1/admin/messages/{room_msg}/unhide", {}, ADM)
        check("admin unhide -> 200 hidden=false", c == 200
              and r.get("hidden") is False, f"{c} {r}")
        c, r = req("GET", "/api/v1/messages?room=general")
        check("unhidden msg back in room read", c == 200
              and len(r["messages"]) == 3, str(r)[:200])

        # -- hide: third room message -> tombstone ---------------
        c, _ = req("POST", f"/api/v1/admin/messages/{third_msg}/hide",
                   {"reason": "test"}, ADM)
        check("hide room post -> 200", c == 200, str(c))
        c, r = req("GET", "/api/v1/messages?room=general")
        tombs = [m for m in r["messages"] if m.get("kind") == "tombstone"]
        check("hidden post surfaces as tombstone", c == 200
              and len(tombs) == 1 and tombs[0]["id"] == third_msg,
              str(r)[:200])
        c, _ = req("POST", f"/api/v1/admin/messages/{third_msg}/unhide", {}, ADM)
        check("unhide room post -> 200", c == 200, str(c))
        c, r = req("GET", "/api/v1/messages?room=general")
        check("room post visible again", c == 200
              and any(m.get("body") == "A third visible message"
                      for m in r["messages"]), str(r)[:200])

        # -- hide: DM read --------------------------------------
        c, _ = req("POST", f"/api/v1/admin/messages/{dm_msg}/hide",
                   {"reason": "test"}, ADM)
        check("hide DM -> 200", c == 200, str(c))
        c, r = req("GET", "/api/v1/dm?with=" + A["bot_id"], None, auth(B))
        check("hidden DM excluded from thread read", c == 200
              and len(r["messages"]) == 0, str(r)[:200])
        thread = server.dm_thread(A["bot_id"], B["bot_id"])
        c, r = req("GET", "/api/v1/chain/verify?thread=" +
                   urllib.parse.quote(thread), None, auth(A))
        check("DM chain verifies with hidden msg present",
              c == 200 and r.get("ok") is True, str(r)[:200])
        c, _ = req("POST", f"/api/v1/admin/messages/{dm_msg}/unhide", {}, ADM)
        check("unhide DM -> 200", c == 200, str(c))

        # -- suspend blocks all posting -------------------------
        c, r = req("POST", f"/api/v1/admin/bots/{A['bot_id']}/suspend",
                   {"reason": "test suspension"}, ADM)
        check("admin suspend -> 200 suspended=true", c == 200
              and r.get("suspended") is True, f"{c} {r}")
        c, r = post_room(A, "general", "should not post")
        check("suspended room post -> 403 account suspended",
              c == 403 and r.get("error") == "account suspended", f"{c} {r}")
        c, r = post_dm(A, B["bot_id"], "should not send")
        check("suspended DM -> 403", c == 403
              and r.get("error") == "account suspended", f"{c} {r}")
        c, r = create_listing(A, "lst_" + os.urandom(8).hex(),
                              "Nope", "suspended seller", "$1")
        check("suspended listing create -> 403", c == 403
              and r.get("error") == "account suspended", f"{c} {r}")
        # reading still works while suspended
        c, r = req("GET", "/api/v1/messages?room=general")
        check("suspended bot's reads unaffected", c == 200
              and len(r["messages"]) == 3, str(c))
        # -- unsuspend restores ---------------------------------
        c, r = req("POST", f"/api/v1/admin/bots/{A['bot_id']}/unsuspend", {}, ADM)
        check("admin unsuspend -> 200", c == 200
              and r.get("suspended") is False, f"{c} {r}")
        c, r = post_room(A, "general", "back in business")
        check("unsuspended room post -> 201", c == 201, f"{c} {r}")

        # -- bad admin token -> 404 ------------------------------
        for method, pth, body in [
            ("POST", f"/api/v1/admin/messages/{room_msg}/hide", {"reason": "x"}),
            ("POST", f"/api/v1/admin/messages/{room_msg}/unhide", {}),
            ("POST", f"/api/v1/admin/bots/{A['bot_id']}/suspend", {"reason": "x"}),
            ("POST", f"/api/v1/admin/bots/{A['bot_id']}/unsuspend", {}),
            ("GET", "/api/v1/admin/mod-log", None),
        ]:
            c, _ = req(method, pth, body, BAD_ADM)
            check(f"bad admin token -> 404 ({pth.split('/')[-1]})", c == 404,
                  str(c))

        # -- unknown targets -> 404 ------------------------------
        c, _ = req("POST", "/api/v1/admin/messages/999999/hide",
                   {"reason": "x"}, ADM)
        check("hide unknown message -> 404", c == 404, str(c))
        c, _ = req("POST", "/api/v1/admin/bots/bot_nope/suspend",
                   {"reason": "x"}, ADM)
        check("suspend unknown bot -> 404", c == 404, str(c))
        c, _ = req("POST", "/api/v1/admin/messages/notanint/hide",
                   {"reason": "x"}, ADM)
        check("hide non-integer id -> 404", c == 404, str(c))

        # -- mod log ---------------------------------------------
        c, r = req("GET", "/api/v1/admin/mod-log", None, ADM)
        acts = r.get("actions", [])
        kinds = [a["action"] for a in acts]
        check("mod-log -> 200, 8 actions recorded",
              c == 200 and len(acts) == 8, f"{c} kinds={kinds}")
        check("mod-log newest first (unsuspend last)",
              kinds[0] == "unsuspend" and kinds[-1] == "hide",
              str(kinds))
        check("mod-log actors all 'admin' (token actions)",
              all(a["actor"] == "admin" for a in acts), str(kinds))
        check("mod-log reasons preserved",
              any(a["action"] == "suspend"
                  and a["reason"] == "test suspension"
                  and a["target_type"] == "bot"
                  and a["target_id"] == A["bot_id"] for a in acts),
              str(acts)[:300])
        c, r = req("GET", "/api/v1/admin/mod-log?limit=2", None, ADM)
        check("mod-log limit=2 -> 2 newest", c == 200
              and len(r["actions"]) == 2
              and r["actions"][0]["action"] == "unsuspend", str(r)[:200])

        # -- public mod-log page ---------------------------------
        c, html = get_html("/moderation")
        check("GET /moderation -> 200 public (no auth)", c == 200, str(c))
        check("mod page shows reasons + actor",
              "Moderation log" in html
              and "test suspension" in html
              and "admin" in html, html[:200])
        check("mod page links affected bot profile",
              f'/bot/{A["bot_id"]}' in html, str(c))
        check("mod page reachable from /bots sidebar",
              '/moderation' in get_html("/bots")[1], "no sidebar link")
        # hide a message, verify page shows the action but NEVER the body
        c, _ = req("POST", f"/api/v1/admin/messages/{third_msg}/hide",
                   {"reason": "mod-page-marker-xyz"}, ADM)
        check("hide for page test -> 200", c == 200, str(c))
        c, html = get_html("/moderation")
        check("mod page shows hide action with reason",
              c == 200 and "mod-page-marker-xyz" in html, str(c))
        check("mod page never renders hidden message bodies",
              "A third visible message" not in html, html[:400])
        c, _ = req("POST", f"/api/v1/admin/messages/{third_msg}/unhide", {}, ADM)
        check("unhide after page test -> 200", c == 200, str(c))
    finally:
        proc.terminate()
        try:
            os.unlink(db)
        except OSError:
            pass


if __name__ == "__main__":
    main()
    print()
    print(f"{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", FAIL)
        sys.exit(1)
