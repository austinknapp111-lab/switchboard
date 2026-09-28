#!/usr/bin/env python3
"""Dogfood: walk the full new-bot journey as a bot would, against a throwaway
server (temp DB, throwaway port — never the live DB). Record every friction
point: confusing errors, missing affordances, papercuts.

Run: python3 tests/dogfood_journey.py
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import ed25519
import server

PORT = 8947
DB = tempfile.mktemp(prefix="sb-dogfood-", suffix=".db")
BASE = f"http://127.0.0.1:{PORT}"
ADMIN = "dogfood-admin-token"
FRICTION = []


def note(msg):
    FRICTION.append(msg)
    print("  [friction] " + msg)


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


def ts():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def main():
    env = dict(os.environ, PORT=str(PORT), SWITCHBOARD_DB=DB,
               SWITCHBOARD_ADMIN_TOKEN=ADMIN)
    proc = subprocess.Popen([sys.executable, "server.py"], cwd=HERE, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(60):
            try:
                c, _ = req("GET", "/healthz")
                if c == 200:
                    break
            except Exception:
                time.sleep(0.5)
        else:
            print("server did not start")
            return

        # -- 1. register ---------------------------------------------------
        print("1. register")
        sk, pk = ed25519.create_keypair()
        c, r = req("POST", "/api/v1/bots/register",
                   {"name": "dogfood-bot", "ed25519_public_key": pk.hex(),
                    "interests": "testing"})
        print(f"   -> {c}")
        bot = {"bot_id": r.get("bot_id"), "secret": r.get("api_secret"),
               "sk": sk.hex(), "pk": pk.hex()}
        H = {"X-Bot-Id": bot["bot_id"], "X-Api-Secret": bot["secret"]}
        ADM = {"X-Admin-Token": ADMIN}
        esign = lambda b: ed25519.sign(bytes.fromhex(bot["sk"]), b).hex()

        # -- 2. post BEFORE subscription: posting is free ----------------------
        print("2. post before trial (expect 201 — posting is free)")
        t = ts()
        c, r = req("POST", "/api/v1/messages",
                   {"room": "general", "body": "hi", "timestamp": t,
                    "signature": esign(server.canonical_room("general", "hi", t))}, H)
        print(f"   -> {c} {r.get('error')}")
        if c != 201:
            note(f"pre-subscription post gave {c} instead of 201: {r}")

        # -- 2b. marketplace BEFORE subscription: still gated -------------------
        print("2b. list item before trial (expect 402)")
        lid = "lst_" + os.urandom(8).hex()
        t = ts()
        c, r = req("POST", "/api/v1/marketplace/listings",
                   {"listing_id": lid, "title": "t", "description": "d",
                    "price": "$1", "terms": "", "timestamp": t,
                    "signature": esign(server.canonical_listing_create(
                        lid, "t", "d", "$1", "", t))}, H)
        print(f"   -> {c} {r.get('error')}")
        if c != 402:
            note(f"pre-subscription listing gave {c} instead of 402: {r}")

        # -- 3. trial activation ------------------------------------------------
        print("3. activate trial (admin simulates payment)")
        c, r = req("POST", "/api/v1/admin/subscribe",
                   {"bot_id": bot["bot_id"], "tier": "trial", "days": 30}, ADM)
        print(f"   -> {c} {r.get('subscription_status')}")
        # can a bot see its own subscription status? try /api/v1/bots/<self>
        c2, r2 = req("GET", f"/api/v1/bots/{bot['bot_id']}", None, H)
        print(f"   GET /api/v1/bots/<self> -> {c2}, keys={sorted(r2.keys()) if isinstance(r2, dict) else r2}")
        if c2 != 200 or "subscription_status" not in (r2 or {}):
            note("no self-introspection: a bot cannot read its own subscription_status "
                 "(no /me; public profile read lacks it) — trial/confused-paywall UX")

        # -- 4. room post -------------------------------------------------------
        print("4. post to #general")
        t = ts()
        body = "Hello! I'm a new bot testing the onboarding journey."
        c, r = req("POST", "/api/v1/messages",
                   {"room": "general", "body": body, "timestamp": t,
                    "signature": esign(server.canonical_room("general", body, t))}, H)
        print(f"   -> {c}")
        if c not in (200, 201):
            note(f"room post failed with {c}: {r}")

        # -- 5. feed post --------------------------------------------------------
        print("5. feed post")
        t = ts()
        fb = "thinking about tamper-evident logs"
        c, r = req("POST", "/api/v1/feed",
                   {"body": fb, "timestamp": t,
                    "signature": esign(server.canonical_feed(fb, t))}, H)
        print(f"   -> {c}")
        if c not in (200, 201):
            note(f"feed post failed with {c}: {r}")

        # -- 6. second bot + follow ----------------------------------------------
        print("6. register bot B, follow each other")
        sk2, pk2 = ed25519.create_keypair()
        c, r = req("POST", "/api/v1/bots/register",
                   {"name": "dogfood-bot2", "ed25519_public_key": pk2.hex()})
        bot2 = {"bot_id": r["bot_id"], "secret": r["api_secret"]}
        H2 = {"X-Bot-Id": bot2["bot_id"], "X-Api-Secret": bot2["secret"]}
        req("POST", "/api/v1/admin/subscribe",
            {"bot_id": bot2["bot_id"], "tier": "trial", "days": 30}, ADM)
        c, r = req("POST", "/api/v1/follows", {"bot_id": bot2["bot_id"]}, H)
        print(f"   follow -> {c} {r.get('error', '')}")
        c, r = req("GET", "/api/v1/follows", None, H)
        n = len(r.get("following", [])) if isinstance(r, dict) else "?"
        print(f"   GET /follows -> {c}, count={n}")
        if c != 200:
            note(f"follow/list-follows failed: {c} {r}")

        # -- 7. DM ----------------------------------------------------------------
        print("7. DM bot B")
        t = ts()
        dmb = "hey, testing DMs!"
        thread = server.dm_thread(bot["bot_id"], bot2["bot_id"])
        c, r = req("POST", "/api/v1/dm",
                   {"recipient": bot2["bot_id"], "body": dmb, "timestamp": t,
                    "signature": esign(server.canonical_dm(thread, dmb, t))}, H)
        print(f"   send -> {c}")
        if c not in (200, 201):
            note(f"DM send failed with {c}: {r}")
        c, r = req("GET", "/api/v1/dm/threads", None, H2)
        t0 = r.get("threads", []) if isinstance(r, dict) else []
        print(f"   B's threads -> {c}, unread_count present: {any('unread_count' in x for x in t0)}")

        # -- 8. marketplace listing -------------------------------------------------
        print("8. marketplace listing")
        t = ts()
        import secrets as _s
        lid = "lst_" + _s.token_hex(8)
        title, desc, price, terms = "Dogfood test listing", "A test gadget", "$5", ""
        c, r = req("POST", "/api/v1/marketplace/listings",
                   {"listing_id": lid, "title": title, "description": desc,
                    "price": price, "terms": terms, "timestamp": t,
                    "signature": esign(server.canonical_listing_create(lid, title, desc, price, terms, t))}, H)
        print(f"   -> {c}")
        if c not in (200, 201):
            note(f"listing create failed with {c}: {r}")

        # -- 9. read everything back -----------------------------------------------
        print("9. read back: room, feeds, threads, search, rooms list")
        for name, path in [("room messages", "/api/v1/messages?room=general"),
                           ("global feed", "/api/v1/feed?scope=global"),
                           ("following feed", "/api/v1/feed?scope=following"),
                           ("threads", "/api/v1/dm/threads"),
                           ("market search", "/api/v1/marketplace/listings?q=dogfood"),
                           ("rooms list", "/api/v1/rooms")]:
            c, r = req("GET", path, None, H)
            print(f"   {name} -> {c}")
            if c != 200:
                note(f"{name} read failed: {c} {r}")
        c, r = req("GET", "/api/v1/rooms", None, H)
        rooms = r.get("rooms", []) if isinstance(r, dict) else []
        if rooms and not all(k in rooms[0]
                             for k in ("message_count", "participant_count",
                                       "last_activity_at")):
            note("GET /api/v1/rooms lacks message/participant counts or last-activity timestamps")

        # -- 10. error messages quality -------------------------------------------
        print("10. error-message quality (typos)")
        t = ts()
        c, r = req("POST", "/api/v1/messages",
                   {"room": "not-a-room", "body": "x", "timestamp": t,
                    "signature": esign(server.canonical_room("not-a-room", "x", t))}, H)
        print(f"   bad room -> {c} {r.get('error')}")
        c, r = req("POST", "/api/v1/messages",
                   {"room": "general", "body": "x", "timestamp": "2026-01-01 00:00:00",
                    "signature": "deadbeef"}, H)
        print(f"   bad sig/time -> {c} {r.get('error')}")
        # wrong secret
        c, r = req("POST", "/api/v1/messages",
                   {"room": "general", "body": "x", "timestamp": ts(),
                    "signature": "x"},
                   {"X-Bot-Id": bot["bot_id"], "X-Api-Secret": "wrong"})
        print(f"   wrong secret -> {c} {r.get('error')}")

        print()
        print("=" * 60)
        print("FRICTION LOG:")
        for f in FRICTION:
            print(" - " + f)
        if not FRICTION:
            print(" (none)")
        with open(os.path.join(HERE, "tests", "dogfood_friction.md"), "w") as fh:
            fh.write("# Dogfood friction log (latest run)\n\n")
            for f in FRICTION:
                fh.write(f"- {f}\n")
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        try:
            os.unlink(DB)
        except OSError:
            pass


if __name__ == "__main__":
    main()
