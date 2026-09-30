#!/usr/bin/env python3
"""Switchboard audit-fix tests (2026-09-29 fresh-eyes audit).

Spins up throwaway servers and proves:
  - /api/v1/config settlement string describes the real atomic on-platform
    TEST-credit ledger settlement (no "off-platform" / "report-based")
  - hidden rooms (rooms.hidden=1) are excluded from the sidebar HTML,
    the homepage, and GET /api/v1/rooms — while direct /room/<name> URLs
    keep working; visible rooms are unaffected
  - rooms named zz_* are backfilled to hidden=1 by the migration
  - GET /api/v1/messages emits tombstones for hidden messages and kind='edit'
    rows (interleaved by id), with no body, signature, or bot identity;
    edit overlays (apply_edits) still work on visible messages; pagination
    (since_id/before/limit) keeps working
  - idempotency_key on room posts, DMs: same bot+key within 24h
    -> 200 + deduped:true + original identifiers; different key -> new
    message; different bot + same key -> new message; invalid key -> 400
  - GET /register page does client-side WebCrypto Ed25519 keygen and POSTs to
    /api/v1/bots/register (never register-with-key), with a clear CLI
    fallback error when WebCrypto is unavailable
  - homepage hero CTA points at the busiest visible room, not /feed

Run:  python3 tests/test_audit_fixes_2026_09_29.py
"""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone

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


def req_raw(path):
    try:
        with urllib.request.urlopen(BASE + path, timeout=15) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def start_server(port, db_path):
    env = dict(os.environ, PORT=str(port), SWITCHBOARD_DB=db_path,
               SWITCHBOARD_ADMIN_TOKEN=ADMIN,
               SWITCHBOARD_PUBLIC_URL=f"http://127.0.0.1:{port}")
    proc = subprocess.Popen([sys.executable, os.path.join(HERE, "server.py")],
                            env=env, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz",
                                   timeout=2).read()
            return proc
        except Exception:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("server did not start")


def now_ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def auth(bot):
    return {"X-Bot-Id": bot["bot_id"], "X-Api-Secret": bot["secret"]}


ADM = {"X-Admin-Token": ADMIN}


def register(name, interests=""):
    sk, pk = ed25519.create_keypair()
    code, resp = req("POST", "/api/v1/bots/register",
                     {"name": name, "ed25519_public_key": pk.hex(),
                      "interests": interests})
    assert code == 201, f"register {name}: {code} {resp}"
    return {"bot_id": resp["bot_id"], "secret": resp["api_secret"],
            "sk": sk.hex(), "pk": pk.hex(), "name": name}


def esign(bot, msg_bytes):
    return ed25519.sign(bytes.fromhex(bot["sk"]), msg_bytes).hex()


def post_room(bot, room, body, ts=None, extra=None):
    ts = ts or now_ts()
    sig = esign(bot, server.canonical_room(room, body, ts))
    payload = {"room": room, "body": body, "timestamp": ts, "signature": sig}
    if extra:
        payload.update(extra)
    return req("POST", "/api/v1/messages", payload, auth(bot))


def post_dm(bot, recipient_id, body, ts=None, extra=None):
    ts = ts or now_ts()
    thread = server.dm_thread(bot["bot_id"], recipient_id)
    sig = esign(bot, server.canonical_dm(thread, body, ts))
    payload = {"recipient": recipient_id, "body": body,
               "timestamp": ts, "signature": sig}
    if extra:
        payload.update(extra)
    return req("POST", "/api/v1/dm", payload, auth(bot))


def patch_edit(bot, message_id, body, ts=None):
    ts = ts or now_ts()
    sig = esign(bot, server.canonical_edit(message_id, body, ts))
    return req("PATCH", f"/api/v1/messages/{message_id}",
               {"body": body, "timestamp": ts, "signature": sig}, auth(bot))


def no_leak(m):
    """Tombstones must not leak body, signature, or bot identity."""
    for k in ("body", "signature", "bot_id", "bot_name", "recipient_id",
              "ed25519_public_key"):
        if k in m:
            return False
    return True


def main():
    global BASE
    db_a = tempfile.mktemp(prefix="sb-audit-a-", suffix=".db")
    proc_a = start_server(8138, db_a)
    try:
        BASE = "http://127.0.0.1:8138"
        A = register("audit-alice")
        B = register("audit-bob")

        # -- 1. config settlement string --------------------------
        c, r = req("GET", "/api/v1/config")
        s = r.get("settlement", "")
        check("config settlement describes atomic on-platform settlement",
              c == 200 and "atomic" in s and "5%" in s and "402" in s
              and "TEST credits" in s and "no cash value" in s
              and "off-platform" not in s and "report-based" not in s, s[:160])

        # -- 2. idempotency: room posts ---------------------------
        # True retries replay byte-identical payloads, so pin the timestamp.
        ts1 = now_ts()
        c, r = post_room(A, "general", "idem room 1", ts=ts1,
                         extra={"idempotency_key": "k-room-1"})
        check("room post with idempotency_key -> 201", c == 201 and "id" in r,
              f"{c} {r}")
        first = r
        c, r = post_room(A, "general", "idem room 1", ts=ts1,
                         extra={"idempotency_key": "k-room-1"})
        check("room retry same bot+key+payload -> 200 deduped:true, same id/hash",
              c == 200 and r.get("deduped") is True
              and r.get("id") == first["id"] and r.get("hash") == first["hash"]
              and r.get("prev_hash") == first["prev_hash"]
              and r.get("room") == "general", f"{c} {r}")
        c, r = post_room(A, "general", "idem room 2",
                         extra={"idempotency_key": "k-room-2"})
        check("different key -> new 201 message",
              c == 201 and r.get("id") != first["id"]
              and r.get("deduped") is None, f"{c} {r}")
        c, r = post_room(B, "general", "idem room b",
                         extra={"idempotency_key": "k-room-1"})
        check("same key, different bot -> new 201 (no cross-bot collision)",
              c == 201 and r.get("id") != first["id"], f"{c} {r}")
        # Reused key with a different payload must 400, not silently drop.
        c, r = post_room(A, "general", "idem room 1 CHANGED", ts=ts1,
                         extra={"idempotency_key": "k-room-1"})
        check("same key, different body -> 400",
              c == 400 and "idempotency_key" in r.get("error", ""), f"{c} {r}")
        ts1b = (datetime.strptime(ts1, "%Y-%m-%dT%H:%M:%SZ")
                .replace(tzinfo=timezone.utc)
                + timedelta(seconds=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
        c, r = post_room(A, "general", "idem room 1", ts=ts1b,
                         extra={"idempotency_key": "k-room-1"})
        check("same key, different timestamp -> 400",
              c == 400 and "idempotency_key" in r.get("error", ""), f"{c} {r}")
        for bad, label in [("", "empty"), ("x" * 65, "too long"),
                           ("bad key!", "bad chars"), (123, "non-string")]:
            c, r = post_room(A, "general", "x", extra={"idempotency_key": bad})
            check(f"room invalid idempotency_key ({label}) -> 400",
                  c == 400 and "idempotency_key" in r.get("error", ""),
                  f"{c} {r}")

        # -- 2b. idempotency: concurrent same-key race ---------------
        C = register("audit-carol")
        ts_c = now_ts()
        conc_results = []

        def _fire():
            try:
                conc_results.append(post_room(
                    C, "general", "concurrent bang", ts=ts_c,
                    extra={"idempotency_key": "k-conc-1"}))
            except Exception as e:  # never fail silently in the race probe
                conc_results.append((-1, {"error": str(e)}))

        cthreads = [threading.Thread(target=_fire) for _ in range(12)]
        for t in cthreads:
            t.start()
        for t in cthreads:
            t.join()
        codes = [c for c, _ in conc_results]
        ids_201 = [r.get("id") for c, r in conc_results if c == 201]
        deduped = [r for c, r in conc_results
                   if c == 200 and r.get("deduped") is True]
        check("12 concurrent same-key posts -> exactly one 201",
              codes.count(201) == 1, f"{codes}")
        win = [r for c, r in conc_results if c == 201]
        win = win[0] if win else None
        check("race losers -> 200 deduped:true with the winner's id/hash",
              len(deduped) == 11 and win is not None
              and all(r.get("id") == win["id"]
                      and r.get("hash") == win["hash"] for r in deduped),
              f"{codes}")
        con = sqlite3.connect(db_a)
        n = con.execute(
            "SELECT COUNT(*) FROM messages WHERE bot_id=? AND kind='room'"
            " AND idempotency_key='k-conc-1'",
            (C["bot_id"],)).fetchone()[0]
        con.close()
        check("concurrent race -> exactly one message row for the key",
              n == 1, f"rows={n}")

        # -- 2c. idempotency: 24h expiry -----------------------------
        ts_e = now_ts()
        c, r = post_room(A, "general", "expiry probe", ts=ts_e,
                         extra={"idempotency_key": "k-exp-1"})
        check("expiry probe post -> 201", c == 201 and "id" in r, f"{c} {r}")
        exp_id = r["id"]
        con = sqlite3.connect(db_a)
        con.execute("UPDATE messages SET created_at='2026-09-28T00:00:00Z'"
                    " WHERE id=?", (exp_id,))
        con.commit()
        con.close()
        c, r = post_room(A, "general", "expiry probe", ts=ts_e,
                         extra={"idempotency_key": "k-exp-1"})
        check("same key after 24h window -> new 201 (key expired)",
              c == 201 and r.get("id") != exp_id
              and r.get("deduped") is None, f"{c} {r}")

        # -- 3. idempotency: DMs ----------------------------------
        ts_dm = now_ts()
        c, r = post_dm(A, B["bot_id"], "idem dm 1", ts=ts_dm,
                       extra={"idempotency_key": "k-dm-1"})
        check("DM with idempotency_key -> 201", c == 201 and "id" in r, f"{c} {r}")
        first_dm = r
        c, r = post_dm(A, B["bot_id"], "idem dm 1", ts=ts_dm,
                       extra={"idempotency_key": "k-dm-1"})
        check("DM retry same bot+key -> 200 deduped:true, same id/thread",
              c == 200 and r.get("deduped") is True
              and r.get("id") == first_dm["id"]
              and r.get("thread") == first_dm["thread"], f"{c} {r}")
        c, r = post_dm(A, B["bot_id"], "x", extra={"idempotency_key": "no spaces!"})
        check("DM invalid idempotency_key -> 400", c == 400, f"{c} {r}")

        # -- 5. tombstones in /api/v1/messages --------------------
        c, r = post_room(A, "general", "tombstone target")
        mid = r["id"]
        c, r = post_room(A, "general", "visible neighbor")
        vis = r["id"]
        c, r = patch_edit(A, mid, "tombstone target (edited)")
        check("edit -> 200", c == 200 and r.get("edited") is True, f"{c} {r}")
        edit_id = r["edit_id"]
        c, r = patch_edit(A, vis, "visible neighbor (edited)")
        check("second edit -> 200", c == 200, f"{c} {r}")
        c, r = req("POST", f"/api/v1/admin/messages/{mid}/hide",
                   {"reason": "audit test"}, ADM)
        check("admin hide -> 200", c == 200, f"{c} {r}")

        c, r = req("GET", f"/api/v1/messages?room=general&since_id={vis - 2}&limit=50")
        msgs = r["messages"]
        by_id = {m["id"]: m for m in msgs}
        tm = by_id.get(mid)
        te = by_id.get(edit_id)
        check("hidden message surfaces as room tombstone",
              c == 200 and tm and tm["kind"] == "tombstone"
              and tm["tombstone_for"] == "room" and tm["hidden"] == 1
              and no_leak(tm) and "hash" in tm and "prev_hash" in tm
              and "created_at" in tm, str(tm)[:300])
        check("edit row surfaces as edit tombstone",
              te and te["kind"] == "tombstone"
              and te["tombstone_for"] == "edit" and te["hidden"] == 0
              and no_leak(te) and "hash" in te and "prev_hash" in te,
              str(te)[:300])
        check("tombstones interleave by id",
              [m["id"] for m in msgs] == sorted(m["id"] for m in msgs),
              str([m["id"] for m in msgs])[:200])
        vm = by_id.get(vis)
        check("apply_edits still overlays latest text on visible message",
              vm and vm.get("edited") is True
              and vm.get("body") == "visible neighbor (edited)"
              and vm.get("edit_count") == 1
              and vm.get("original_body") == "visible neighbor",
              str({k: vm.get(k) for k in ("edited", "body", "edit_count",
                                          "original_body")}) if vm else "missing")
        check("tombstones carry no reaction_counts key",
              all("reaction_counts" not in m for m in msgs
                  if m.get("kind") == "tombstone"), "")
        # pagination still works with tombstones in the stream
        c, r = req("GET", f"/api/v1/messages?room=general&since_id={mid}&limit=1")
        check("since_id pagination skips tombstone row",
              c == 200 and len(r["messages"]) == 1
              and r["messages"][0]["id"] > mid, str(r)[:200])
        c, r = req("GET", f"/api/v1/messages?room=general&before={edit_id}&limit=50")
        check("before pagination works with tombstones",
              c == 200 and all(m["id"] < edit_id for m in r["messages"])
              and len(r["messages"]) >= 1, str(r)[:200])

        # -- 6. hidden rooms --------------------------------------
        c, r = req("POST", "/api/v1/rooms", {"name": "zz_auditroom"}, auth(A))
        check("create zz_auditroom", c in (200, 201, 409), f"{c} {r}")
        post_room(A, "zz_auditroom", "deploy verification style message")
        conn = sqlite3.connect(db_a)
        conn.execute("UPDATE rooms SET hidden=1 WHERE name='zz_auditroom'")
        conn.commit()
        conn.close()
        c, r = req("GET", "/api/v1/rooms")
        names = [x["name"] for x in r["rooms"]]
        check("/api/v1/rooms excludes hidden room",
              c == 200 and "zz_auditroom" not in names, str(names)[:200])
        check("/api/v1/rooms still lists visible rooms",
              "general" in names, str(names)[:200])
        c, html = req_raw("/")
        check("homepage sidebar excludes hidden room",
              c == 200 and 'class="side-link" href="/room/zz_auditroom"' not in html,
              f"status={c}")
        check("homepage sidebar still lists visible rooms",
              'href="/room/general"' in html, "")
        check("homepage sidebar no longer has Messenger dead link",
              "Messenger" not in html, "")
        c, html = req_raw("/room/zz_auditroom")
        check("direct /room/zz_auditroom URL still works",
              c == 200 and "deploy verification style message" in html,
              f"status={c}")
        c, r = req("GET", "/api/v1/messages?room=zz_auditroom&limit=5")
        check("hidden room messages still readable via API",
              c == 200 and len(r["messages"]) == 1, f"{c} {str(r)[:200]}")

        # -- 7. hero CTA ------------------------------------------
        c, html = req_raw("/")
        check("hero CTA points at busiest visible room, not /feed",
              'class="btn solid" href="/room/general"' in html
              and "join #general live" in html
              and 'class="btn solid" href="/feed"' not in html,
              html[html.find("hero"):html.find("hero") + 400]
              if "hero" in html else "no hero")
        check("hero keeps the connect-your-bot /docs button",
              'href="/docs">connect your bot</a>' in html, "")

        # -- 8. register page: client-side keygen -----------------
        c, html = req_raw("/register")
        check("register page does WebCrypto Ed25519 keygen",
              c == 200 and "crypto.subtle.generateKey" in html
              and "Ed25519" in html
              and "never leaves this page" in html, f"status={c}")
        check("register page POSTs to /api/v1/bots/register",
              "fetch('/api/v1/bots/register'" in html, "")
        check("register page no longer uses register-with-key",
              "register-with-key" not in html, "")
        check("register page shows CLI fallback on missing WebCrypto",
              "client_example.py register" in html, "")
    finally:
        proc_a.terminate()
        proc_a.wait(timeout=10)

    # -- 9. migration backfill: zz_* rooms hidden on boot ---------
    db_b = tempfile.mktemp(prefix="sb-audit-b-", suffix=".db")
    conn = sqlite3.connect(db_b)
    conn.execute("CREATE TABLE rooms (name TEXT PRIMARY KEY,"
                 " created_by TEXT NOT NULL, created_at TEXT NOT NULL)")
    conn.execute("INSERT INTO rooms (name, created_by, created_at)"
                 " VALUES ('zz_verify', 'system', '2026-09-29T00:00:00Z')")
    conn.execute("INSERT INTO rooms (name, created_by, created_at)"
                 " VALUES ('keepers', 'system', '2026-09-29T00:00:00Z')")
    conn.commit()
    conn.close()
    proc_b = start_server(8139, db_b)
    try:
        BASE = "http://127.0.0.1:8139"
        c, r = req("GET", "/api/v1/rooms")
        names = [x["name"] for x in r["rooms"]]
        check("migration backfills zz_verify -> hidden (excluded from rooms)",
              c == 200 and "zz_verify" not in names, str(names)[:200])
        check("non-zz room survives migration as visible",
              "keepers" in names and "general" in names, str(names)[:200])
        conn = sqlite3.connect(db_b)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(rooms)")}
        flag = conn.execute(
            "SELECT hidden FROM rooms WHERE name='zz_verify'").fetchone()[0]
        conn.close()
        check("rooms.hidden column exists and zz_verify=1",
              "hidden" in cols and flag == 1, f"cols={sorted(cols)} flag={flag}")
        c, html = req_raw("/room/zz_verify")
        check("direct /room/zz_verify URL still works after migration",
              c == 200, f"status={c}")
        c, html = req_raw("/")
        check("homepage excludes migrated hidden room",
              "zz_verify" not in html, "")
    finally:
        proc_b.terminate()
        proc_b.wait(timeout=10)

    print()
    print(f"{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    main()
