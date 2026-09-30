#!/usr/bin/env python3
"""Switchboard webhooks (push notifications) acceptance tests.

Spins up throwaway server(s) with temp SQLite DBs, then proves end-to-end
over HTTP:

  URL validation (SSRF guards): https-only, no userinfo, default port only,
  private/loopback/link-local/reserved IPs rejected (unit + e2e on a strict
  server); bad events/signature/suspended -> 400/403; per-bot limit -> 409.
  register -> 201 (secret shown once, never in list); re-register same URL ->
  idempotent refresh; delete (bad sig -> 403, missing/other-bot -> 404).
  delivery: local HTTP receiver gets DM + room-mention payloads
  with valid HMAC-SHA256 signatures; no delivery without a matching @mention,
  on self-mention, or for unknown names; retry/backoff then auto-disable after
  N consecutive failures.

Run:  python3 tests/test_webhooks.py
"""
import hashlib
import hmac
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import ed25519
import server  # canonical signing-byte builders + url validation unit tests

ADMIN = "test-admin-token"
PASS, FAIL = [], []
BASE = None


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name +
          (f"  -- {detail}" if detail and not cond else ""))


def now_ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


ADM = {"X-Admin-Token": ADMIN}


def register(name):
    sk, pk = ed25519.create_keypair()
    code, resp = req("POST", "/api/v1/bots/register",
                     {"name": name, "ed25519_public_key": pk.hex()})
    if code != 201:
        return code, resp
    return code, {"bot_id": resp["bot_id"], "secret": resp["api_secret"],
                  "sk": sk.hex(), "pk": pk.hex(), "name": name}


def start_server(port, db_path, extra_env=None):
    global BASE
    env = dict(os.environ, PORT=str(port), SWITCHBOARD_DB=db_path,
               SWITCHBOARD_ADMIN_TOKEN=ADMIN,
               SWITCHBOARD_PUBLIC_URL=f"http://127.0.0.1:{port}")
    env.update(extra_env or {})
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


def sign(sk_hex, canonical: bytes) -> str:
    return ed25519.sign(bytes.fromhex(sk_hex), canonical).hex()


def webhook_register(bot, url, events):
    events_csv = ",".join(sorted(events))
    ts = now_ts()
    sig = sign(bot["sk"], server.canonical_webhook_register(url, events_csv, ts))
    return req("POST", "/api/v1/webhooks",
               {"url": url, "events": events, "timestamp": ts, "signature": sig},
               auth(bot))


def webhook_delete(bot, wid, bad_sig=False):
    ts = now_ts()
    sk = "00" * 32 if bad_sig else bot["sk"]
    sig = sign(sk, server.canonical_webhook_delete(wid, ts))
    return req("DELETE", f"/api/v1/webhooks/{wid}",
               {"timestamp": ts, "signature": sig}, auth(bot))


def post_room(bot, room, body):
    ts = now_ts()
    sig = sign(bot["sk"], server.canonical_room(room, body, ts))
    return req("POST", "/api/v1/messages",
               {"room": room, "body": body, "timestamp": ts, "signature": sig},
               auth(bot))


def post_dm(me, other, body):
    thread = server.dm_thread(me["bot_id"], other["bot_id"])
    ts = now_ts()
    sig = sign(me["sk"], server.canonical_dm(thread, body, ts))
    return req("POST", "/api/v1/dm",
               {"recipient": other["bot_id"], "body": body,
                "timestamp": ts, "signature": sig}, auth(me))


# ------------------------------------------------- delivery receiver
class Receiver(BaseHTTPRequestHandler):
    hits = []
    lock = threading.Lock()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        with Receiver.lock:
            Receiver.hits.append({
                "path": self.path,
                "event": self.headers.get("X-Switchboard-Event"),
                "sig": self.headers.get("X-Switchboard-Signature"),
                "delivery": self.headers.get("X-Switchboard-Delivery"),
                "body": raw,
            })
        data = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def start_receiver():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def wait_hits(n, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        with Receiver.lock:
            if len(Receiver.hits) >= n:
                return True
        time.sleep(0.1)
    return False


def verify_hit(hit, secret_hex, event):
    if hit["event"] != event:
        return False, "wrong event header"
    if not hit["delivery"]:
        return False, "missing delivery id"
    expect = "sha256=" + hmac.new(bytes.fromhex(secret_hex), hit["body"],
                                  hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, hit["sig"] or ""):
        return False, "bad HMAC signature"
    try:
        payload = json.loads(hit["body"].decode())
    except Exception:
        return False, "body not JSON"
    if payload.get("event") != event:
        return False, "payload event mismatch"
    return True, payload


# ---------------------------------------------------------------- tests
def main():
    # -- unit: url validation -------------------------------------
    server.WEBHOOK_ALLOW_PRIVATE = False
    strict_cases = [
        ("https://203.0.113.7/hook", False),   # TEST-NET-3, reserved-ish
        ("https://10.1.2.3/hook", False),
        ("https://172.16.0.1/hook", False),
        ("https://192.168.1.1/hook", False),
        ("https://127.0.0.1/hook", False),
        ("https://[::1]/hook", False),
        ("https://169.254.169.254/hook", False),  # cloud metadata
        ("http://203.0.113.7/hook", False),       # http blocked in strict mode
        ("ftp://203.0.113.7/hook", False),
        ("https://user@203.0.113.7/hook", False),
        ("https://203.0.113.7:8443/hook", False),
        ("", False), ("not a url", False),
    ]
    for url, want in strict_cases:
        ok, _ = server.webhook_url_ok(url)
        check(f"strict validation {url or '<empty>'} -> {'ok' if want else 'blocked'}",
              ok == want, url)
    server.WEBHOOK_ALLOW_PRIVATE = True
    for url in ["http://127.0.0.1:9/hook", "https://127.0.0.1/hook",
                "http://10.0.0.9/hook"]:
        ok, _ = server.webhook_url_ok(url)
        check(f"allow-private validation {url} -> ok", ok, url)
    server.WEBHOOK_ALLOW_PRIVATE = False
    check("normalize events order-independent",
          server.normalize_webhook_events(["mention", "dm", "dm"]) == ["dm", "mention"])
    check("normalize events rejects unknown",
          server.normalize_webhook_events(["dm", "bogus"]) is None)
    check("normalize events rejects empty",
          server.normalize_webhook_events([]) is None)

    # -- strict server: e2e validation ---------------------------
    db2 = tempfile.mktemp(prefix="sb-wh-strict-", suffix=".db")
    p2 = start_server(8137, db2)
    try:
        c, A = register("wh-strict-a")
        check("strict register -> 201", c == 201, f"{c} {A}")
        for url, why in [("https://127.0.0.1/hook", "loopback"),
                         ("https://10.0.0.5/hook", "private"),
                         ("http://127.0.0.1/hook", "http"),
                         ("https://user@127.0.0.1/hook", "userinfo"),
                         ("https://127.0.0.1:8443/hook", "port")]:
            c, r = webhook_register(A, url, ["dm"])
            check(f"strict register {why} url -> 400", c == 400, f"{c} {r}")
        c, r = webhook_register(A, "https://127.0.0.1/hook", ["bogus"])
        check("bad events -> 400", c == 400, f"{c} {r}")
        # bad signature
        ts = now_ts()
        c, r = req("POST", "/api/v1/webhooks",
                   {"url": "https://8.8.8.8/hook", "events": ["dm"],
                    "timestamp": ts, "signature": "00" * 64}, auth(A))
        check("bad signature -> 403", c == 403, f"{c} {r}")
        # unauthenticated
        c, r = req("GET", "/api/v1/webhooks")
        check("list without auth -> 401", c == 401, f"{c} {r}")
        # suspended bot cannot register
        c, S = register("wh-strict-s")
        c, r = req("POST", f"/api/v1/admin/bots/{S['bot_id']}/suspend",
                   {"reason": "test"}, ADM)
        c, r = webhook_register(S, "https://127.0.0.1/hook", ["dm"])
        check("suspended register -> 403", c == 403, f"{c} {r}")
        # per-bot limit: 10 ok, 11th -> 409
        for i in range(10):
            c, r = webhook_register(A, f"https://8.8.8.8/wh{i}", ["dm"])
            if c != 201:
                break
        check("10 webhooks -> 201", c == 201, f"{c} {r}")
        c, r = webhook_register(A, "https://8.8.8.8/wh10", ["dm"])
        check("11th webhook -> 409", c == 409, f"{c} {r}")
    finally:
        p2.terminate()
        try:
            os.unlink(db2)
        except OSError:
            pass

    # -- main server: register + delivery -------------------------
    db = tempfile.mktemp(prefix="sb-wh-", suffix=".db")
    proc = start_server(8136, db, {"SWITCHBOARD_WEBHOOK_ALLOW_PRIVATE": "1",
                                  "SWITCHBOARD_WEBHOOK_RETRY_DELAYS": "0.2,0.2"})
    try:
        c, A = register("wh-alice")
        check("register A -> 201", c == 201, f"{c} {A}")
        c, B = register("wh-bob")
        check("register B -> 201", c == 201, f"{c} {B}")

        recv = start_receiver()
        hook_url = f"http://127.0.0.1:{recv.server_address[1]}/hook"

        c, r = webhook_register(A, hook_url, ["mention", "dm"])
        check("register webhook -> 201", c == 201 and r.get("webhook_id"), f"{c} {r}")
        wid = r["webhook_id"]
        secret = r.get("secret", "")
        check("secret returned once (64 hex)", len(secret) == 64, secret[:16])
        check("events normalized", r.get("events") == ["dm", "mention"], str(r.get("events")))

        c, r = req("GET", "/api/v1/webhooks", headers=auth(A))
        check("list -> 1 webhook", c == 200 and len(r["webhooks"]) == 1, f"{c} {r}")
        check("list hides secret", "secret" not in r["webhooks"][0], str(r["webhooks"][0]))
        check("list shows active", r["webhooks"][0]["active"] is True)

        # re-register same URL: idempotent refresh, secret rotates
        c, r2 = webhook_register(A, hook_url, ["dm"])
        check("re-register same URL -> 201", c == 201, f"{c} {r2}")
        check("same webhook id", r2.get("webhook_id") == wid, str(r2))
        check("secret rotated", r2.get("secret") != secret)
        secret = r2["secret"]
        c, r = req("GET", "/api/v1/webhooks", headers=auth(A))
        check("still 1 webhook after re-register", len(r["webhooks"]) == 1)
        check("events updated to dm-only", r["webhooks"][0]["events"] == ["dm"])

        # DM delivery
        c, r = post_dm(B, A, "hey alice, ping via webhook")
        check("DM -> 201", c == 201, f"{c} {r}")
        check("delivery arrives", wait_hits(1), "no delivery in 15s")
        with Receiver.lock:
            hit = Receiver.hits[0]
        ok, payload = verify_hit(hit, secret, "dm")
        check("DM delivery verifies (HMAC)", ok, str(payload)[:120])
        if ok:
            d = payload["data"]
            check("DM payload fields",
                  d.get("from_bot_id") == B["bot_id"]
                  and d.get("from_bot_name") == "wh-bob"
                  and d.get("body") == "hey alice, ping via webhook"
                  and d.get("message_id") == r["id"], str(d))

        # mention delivery (room) — need mention in events again
        c, r = webhook_register(A, hook_url, ["dm", "mention"])
        secret = r["secret"]
        before = len(Receiver.hits)
        c, r = post_room(B, "general", "hello @wh-alice, you are mentioned")
        check("room post with mention -> 201", c == 201, f"{c} {r}")
        check("mention delivery arrives", wait_hits(before + 1), "none in 15s")
        with Receiver.lock:
            hit = Receiver.hits[-1]
        ok, payload = verify_hit(hit, secret, "mention")
        check("mention delivery verifies (HMAC)", ok, str(payload)[:120])
        if ok:
            d = payload["data"]
            check("mention payload fields",
                  d.get("kind") == "room" and d.get("room") == "general"
                  and d.get("from_bot_id") == B["bot_id"], str(d))

        # room mention (second room)
        before = len(Receiver.hits)
        c, r = post_room(B, "dev", "shoutout to @WH-ALICE (case-insensitive)")
        check("room post with mention -> 201", c == 201, f"{c} {r}")
        check("room mention delivery arrives", wait_hits(before + 1), "none in 15s")
        with Receiver.lock:
            hit = Receiver.hits[-1]
        ok, payload = verify_hit(hit, secret, "mention")
        check("room mention verifies", ok, str(payload)[:120])
        if ok:
            check("room mention kind=room", payload["data"].get("kind") == "room")

        # no mention -> no delivery
        before = len(Receiver.hits)
        c, r = post_room(B, "general", "no mention here at all")
        check("plain room post -> 201", c == 201)
        time.sleep(2)
        with Receiver.lock:
            check("no delivery without mention", len(Receiver.hits) == before,
                  f"hits={len(Receiver.hits)}")

        # unknown @name -> no delivery, no crash
        before = len(Receiver.hits)
        c, r = post_room(B, "general", "hello @nobody-here-xyz")
        check("unknown mention -> 201", c == 201)
        time.sleep(2)
        with Receiver.lock:
            check("no delivery for unknown name", len(Receiver.hits) == before)

        # self-mention -> no delivery
        before = len(Receiver.hits)
        c, r = post_room(B, "general", "talking to myself @wh-bob")
        check("self mention post -> 201", c == 201)
        time.sleep(2)
        with Receiver.lock:
            check("no delivery on self-mention", len(Receiver.hits) == before)

        # delete: bad sig -> 403, then real delete -> 200, DM -> no delivery
        c, r = webhook_delete(A, wid, bad_sig=True)
        check("delete bad signature -> 403", c == 403, f"{c} {r}")
        c, r = webhook_delete(A, 999999)
        check("delete unknown id -> 404", c == 404, f"{c} {r}")
        c, C = register("wh-carol")
        c, r = webhook_delete(C, wid)
        check("delete another bot's webhook -> 404", c == 404, f"{c} {r}")
        c, r = webhook_delete(A, wid)
        check("delete -> 200", c == 200 and r.get("deleted") is True, f"{c} {r}")
        c, r = req("GET", "/api/v1/webhooks", headers=auth(A))
        check("list empty after delete", c == 200 and r["webhooks"] == [], f"{c} {r}")
        before = len(Receiver.hits)
        c, r = post_dm(B, A, "DM after webhook deleted")
        check("DM after delete -> 201", c == 201)
        time.sleep(2)
        with Receiver.lock:
            check("no delivery after delete", len(Receiver.hits) == before)

        # auto-disable after consecutive failures (dead port)
        c, r = webhook_register(A, "http://127.0.0.1:9/dead", ["dm"])
        dead_wid = r["webhook_id"]
        check("dead webhook registered", c == 201, f"{c} {r}")
        for i in range(10):
            post_dm(B, A, f"failure probe {i}")
        ok_wait = False
        for _ in range(100):
            c, r = req("GET", "/api/v1/webhooks", headers=auth(A))
            row = next((w for w in r["webhooks"]
                        if w["webhook_id"] == dead_wid), None)
            if row and not row["active"] and row["consecutive_failures"] >= 10:
                ok_wait = True
                break
            time.sleep(0.5)
        check("auto-disabled after 10 consecutive failures", ok_wait,
              str(row)[:160] if row else "missing")
    finally:
        proc.terminate()
        try:
            os.unlink(db)
        except OSError:
            pass

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
