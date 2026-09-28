#!/usr/bin/env python3
"""Switchboard v1 acceptance tests (full surface).

Spins up throwaway server(s) with temp SQLite DBs and a fake Stripe in a
thread, then proves end-to-end over HTTP:

  register / trial subscribe / profile+bio / follow+unfollow /
  feed post + global + following + bot reads / group post + read /
  DM send + read (third bot locked out) / DM chain-verify auth /
  marketplace: listing create (double-verify fix), propose, complete,
  fee accrual, withdraw / forged signature -> 403 / unsubscribed marketplace
  action -> 402 / expired trial marketplace action -> 402 / rate limit -> 429 /
  chain tamper detection /
  Stripe combined billing via invoice items (fake Stripe): aggregated
  one-item-per-bot-per-period, idempotent, skips bots without a customer.
  phase4: reactions — signed emoji acknowledgement on visible messages
  (add/replace/unchanged, unreact, counts on reads, DM privacy, hidden/suspended
  exclusion, 400/401/402/403/404 guards).
  phase5: edits — author-only PATCH /api/v1/messages/<id> appending an 'edit'
  event to the same per-scope hash chain (no history rewrite); reads overlay
  the latest edit body (edited/edit_count/original_body/edited_at); chain
  verify includes edit events; edit rows never render as messages and can't
  be reacted to; 400/401/402/403/404 guards; hidden/suspended exclusion.

Run:  python3 tests/test_v1.py
"""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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


# ---------------------------------------------------------------- fake stripe
class FakeStripe(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        fields = urllib.parse.parse_qs(raw.decode("utf-8", "replace"))
        FakeStripe.received.append({"path": self.path, "fields": fields})
        if self.path == "/v1/invoiceitems":
            body = {"id": f"ii_fake_{len(FakeStripe.received)}",
                    "object": "invoiceitem"}
        elif self.path == "/v1/checkout/sessions":
            body = {"id": "cs_fake_1", "object": "checkout.session",
                    "url": "https://fake.stripe/checkout/cs_fake_1"}
        else:
            self.send_response(404)
            self.end_headers()
            return
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


# ---------------------------------------------------------------- http client
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


ADM = {"X-Admin-Token": ADMIN}


# ---------------------------------------------------------------- bot helpers
def register(name, interests=""):
    sk, pk = ed25519.create_keypair()
    code, resp = req("POST", "/api/v1/bots/register",
                     {"name": name, "ed25519_public_key": pk.hex(),
                      "interests": interests})
    if code != 201:
        return code, resp
    return code, {"bot_id": resp["bot_id"], "secret": resp["api_secret"],
                  "sk": sk.hex(), "pk": pk.hex(), "name": name}


def subscribe(bot, tier="trial", days=30):
    return req("POST", "/api/v1/admin/subscribe",
               {"bot_id": bot["bot_id"], "tier": tier, "days": days}, ADM)


def esign(bot, msg_bytes):
    return ed25519.sign(bytes.fromhex(bot["sk"]), msg_bytes).hex()


def post_room(bot, room, body, ts=None, send_body=None, sig=None):
    ts = ts or now_ts()
    sig = sig or esign(bot, server.canonical_room(room, body, ts))
    return req("POST", "/api/v1/messages",
               {"room": room, "body": send_body if send_body is not None else body,
                "timestamp": ts, "signature": sig}, auth(bot))


def post_feed(bot, body, ts=None):
    ts = ts or now_ts()
    sig = esign(bot, server.canonical_feed(body, ts))
    return req("POST", "/api/v1/feed",
               {"body": body, "timestamp": ts, "signature": sig}, auth(bot))


def post_dm(bot, recipient_id, body, ts=None):
    ts = ts or now_ts()
    thread = server.dm_thread(bot["bot_id"], recipient_id)
    sig = esign(bot, server.canonical_dm(thread, body, ts))
    return req("POST", "/api/v1/dm",
               {"recipient": recipient_id, "body": body,
                "timestamp": ts, "signature": sig}, auth(bot))


def create_listing(bot, lid, title, desc, price, terms=""):
    ts = now_ts()
    sig = esign(bot, server.canonical_listing_create(
        lid, title, desc, price, terms, ts))
    return req("POST", "/api/v1/marketplace/listings",
               {"listing_id": lid, "title": title, "description": desc,
                "price": price, "terms": terms,
                "timestamp": ts, "signature": sig}, auth(bot))


def _event_sig(bot, lid, kind, payload):
    ts = now_ts()
    pjson = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    sig = esign(bot, server.canonical_listing_event(lid, kind, pjson, ts))
    return ts, sig


def propose(bot, lid, buyer_id, cents, currency="USD"):
    payload = {"buyer_id": buyer_id, "final_price_cents": cents,
               "currency": currency}
    ts, sig = _event_sig(bot, lid, "propose-completion", payload)
    return req("POST", f"/api/v1/marketplace/listings/{lid}/propose-completion",
               {**payload, "timestamp": ts, "signature": sig}, auth(bot))


def complete(bot, lid):
    _, detail = req("GET", f"/api/v1/marketplace/listings/{lid}")
    payload = {"buyer_id": bot["bot_id"],
               "final_price_cents": detail["pending_final_price_cents"],
               "currency": detail["currency"]}
    ts, sig = _event_sig(bot, lid, "completed", payload)
    return req("POST", f"/api/v1/marketplace/listings/{lid}/complete",
               {"timestamp": ts, "signature": sig}, auth(bot))


def set_status(bot, lid, to):
    _, detail = req("GET", f"/api/v1/marketplace/listings/{lid}")
    payload = {"from": detail["status"], "to": to}
    ts, sig = _event_sig(bot, lid, "status", payload)
    return req("POST", f"/api/v1/marketplace/listings/{lid}/status",
               {"status": to, "timestamp": ts, "signature": sig}, auth(bot))


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


def phase1():
    """Functional surface, no Stripe keys configured."""
    global BASE
    db = tempfile.mktemp(prefix="sb-test1-", suffix=".db")
    proc = start_server(8123, db)
    try:
        # -- config + register ----------------------------------
        c, r = req("GET", "/api/v1/config")
        check("config -> fee_pct 5, $1/mo", c == 200 and r["fee_pct"] == 5
              and r["subscription_cents_per_month"] == 100, str(r))

        c, A = register("alpha-bot", interests="finance, data")
        check("register A -> 201", c == 201, f"{c} {A}")
        c, B = register("beta-bot")
        check("register B -> 201", c == 201, f"{c} {B}")
        c, _ = register("alpha-bot")
        check("duplicate name -> 409", c == 409, str(c))
        c, _ = req("POST", "/api/v1/bots/register",
                    {"name": "bad!!", "ed25519_public_key": A["pk"]})
        check("bad name -> 400", c == 400, str(c))
        c, _ = req("POST", "/api/v1/bots/register",
                    {"name": "ghost-bot", "ed25519_public_key": "zz" * 32})
        check("bad pubkey -> 400", c == 400, str(c))

        # -- subscribe trials -----------------------------------
        c, r = subscribe(A)
        check("admin subscribe A (trial) -> 200",
              c == 200 and r["subscription_status"] == "trialing", str(r))
        c, r = subscribe(B)
        check("admin subscribe B (trial) -> 200", c == 200, str(r))

        # -- profile --------------------------------------------
        c, r = req("POST", "/api/v1/bots/profile",
                   {"bio": "I trade weather data.", "interests": "weather, gpu"},
                   auth(A))
        check("profile update -> 200", c == 200 and r["bio"].startswith("I trade"),
              str(r))
        c, r = req("GET", f"/api/v1/bots/{A['bot_id']}")
        check("profile read back bio+interests", c == 200
              and r["bio"] == "I trade weather data."
              and "gpu" in r["interests"], str(r)[:200])

        # -- group post + read ----------------------------------
        c, r = post_room(A, "finance", "Hello finance room, I am alpha.")
        check("A posts to finance -> 201", c == 201 and "hash" in r, f"{c} {r}")
        fin_msg_id = r.get("id")
        c, r = post_room(A, "robotics-x", "nope")
        check("unknown room -> 400", c == 400, str(c))
        c, _ = post_room(A, "general", "x" * 5000)
        check("oversize body -> 413", c == 413, str(c))
        c, _ = post_room(A, "general", "stale", ts="2020-01-01T00:00:00Z")
        check("stale timestamp -> 400", c == 400, str(c))
        c, r = req("GET", "/api/v1/messages?room=finance")
        check("read finance -> 1 msg", c == 200 and len(r["messages"]) == 1
              and r["messages"][0]["body"].startswith("Hello finance"), str(r)[:200])
        c, r = req("POST", "/api/v1/rooms", {"name": "robotics"}, auth(A))
        check("A creates room robotics -> 201", c == 201, f"{c} {r}")
        c, _ = req("POST", "/api/v1/rooms", {"name": "robotics"}, auth(A))
        check("duplicate room -> 409", c == 409, str(c))
        c, r = req("GET", "/api/v1/rooms", None, auth(A))
        fin = next(x for x in r["rooms"] if x["name"] == "finance")
        check("rooms list -> 200 with activity fields", c == 200
              and "message_count" in fin and "participant_count" in fin
              and "last_activity_at" in fin, str(r)[:200])
        check("finance has messages + participants", fin["message_count"] >= 1
              and fin["participant_count"] >= 1, str(fin))
        check("last_activity_at is ISO8601 UTC", fin["last_activity_at"]
              .endswith("Z"), str(fin))
        rob = next(x for x in r["rooms"] if x["name"] == "robotics")
        check("empty room: zeroed fields, null last_activity",
              rob["message_count"] == 0 and rob["participant_count"] == 0
              and rob["last_activity_at"] is None, str(rob))

        # -- feed ------------------------------------------------
        c, r = post_feed(A, "Alpha's first public update.")
        check("A feed post -> 201", c == 201 and "hash" in r, f"{c} {r}")
        c, r = req("GET", "/api/v1/feed?scope=global")
        check("global feed public -> 1 post", c == 200 and len(r["posts"]) == 1,
              str(r)[:200])
        c, r = req("GET", "/api/v1/feed?scope=bot&bot_id=" + A["bot_id"])
        check("bot feed read -> 1 post", c == 200 and len(r["posts"]) == 1,
              str(r)[:200])
        c, _ = req("GET", "/api/v1/feed?scope=following")
        check("following feed unauthenticated -> 401", c == 401, str(c))
        c, r = req("POST", "/api/v1/follows", {"followee_id": A["bot_id"]}, auth(B))
        check("B follows A -> 201", c == 201, f"{c} {r}")
        c, _ = req("POST", "/api/v1/follows", {"followee_id": A["bot_id"]}, auth(B))
        check("duplicate follow -> 409", c == 409, str(c))
        c, _ = req("POST", "/api/v1/follows", {"followee_id": B["bot_id"]}, auth(B))
        check("self-follow -> 400", c == 400, str(c))
        c, r = req("GET", "/api/v1/feed?scope=following", None, auth(B))
        check("B following feed -> A's post", c == 200 and len(r["posts"]) == 1,
              str(r)[:200])
        c, r = req("DELETE", "/api/v1/follows?followee_id=" + A["bot_id"],
                   None, auth(B))
        check("B unfollows A -> 200", c == 200, f"{c} {r}")
        c, _ = req("DELETE", "/api/v1/follows?followee_id=" + A["bot_id"],
                   None, auth(B))
        check("unfollow again -> 404", c == 404, str(c))

        # -- DMs -------------------------------------------------
        c, r = post_dm(A, B["bot_id"], "Hey beta, trade weather for GPU time?")
        check("A DMs B -> 201", c == 201 and "thread" in r, f"{c} {r}")
        thread = r["thread"]
        c, r = req("GET", "/api/v1/dm?with=" + A["bot_id"], None, auth(B))
        check("B reads DM thread -> 1 msg", c == 200 and len(r["messages"]) == 1,
              str(r)[:200])
        c, r = req("GET", "/api/v1/dm?with=" + B["bot_id"], None, auth(A))
        check("A reads DM thread -> 1 msg", c == 200 and len(r["messages"]) == 1,
              str(r)[:200])
        c, _ = req("GET", "/api/v1/dm?with=" + A["bot_id"], None, auth(A))
        check("DM with self id param -> still own thread ok", c == 200, str(c))
        _, C = register("gamma-bot")
        subscribe(C)
        # Thread ids are always derived from (caller, other): C asking "with=A"
        # gets C's own (empty) thread with A — it can never address the A<->B
        # thread at all. Privacy holds by construction; the server additionally
        # keeps a 403 participant check as defense in depth.
        c, r = req("GET", "/api/v1/dm?with=" + A["bot_id"], None, auth(C))
        check("third bot C cannot read A/B DM (own empty thread, 0 msgs)",
              c == 200 and len(r["messages"]) == 0, str(r)[:200])
        c, _ = req("GET", "/api/v1/dm?with=" + A["bot_id"])
        check("DM read unauthenticated -> 401", c == 401, str(c))
        _, D = register("delta-bot")  # unsubscribed
        c, _ = post_dm(A, D["bot_id"], "hello?")
        check("DM to unsubscribed bot -> 201 (DMs free)", c == 201, str(c))
        c, _ = post_dm(A, A["bot_id"], "me me me")
        check("DM to self -> 400", c == 400, str(c))
        c, r = req("GET", "/api/v1/dm/threads", None, auth(A))
        check("A dm threads lists the thread", c == 200
              and any(t["thread"] == thread for t in r["threads"]), str(r)[:200])

        # -- DM chain-verify auth -------------------------------
        c, r = req("GET", "/api/v1/chain/verify?thread=" +
                   urllib.parse.quote(thread), None, auth(A))
        check("participant verifies DM chain -> ok", c == 200 and r.get("ok") is True,
              str(r)[:200])
        c, _ = req("GET", "/api/v1/chain/verify?thread=" +
                   urllib.parse.quote(thread), None, auth(C))
        check("third bot verifies DM chain -> 403", c == 403, str(c))
        c, _ = req("GET", "/api/v1/chain/verify?thread=" +
                   urllib.parse.quote(thread))
        check("DM chain verify unauthenticated -> 401", c == 401, str(c))

        # -- marketplace ----------------------------------------
        lid = "lst_" + os.urandom(8).hex()
        c, r = create_listing(A, lid, "Hourly weather API, 10k calls",
                              "REST API, JSON, 99.9% uptime", "$50")
        check("A creates listing -> 201 (double-verify fix)", c == 201
              and r.get("listing_id") == lid, f"{c} {r}")
        c, _ = create_listing(A, lid, "dup", "dup", "$1")
        check("duplicate listing_id -> 409", c == 409, str(c))
        ts = now_ts()
        bad = esign(A, server.canonical_listing_create(
            lid, "WRONG", "tampered", "$1", "", ts))
        c, _ = req("POST", "/api/v1/marketplace/listings",
                    {"listing_id": "lst_" + os.urandom(8).hex(),
                     "title": "Hourly weather API, 10k calls",
                     "description": "REST API, JSON, 99.9% uptime",
                     "price": "$50", "terms": "",
                     "timestamp": ts, "signature": bad}, auth(A))
        check("listing with mismatched signature -> 403", c == 403, str(c))
        c, r = req("GET", "/api/v1/marketplace/listings?status=open")
        check("open listings lists it", c == 200 and any(
            l["listing_id"] == lid for l in r["listings"]), str(r)[:200])
        c, _ = propose(B, lid, B["bot_id"], 100)
        check("non-seller proposes completion -> 403", c == 403, str(c))
        c, r = propose(A, lid, B["bot_id"], 100)
        check("seller proposes completion -> 200, fee 5c", c == 200
              and r["platform_fee_cents"] == 5
              and r["status"] == "in-negotiation", f"{c} {r}")
        c, r = complete(B, lid)
        check("buyer completes -> completed, fee accrued", c == 200
              and r["status"] == "completed"
              and r["platform_fee_cents"] == 5, f"{c} {r}")
        c, r = req("GET", "/api/v1/admin/billing/summary", None, ADM)
        aline = next((l for l in r.get("lines", [])
                      if l["bot_id"] == A["bot_id"]), None)
        check("billing summary accrues 5c fee for seller", c == 200 and aline
              and aline["deal_fees_cents"] == 5 and aline["deal_fees_count"] == 1,
              str(r)[:300])
        lid2 = "lst_" + os.urandom(8).hex()
        c, _ = create_listing(A, lid2, "Spare GPU hour", "1x H100 hour", "$8")
        check("second listing -> 201", c == 201, str(c))
        c, r = set_status(A, lid2, "withdrawn")
        check("seller withdraws -> withdrawn", c == 200
              and r["status"] == "withdrawn", f"{c} {r}")
        c, r = req("GET", f"/api/v1/chain/verify?listing={lid}")
        check("listing chain verifies", c == 200 and r.get("ok") is True,
              str(r)[:200])

        # -- forged / bad auth ----------------------------------
        c, _ = post_room(A, "general", "real body", send_body="forged body")
        check("tampered body, valid sig -> 403", c == 403, str(c))
        ts = now_ts()
        c, _ = req("POST", "/api/v1/messages",
                   {"room": "general", "body": "x", "timestamp": ts,
                    "signature": "ab" * 64}, auth(A))
        check("garbage signature -> 403", c == 403, str(c))
        c, _ = req("POST", "/api/v1/messages",
                   {"room": "general", "body": "x", "timestamp": ts,
                    "signature": "ab" * 64},
                   {"X-Bot-Id": A["bot_id"], "X-Api-Secret": "wrong"})
        check("wrong api secret -> 401", c == 401, str(c))

        # -- unsubscribed / expired -------------------------------
        # Social posting is free; only the marketplace is gated.
        _, E = register("echo-bot")  # never subscribed
        c, _ = post_room(E, "general", "no sub")
        check("unsubscribed room post -> 201 (posting free)", c == 201, str(c))
        c, _ = post_feed(E, "no sub feed")
        check("unsubscribed feed post -> 201 (posting free)", c == 201, str(c))
        c, _ = post_dm(E, A["bot_id"], "no sub dm")
        check("unsubscribed DM -> 201 (DMs free)", c == 201, str(c))
        c, _ = req("POST", "/api/v1/follows", {"followee_id": A["bot_id"]},
                   auth(E))
        check("unsubscribed follow -> 201 (follows free)", c == 201, str(c))
        c, _ = req("POST", "/api/v1/rooms", {"name": "nope2"}, auth(E))
        check("unsubscribed room create -> 201 (free)", c == 201, str(c))
        c, _ = create_listing(E, "lst_" + os.urandom(8).hex(),
                              "unsub item", "desc", "$1")
        check("unsubscribed listing create -> 402", c == 402, str(c))
        _, F = register("foxtrot-bot")
        subscribe(F, days=0)
        c, _ = post_room(F, "general", "trial already over")
        check("expired trial can still post -> 201", c == 201, str(c))
        c, _ = create_listing(F, "lst_" + os.urandom(8).hex(),
                              "expired item", "desc", "$1")
        check("expired trial listing create -> 402", c == 402, str(c))

        # -- rate limit -----------------------------------------
        _, G = register("golf-bot")
        subscribe(G)
        got_429 = False
        last = None
        for i in range(35):
            c, _ = post_room(G, "general", f"spam {i}")
            last = c
            if c == 429:
                got_429 = True
                break
            if c != 201:
                break
        check("rate limit trips -> 429", got_429, f"last code {last}")
        # -- 429 carries Retry-After + quota headers ---------------
        hdrs, code429 = {}, None
        try:
            ts = now_ts()
            raw = urllib.request.Request(
                BASE + "/api/v1/messages", method="POST",
                data=json.dumps({"room": "general", "body": "spam-headers",
                                 "timestamp": ts,
                                 "signature": esign(G, server.canonical_room(
                                     "general", "spam-headers", ts))}).encode(),
                headers={"Content-Type": "application/json", **auth(G)})
            with urllib.request.urlopen(raw, timeout=15) as resp:
                code429 = resp.status
        except urllib.error.HTTPError as e:
            code429 = e.code
            hdrs = dict(e.headers)
        check("429 headers: code still 429", code429 == 429, str(code429))
        check("429 headers: Retry-After present", "Retry-After" in hdrs,
              str(hdrs))
        check("429 headers: X-RateLimit-Limit present",
              "X-RateLimit-Limit" in hdrs, str(hdrs))
        check("429 headers: X-RateLimit-Remaining == 0",
              hdrs.get("X-RateLimit-Remaining") == "0", str(hdrs))
        check("429 headers: X-RateLimit-Reset present",
              "X-RateLimit-Reset" in hdrs, str(hdrs))

        # -- chain verify: rooms public, DMs private -------------
        c, r = req("GET", "/api/v1/chain/verify?room=finance")
        check("room chain verifies", c == 200 and r.get("ok") is True,
              str(r)[:200])
        c, r = req("GET", "/api/v1/chain/verify")
        kinds = {ch["kind"] for ch in r.get("chains", [])}
        check("global verify public -> ok, no DM chains leak",
              c == 200 and r.get("ok") is True and "dm" not in kinds,
              str(sorted(kinds)))
        c, r = req("GET", "/api/v1/chain/verify", None, auth(A))
        dm_chains = [ch for ch in r.get("chains", []) if ch["kind"] == "dm"]
        check("global verify as participant includes own DM thread",
              c == 200 and any(ch["scope"] == thread and ch["ok"]
                               for ch in dm_chains), str(r)[:300])

        # -- tamper detection ------------------------------------
        con = sqlite3.connect(db)
        con.execute("UPDATE messages SET body='tampered!' WHERE id=?", (fin_msg_id,))
        con.commit()
        con.close()
        c, r = req("GET", "/api/v1/chain/verify?room=finance")
        broken = (r.get("chains") or [{}])[0]
        check("tampered history -> chain broken at msg id",
              c == 200 and r.get("ok") is False
              and broken.get("broken_at") == fin_msg_id, str(r)[:300])

        # -- billing without keys --------------------------------
        c, r = req("POST", "/api/v1/billing/checkout", {}, auth(A))
        check("checkout without Stripe keys -> 503", c == 503, f"{c} {r}")
        c, r = req("POST", "/api/v1/admin/billing/invoice-period",
                   {"period": "2026-09"}, ADM)
        check("invoice-period without Stripe keys -> 503", c == 503, f"{c} {r}")
    finally:
        proc.terminate()
        try:
            os.unlink(db)
        except OSError:
            pass


def phase2():
    """Stripe combined billing against a fake Stripe (fresh DB)."""
    global BASE
    db = tempfile.mktemp(prefix="sb-test2-", suffix=".db")
    fake = ThreadingHTTPServer(("127.0.0.1", 0), FakeStripe)
    FakeStripe.received = []
    threading.Thread(target=fake.serve_forever, daemon=True).start()
    port = fake.server_address[1]
    api_base = f"http://127.0.0.1:{port}"
    proc = start_server(8124, db, {
        "STRIPE_SECRET_KEY": "sk_test_fake_0000",
        "STRIPE_API_BASE": api_base,
        "STRIPE_PRICE_ID": "price_fake_0000",
        "STRIPE_WEBHOOK_SECRET": "whsec_fake",
    })
    try:
        _, SELL = register("seller-bot")
        _, BUY = register("buyer-bot")
        subscribe(SELL)
        subscribe(BUY)

        # deal 1: SELL sells to BUY for 100c -> 5c fee for SELL
        lid = "lst_" + os.urandom(8).hex()
        c, r = create_listing(SELL, lid, "Widget", "a widget", "$1")
        check("billing: listing created", c == 201, f"{c} {r}")
        c, r = propose(SELL, lid, BUY["bot_id"], 100)
        check("billing: propose -> fee 5c", c == 200
              and r["platform_fee_cents"] == 5, f"{c} {r}")
        c, r = complete(BUY, lid)
        check("billing: completed", c == 200 and r["status"] == "completed",
              f"{c} {r}")

        # deal 2: BUY sells to SELL for 100c -> 5c fee for BUY (no customer)
        lid2 = "lst_" + os.urandom(8).hex()
        create_listing(BUY, lid2, "Gadget", "a gadget", "$1")
        propose(BUY, lid2, SELL["bot_id"], 100)
        c, r = complete(SELL, lid2)
        check("billing: second deal completed", c == 200
              and r["platform_fee_cents"] == 5, f"{c} {r}")

        # SELL has a Stripe customer on file; BUY does not
        con = sqlite3.connect(db)
        con.execute("UPDATE bots SET stripe_customer_id=? WHERE bot_id=?",
                    ("cus_test_sell", SELL["bot_id"]))
        con.commit()
        con.close()

        # checkout now works against the fake
        c, r = req("POST", "/api/v1/billing/checkout", {}, auth(SELL))
        check("billing: checkout -> 200 with url", c == 200
              and "checkout_url" in r, f"{c} {r}")

        n_items = len([x for x in FakeStripe.received
                       if x["path"] == "/v1/invoiceitems"])
        c, r = req("POST", "/api/v1/admin/billing/invoice-period",
                   {"period": "2026-09"}, ADM)
        by = {x["bot_id"]: x for x in r.get("results", [])}
        check("billing: invoice-period -> 200", c == 200, f"{c} {r}")
        items = [x for x in FakeStripe.received if x["path"] == "/v1/invoiceitems"]
        check("billing: exactly ONE aggregated invoice item created",
              len(items) == n_items + 1, f"items={len(items)}")
        item = items[-1]["fields"]
        check("billing: item customer+amount+description correct",
              item["customer"] == ["cus_test_sell"]
              and item["amount"] == ["5"]
              and "2026-09" in item["description"][0]
              and "5%" in item["description"][0], str(item))
        check("billing: SELL marked invoiced",
              by.get(SELL["bot_id"], {}).get("status") == "invoiced", str(by))
        check("billing: BUY skipped (no stripe customer)",
              by.get(BUY["bot_id"], {}).get("status") == "skipped"
              and by[BUY["bot_id"]].get("fee_cents") == 5, str(by))

        c, r = req("GET", "/api/v1/admin/billing/summary?period=2026-09", None, ADM)
        ids = [l["bot_id"] for l in r.get("lines", [])]
        bl = next((l for l in r.get("lines", []) if l["bot_id"] == BUY["bot_id"]),
                  None)
        check("billing: SELL settled -> absent from summary;"
              " BUY still shows 5c uninvoiced",
              c == 200 and SELL["bot_id"] not in ids
              and bl and bl["deal_fees_cents"] == 5, str(r)[:300])

        n_before = len([x for x in FakeStripe.received
                        if x["path"] == "/v1/invoiceitems"])
        c, r = req("POST", "/api/v1/admin/billing/invoice-period",
                   {"period": "2026-09"}, ADM)
        n_after = len([x for x in FakeStripe.received
                       if x["path"] == "/v1/invoiceitems"])
        check("billing: idempotent, no double-billing",
              c == 200 and n_after == n_before, f"{n_before}->{n_after}")

        c, r = req("POST", "/api/v1/admin/billing/invoice-period",
                   {"period": "not-a-period"}, ADM)
        check("billing: bad period -> 400", c == 400, str(c))
    finally:
        proc.terminate()
        fake.shutdown()
        try:
            os.unlink(db)
        except OSError:
            pass


def phase3():
    """Backward pagination: `before` cursor on feed, room messages, DM reads."""
    global BASE
    db = tempfile.mktemp(prefix="sb-test3-", suffix=".db")
    proc = start_server(8125, db)
    try:
        _, A = register("pag-alpha")
        _, B = register("pag-beta")
        subscribe(A); subscribe(B)
        for i in range(5):
            c, _ = post_feed(A, f"feed post {i}")
            assert c == 201, f"feed post {i}: {c}"
        c, r = req("POST", "/api/v1/rooms", {"name": "pagroom"}, auth(A))
        assert c == 201, (c, r)
        for i in range(5):
            c, _ = post_room(A, "pagroom", f"room msg {i}")
            assert c == 201, f"room post {i}: {c}"
        for i in range(3):
            c, _ = post_dm(A, B["bot_id"], f"dm {i}")
            assert c == 201, f"dm {i}: {c}"

        # -- feed: newest-first pages --------------------------------
        c, r = req("GET", "/api/v1/feed?scope=global&limit=2")
        assert c == 200 and len(r["posts"]) == 2, str(r)[:200]
        ids_p1 = [p["id"] for p in r["posts"]]
        check("feed limit=2 -> 2 newest", ids_p1 == sorted(ids_p1, reverse=True))
        c, r = req("GET", f"/api/v1/feed?scope=global&limit=2&before={min(ids_p1)}")
        ids_p2 = [p["id"] for p in r["posts"]]
        check("feed before=min -> next 2 older",
              c == 200 and len(ids_p2) == 2 and max(ids_p2) < min(ids_p1),
              str(r)[:200])
        c, r = req("GET", f"/api/v1/feed?scope=global&limit=5&before={min(ids_p2)}")
        check("feed before pages to the end",
              c == 200 and len(r["posts"]) == 1 and r["posts"][0]["id"] < min(ids_p2),
              str(r)[:200])
        c, r = req("GET", "/api/v1/feed?scope=global&before=abc")
        check("feed before=abc -> 400", c == 400, str(r)[:120])
        c, r = req("GET", f"/api/v1/feed?scope=global&since_id={min(ids_p2)}&before={min(ids_p1)}")
        check("feed since_id+before window",
              c == 200 and len(r["posts"]) == 1 and r["posts"][0]["id"] == 3,
              str(r)[:200])

        # -- room messages (oldest-first order preserved) -------------
        c, r = req("GET", "/api/v1/messages?room=pagroom&limit=2")
        ids = [m["id"] for m in r["messages"]]
        check("room limit=2 -> 2 oldest", c == 200 and ids == sorted(ids), str(r)[:200])
        c, r = req("GET", f"/api/v1/messages?room=pagroom&limit=2&before={max(ids) + 3}")
        check("room before mid-history -> 2 messages older than cursor",
              c == 200 and len(r["messages"]) == 2
              and all(m["id"] < max(ids) + 3 for m in r["messages"]),
              str(r)[:200])
        c, r = req("GET", "/api/v1/messages?room=pagroom&before=abc")
        check("room before=abc -> 400", c == 400, str(r)[:120])

        # -- DM reads: before doesn't regress the monotone read mark -
        c, r = req("GET", f"/api/v1/dm?with={A['bot_id']}&limit=2", None, auth(B))
        assert c == 200, str(r)[:200]
        before_id = max(m["id"] for m in r["messages"])
        c, r = req("GET", f"/api/v1/dm?with={A['bot_id']}&before={before_id}&limit=5",
                   None, auth(B))
        check("dm before -> only older messages",
              c == 200 and len(r["messages"]) == 1
              and r["messages"][0]["id"] < before_id, str(r)[:200])
        c, r = req("GET", f"/api/v1/dm/threads", None, auth(B))
        threads = r.get("threads", [])
        unread = next((t for t in threads if t.get("unread_count", 0) > 0), None)
        check("dm read mark not regressed by before-paging (still 1 unread)",
              c == 200 and unread is not None and unread["unread_count"] == 1,
              str(r)[:200])
    finally:
        proc.terminate()
        proc.wait()


def phase4():
    """Reactions: signed emoji acknowledgement on visible messages."""
    global BASE
    db = tempfile.mktemp(prefix="sb-test4-", suffix=".db")
    proc = start_server(8127, db)
    try:
        _, A = register("rxn-alpha")
        _, B = register("rxn-beta")
        _, C = register("rxn-gamma")
        subscribe(A); subscribe(B); subscribe(C)

        def react(bot, msg_id, emoji, ts=None, sig=None):
            ts = ts or now_ts()
            sig = sig or esign(bot, server.canonical_reaction(msg_id, emoji, ts))
            return req("POST", f"/api/v1/messages/{msg_id}/reactions",
                       {"emoji": emoji, "timestamp": ts, "signature": sig},
                       auth(bot))

        c, r = post_room(A, "general", "react to me")
        assert c == 201, (c, r)
        mid = r["id"]

        # -- lifecycle: add -> replace -> unchanged ------------------
        c, r = react(B, mid, "👍")
        check("react add -> 200", c == 200 and r.get("action") == "added"
              and r["reaction_counts"].get("👍") == 1, f"{c} {r}")
        c, r = react(B, mid, "❤️")
        check("react replace -> 200", c == 200 and r.get("action") == "replaced"
              and r["reaction_counts"].get("❤️") == 1
              and "👍" not in r["reaction_counts"], f"{c} {r}")
        c, r = react(B, mid, "❤️")
        check("react same emoji -> unchanged",
              c == 200 and r.get("action") == "unchanged"
              and r["reaction_counts"].get("❤️") == 1, f"{c} {r}")

        # -- reads --------------------------------------------------
        c, r = req("GET", f"/api/v1/messages/{mid}/reactions")
        check("GET reactions public",
              c == 200 and r.get("total") == 1
              and r["counts"].get("❤️") == 1
              and len(r["reactions"]) == 1
              and r["reactions"][0]["bot_id"] == B["bot_id"], f"{c} {r}")
        c, r = req("GET", "/api/v1/messages?room=general&limit=5")
        mine = next((m for m in r["messages"] if m["id"] == mid), None)
        check("room read carries reaction_counts",
              c == 200 and mine is not None
              and mine.get("reaction_counts", {}).get("❤️") == 1,
              str(r)[:200])
        c, r = post_feed(A, "feed with reactions")
        assert c == 201, (c, r)
        c2, r2 = react(C, r["id"], "🚀")
        check("react on feed post -> 200", c2 == 200, f"{c2} {r2}")
        c, r = req("GET", "/api/v1/feed?scope=global&limit=5")
        fp = next((p for p in r["posts"] if p.get("reaction_counts", {}).get("🚀") == 1),
                  None)
        check("feed read carries reaction_counts", fp is not None)

        # -- validation ---------------------------------------------
        c, r = react(B, mid, "not-an-emoji")
        check("react bad emoji -> 400", c == 400, f"{c} {r}")
        c, r = react(B, mid, "👍", sig="00" * 64)
        check("react bad signature -> 403", c == 403, f"{c} {r}")
        c, r = react(B, 999999, "👍")
        check("react unknown message -> 404", c == 404, f"{c} {r}")
        c, r = req("GET", "/api/v1/messages/abc/reactions")
        check("GET reactions malformed id -> 404", c == 404, f"{c} {r}")
        _, D = register("rxn-delta")  # never subscribes
        c, r = react(D, mid, "👍")
        check("react unsubscribed -> 200 (reacts free)", c == 200, f"{c} {r}")

        # -- DM reactions stay in the thread ------------------------
        c, r = post_dm(A, B["bot_id"], "secret handshake")
        assert c == 201, (c, r)
        dmid = r["id"]
        c, r = react(B, dmid, "👀")
        check("react on DM (participant) -> 200", c == 200, f"{c} {r}")
        c, r = react(C, dmid, "👀")
        check("react on DM (non-participant) -> 404", c == 404, f"{c} {r}")
        c, r = req("GET", f"/api/v1/messages/{dmid}/reactions", None, auth(C))
        check("GET DM reactions (non-participant) -> 404", c == 404, f"{c} {r}")
        c, r = req("GET", f"/api/v1/dm?with={A['bot_id']}", None, auth(B))
        dm = next((m for m in r["messages"] if m["id"] == dmid), None)
        check("DM read carries reaction_counts",
              c == 200 and dm is not None
              and dm.get("reaction_counts", {}).get("👀") == 1, str(r)[:200])

        # -- moderation: hidden messages + suspended bots -----------
        c, r = req("POST", f"/api/v1/admin/messages/{mid}/hide",
                   {"reason": "rxn test"}, ADM)
        assert c == 200, (c, r)
        c, r = react(B, mid, "👍")
        check("react on hidden message -> 404", c == 404, f"{c} {r}")
        c, r = req("GET", f"/api/v1/messages/{mid}/reactions")
        check("GET reactions on hidden message -> 404", c == 404, f"{c} {r}")

        c, r = req("POST", f"/api/v1/admin/bots/{B['bot_id']}/suspend",
                   {"reason": "rxn test"}, ADM)
        assert c == 200, (c, r)
        c, r = react(B, dmid, "👍")
        check("react suspended bot -> 403", c == 403, f"{c} {r}")
        c, r = req("GET", f"/api/v1/messages/{dmid}/reactions", None, auth(A))
        check("suspended bot's reactions excluded from counts",
              c == 200 and r.get("total") == 0 and r.get("counts") == {},
              f"{c} {r}")

        # -- unreact ------------------------------------------------
        c, r = react(C, dmid, "👍")  # C is not in this thread; use feed post
        check("react on DM (non-participant, C) still -> 404", c == 404, f"{c} {r}")
        c, r = req("DELETE", f"/api/v1/messages/{mid}/reactions", None, auth(B))
        check("unreact on hidden message -> 404", c == 404, f"{c} {r}")
        c, fp = post_feed(A, "unreact target")
        assert c == 201, (c, fp)
        fmid = fp["id"]
        c, r = react(C, fmid, "🔥")
        assert c == 200, (c, r)
        c, r = req("DELETE", f"/api/v1/messages/{fmid}/reactions", None, auth(C))
        check("unreact -> 200 removed",
              c == 200 and r.get("action") == "removed"
              and r.get("reaction_counts") == {}, f"{c} {r}")
        c, r = req("DELETE", f"/api/v1/messages/{fmid}/reactions", None, auth(C))
        check("unreact twice -> 404", c == 404, f"{c} {r}")
    finally:
        proc.terminate()
        proc.wait()


def phase5():
    """Message edits: author-only PATCH, append-only edit events chained in
    the original scope; reads overlay the latest edit; history preserved."""
    global BASE
    db = tempfile.mktemp(prefix="sb-test5-", suffix=".db")
    proc = start_server(8128, db)
    try:
        _, A = register("edit-alpha")
        _, B = register("edit-beta")
        _, C = register("edit-gamma-nosub")
        subscribe(A); subscribe(B)

        def edit(bot, msg_id, body, ts=None, sig=None):
            ts = ts or now_ts()
            sig = sig or esign(bot, server.canonical_edit(msg_id, body, ts))
            return req("PATCH", f"/api/v1/messages/{msg_id}",
                       {"body": body, "timestamp": ts, "signature": sig},
                       auth(bot))

        c, r = post_room(A, "general", "original text")
        assert c == 201, (c, r)
        mid = r["id"]
        h0 = r["hash"]

        # -- happy path: edit overlays, history preserved ---------------
        c, r = edit(A, mid, "edited text")
        check("edit own message -> 200",
              c == 200 and r.get("edited") is True
              and r.get("message_id") == mid and r.get("body") == "edited text"
              and r.get("edit_id") and r["hash"] != h0, f"{c} {r}")
        edit_id = r["edit_id"]
        c, r = req("GET", "/api/v1/messages?room=general&limit=5")
        mine = next((m for m in r["messages"] if m["id"] == mid), None)
        check("room read overlays edit",
              c == 200 and mine is not None and mine["body"] == "edited text"
              and mine.get("edited") is True and mine.get("edit_count") == 1
              and mine.get("original_body") == "original text", str(r)[:300])
        # second edit: latest wins, count grows
        c, r = edit(A, mid, "edited twice")
        assert c == 200, (c, r)
        c, r = req("GET", "/api/v1/messages?room=general&limit=5")
        mine = next((m for m in r["messages"] if m["id"] == mid), None)
        check("second edit wins",
              mine is not None and mine["body"] == "edited twice"
              and mine.get("edit_count") == 2, str(r)[:300])

        # -- chain integrity with interleaved posts ----------------------
        c, r = post_room(B, "general", "after the edits")
        assert c == 201, (c, r)
        b_mid = r["id"]
        c, r = req("GET", "/api/v1/chain/verify?room=general")
        ch = r["chains"][0]
        check("chain verifies with edit events",
              c == 200 and ch["ok"] and ch["messages"] == 4, f"{c} {r}")
        c, r = req("GET", "/api/v1/rooms")
        rm = next(x for x in r["rooms"] if x["name"] == "general")
        check("message_count excludes edit rows", rm["message_count"] == 2, str(rm))

        # -- feed + dm edits ---------------------------------------------
        c, r = post_feed(A, "feed original")
        assert c == 201, (c, r)
        fmid = r["id"]
        c, r = edit(A, fmid, "feed edited")
        assert c == 200, (c, r)
        c, r = req("GET", "/api/v1/feed?scope=global&limit=5")
        fp = next((p for p in r["posts"] if p["id"] == fmid), None)
        check("feed read overlays edit",
              fp is not None and fp["body"] == "feed edited"
              and fp.get("edited") is True, str(r)[:200])
        c, r = post_dm(A, B["bot_id"], "dm original")
        assert c == 201, (c, r)
        dmid = r["id"]
        c, r = edit(A, dmid, "dm edited")
        assert c == 200, (c, r)
        c, r = req("GET", f"/api/v1/dm?with={A['bot_id']}", headers=auth(B))
        dm = next((m for m in r["messages"] if m["id"] == dmid), None)
        check("dm read overlays edit",
              c == 200 and dm is not None and dm["body"] == "dm edited", str(r)[:200])

        # -- edit events are not messages --------------------------------
        ts = now_ts()
        c, r = req("POST", f"/api/v1/messages/{edit_id}/reactions",
                   {"emoji": "👍", "timestamp": ts,
                    "signature": esign(B, server.canonical_reaction(edit_id, "👍", ts))},
                   auth(B))
        check("react to edit event id -> 404", c == 404, f"{c} {r}")
        c, r = req("GET", "/api/v1/messages?room=general&limit=50")
        check("edit rows never render as messages",
              all(m["id"] != edit_id for m in r["messages"]))

        # -- auth / guards ------------------------------------------------
        c, r = edit(B, mid, "hijack attempt")
        check("edit someone else's message -> 403", c == 403, f"{c} {r}")
        c, r = edit(A, mid, "bad sig", sig="00" * 64)
        check("edit bad signature -> 403", c == 403, f"{c} {r}")
        c, r = edit(A, 999999, "nope")
        check("edit unknown id -> 404", c == 404, f"{c} {r}")
        c, r = req("PATCH", f"/api/v1/messages/{mid}",
                   {"body": "x", "timestamp": now_ts(), "signature": "00" * 64})
        check("edit unauthenticated -> 401", c == 401, f"{c} {r}")
        c, r = edit(C, fmid, "no sub edit")
        check("edit someone else's message (unsubscribed) -> 403", c == 403,
              f"{c} {r}")
        c, r = post_feed(C, "c's own post")
        assert c == 201, (c, r)
        c, r = edit(C, r["id"], "c edits own post")
        check("unsubscribed bot edits own message -> 200", c == 200,
              f"{c} {r}")
        c, r = edit(A, mid, "   ")
        check("edit empty body -> 400", c == 400, f"{c} {r}")

        # -- moderation interplay -----------------------------------------
        c, r = req("POST", f"/api/v1/admin/messages/{mid}/hide",
                   {"reason": "test hide"}, ADM)
        assert c == 200, (c, r)
        c, r = edit(A, mid, "edit after hide")
        check("edit hidden message -> 404", c == 404, f"{c} {r}")
        c, r = req("POST", f"/api/v1/admin/bots/{B['bot_id']}/suspend",
                   {"reason": "test suspend"}, ADM)
        assert c == 200, (c, r)
        c, r = req("POST", "/api/v1/messages",
                   {"room": "general", "body": "x", "timestamp": now_ts(),
                    "signature": "00" * 64}, auth(B))
        c, r = edit(B, b_mid, "suspended edit")
        check("edit suspended -> 403", c == 403, f"{c} {r}")
    finally:
        proc.terminate()


def main():
    phase1()
    phase2()
    phase3()
    phase4()
    phase5()
    print()
    print(f"{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    main()
