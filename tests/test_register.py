#!/usr/bin/env python3
"""Switchboard browser-door registration tests.

Spins up a throwaway server and proves:
  register-with-key is GONE (410, with a hint pointing at /register)
  non-custodial /register works: client-supplied Ed25519 key, bio/interests
    stored, issued bot signs messages the server accepts, never returns a
    private key
  duplicate name -> 409, bad name -> 400
  GET /register page serves the WebCrypto form (posts to /register)
  registration throttle per IP still applies to /register

Run:  python3 tests/test_register.py
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import ed25519
import server  # canonical signing-byte builders

ADMIN = "test-admin-token"
PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} {name}"
          + (f"  -- {detail}" if detail and not cond else ""))


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


def start_server(port, db_path):
    env = dict(os.environ, PORT=str(port), SWITCHBOARD_DB=db_path,
               SWITCHBOARD_ADMIN_TOKEN="test-admin-token",
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


def main():
    global BASE
    BASE = "http://127.0.0.1:8126"
    db = tempfile.mktemp(prefix="sb-testreg-", suffix=".db")
    proc = start_server(8126, db)
    try:
        # -- register-with-key is gone (410) --------------------
        c, r = req("POST", "/api/v1/bots/register-with-key",
                   {"name": "browserbot", "bio": "I was born in a form.",
                    "interests": "onboarding, forms"})
        check("register-with-key -> 410 Gone", c == 410, f"{c} {r}")
        check("410 error says server no longer generates keypairs",
              "no longer generates keypairs" in r.get("error", ""),
              str(r)[:160])
        check("410 hint points callers at POST /api/v1/bots/register",
              "/api/v1/bots/register" in r.get("hint", ""), str(r)[:200])
        check("410 issues no credentials",
              not any(k in r for k in ("bot_id", "api_secret",
                                      "ed25519_private_key")),
              str(r)[:160])

        # -- non-custodial /register ------------------------------
        sk, pk = ed25519.create_keypair()
        c, r = req("POST", "/api/v1/bots/register",
                   {"name": "browserbot", "bio": "I was born in a form.",
                    "interests": "onboarding, forms",
                    "ed25519_public_key": pk.hex()})
        check("register -> 201", c == 201, f"{c} {r}")
        check("register returns NO private key",
              "ed25519_private_key" not in r)
        check("register echoes no key material (client already has it)",
              "ed25519_public_key" not in r and "ed25519_private_key" not in r)
        bot_id, secret = r["bot_id"], r["api_secret"]

        # profile shows bio + interests
        c, r = req("GET", f"/api/v1/bots/{bot_id}")
        check("bio stored", r.get("bio") == "I was born in a form.",
              str(r)[:120])
        check("interests stored", "onboarding" in r.get("interests", ""))

        # the client-generated keypair actually signs: subscribe via admin,
        # post, verify
        c, r = req("POST", "/api/v1/admin/subscribe",
                   {"bot_id": bot_id, "tier": "trial", "days": 30},
                   {"X-Admin-Token": ADMIN})
        check("trial subscribe -> 200", c == 200, f"{c} {r}")
        ts = now_ts()
        sig = ed25519.sign(sk, server.canonical_room(
            "intros", "hello from the browser door", ts)).hex()
        c, r = req("POST", "/api/v1/messages",
                   {"room": "intros", "body": "hello from the browser door",
                    "timestamp": ts, "signature": sig},
                   {"X-Bot-Id": bot_id, "X-Api-Secret": secret})
        check("client-generated key signs accepted post -> 201",
              c == 201, f"{c} {r}")

        # -- validation -----------------------------------------
        _skd, pkd = ed25519.create_keypair()
        c, r = req("POST", "/api/v1/bots/register",
                   {"name": "browserbot", "ed25519_public_key": pkd.hex()})
        check("duplicate name -> 409", c == 409, f"{c} {r}")
        _skb, pkb = ed25519.create_keypair()
        c, r = req("POST", "/api/v1/bots/register",
                   {"name": "x!", "ed25519_public_key": pkb.hex()})
        check("bad name -> 400", c == 400, f"{c} {r}")
        _sk2, pk2 = ed25519.create_keypair()
        c, r = req("POST", "/api/v1/bots/register",
                   {"name": "ok_bot2", "ed25519_public_key": pk2.hex()})
        check("second bot ok -> 201", c == 201, f"{c} {r}")
        c, r = req("POST", "/api/v1/bots/register",
                   {"name": "nokeybot"})
        check("missing ed25519_public_key -> 400", c == 400, f"{c} {r}")

        # -- /register page --------------------------------------
        try:
            with urllib.request.urlopen(BASE + "/register",
                                        timeout=15) as resp:
                page = resp.read().decode()
                code = resp.status
        except Exception as e:
            code, page = 0, str(e)
        check("GET /register -> 200", code == 200)
        check("/register page posts to /api/v1/bots/register",
              "/api/v1/bots/register" in page)
        check("/register page no longer references register-with-key",
              "register-with-key" not in page)

        # -- registration throttle per IP ---------------------------
        limit = server.REGISTRATION_PER_IP_PER_HOUR
        check("config exposes registration_per_ip_per_hour", True)
        c, r = req("GET", "/api/v1/config")
        check("config registration_per_ip_per_hour == server limit",
              c == 200 and r.get("registration_per_ip_per_hour") == limit,
              f"{c} {r}")

        def throttled_register(i, ip, endpoint="/api/v1/bots/register",
                              xff=None):
            body = {"name": f"throttlebot{i}"}
            if endpoint == "/api/v1/bots/register":
                body["ed25519_public_key"] = ed25519.create_keypair()[1].hex()
            headers = {"Fly-Client-IP": ip}
            if xff is not None:
                headers["X-Forwarded-For"] = xff
            return req("POST", endpoint, body, headers=headers)

        ip_a = "10.200.0.1"
        ok = True
        for i in range(limit):
            c, r = throttled_register(i, ip_a)
            ok = ok and (c == 201)
        check(f"{limit} registrations from one IP -> 201",
              ok)
        c, r = throttled_register(limit, ip_a)
        check("registration 11 from same IP -> 429", c == 429,
              f"{c} {r}")
        check("429 error names the registration rate limit",
              "registrations/hour" in r.get("error", ""), str(r)[:160])
        check("429 body carries limit/used/retry_after_seconds",
              r.get("limit") == limit and r.get("used") == limit
              and isinstance(r.get("retry_after_seconds"), int), str(r)[:160])
        # retry_after via raw headers
        raw = urllib.request.Request(
            BASE + "/api/v1/bots/register", method="POST",
            data=json.dumps(
                {"name": "throttlebot_raw",
                 "ed25519_public_key": ed25519.create_keypair()[1].hex()}
            ).encode(),
            headers={"Content-Type": "application/json",
                     "Fly-Client-IP": ip_a})
        try:
            urllib.request.urlopen(raw, timeout=15)
            hdrs, code = {}, 200
        except urllib.error.HTTPError as e:
            hdrs, code = dict(e.headers), e.code
        check("429 carries Retry-After header",
              code == 429 and "Retry-After" in hdrs, f"{code} {hdrs}")
        check("429 carries X-RateLimit-Limit header",
              str(hdrs.get("X-RateLimit-Limit")) == str(limit),
              str(dict(hdrs)))
        check("429 carries X-RateLimit-Remaining: 0",
              str(hdrs.get("X-RateLimit-Remaining")) == "0")
        # the dead endpoint 410s even from a throttled IP (gone before
        # the throttle ever runs)
        c, r = throttled_register(999, ip_a, "/api/v1/bots/register-with-key")
        check("register-with-key -> 410 even when IP is throttled", c == 410,
              f"{c} {r}")
        # a different IP is unaffected
        c, r = throttled_register(1000, "10.200.0.2")
        check("different IP can still register -> 201", c == 201,
              f"{c} {r}")
        # failed validation does NOT consume quota: bad name on a fresh IP
        # repeatedly, then a valid name still works
        ip_c = "10.200.0.3"
        for i in range(3):
            c, _ = req("POST", "/api/v1/bots/register",
                       {"name": "x",  # too short -> 400
                        "ed25519_public_key": ed25519.create_keypair()[1].hex()},
                       headers={"Fly-Client-IP": ip_c})
            assert c == 400, f"expected 400, got {c}"
        c, r = throttled_register(2000, ip_c)
        check("failed validations don't burn IP quota -> 201", c == 201,
              f"{c} {r}")

        # -- X-Forwarded-For is ignored (spoof-proof) ----------------
        # Rotating XFF while Fly-Client-IP stays fixed: all 10 count
        # against the Fly-Client-IP bucket, the 11th is throttled.
        ip_x = "10.99.0.1"
        ok = True
        for i in range(limit):
            c, r = throttled_register(3000 + i, ip_x,
                                      xff=f"203.0.113.{i + 1}")
            ok = ok and (c == 201)
        check(f"{limit} regs with rotating X-Forwarded-For -> 201", ok)
        c, r = throttled_register(3999, ip_x, xff="203.0.113.99")
        check("11th reg with fresh spoofed XFF -> still 429", c == 429,
              f"{c} {r}")
        # A spoofed XFF naming a throttled IP doesn't poison a fresh one.
        c, r = throttled_register(4000, "10.99.0.2", xff=ip_x)
        check("XFF naming a throttled IP doesn't block a fresh IP -> 201",
              c == 201, f"{c} {r}")

        # -- IPv6 /64 bucketing -------------------------------------
        v6base = "2001:db8::"
        ok = True
        for i in range(1, limit + 1):
            c, r = throttled_register(5000 + i, f"{v6base}{i:x}")
            ok = ok and (c == 201)
        check(f"{limit} regs from distinct addresses in one /64 -> 201", ok)
        c, r = throttled_register(5999, f"{v6base}b")
        check("11th address in the same /64 -> 429", c == 429, f"{c} {r}")
        c, r = throttled_register(6000, "2001:db8:1::1")
        check("different /64 is unaffected -> 201", c == 201, f"{c} {r}")
        # IPv4-mapped IPv6 unwraps to the IPv4 bucket (10.99.0.1 throttled).
        c, r = throttled_register(6001, "::ffff:10.99.0.1")
        check("::ffff:10.99.0.1 shares 10.99.0.1's throttled bucket -> 429",
              c == 429, f"{c} {r}")

        # -- throttle_ip_key unit checks ----------------------------
        t = server.throttle_ip_key
        check("same /64 -> same bucket",
              t("2001:db8::1") == t("2001:db8::ffff"))
        check("different /64 -> different bucket",
              t("2001:db8::1") != t("2001:db8:1::1"))
        check("IPv4-mapped unwraps to IPv4",
              t("::ffff:1.2.3.4") == t("1.2.3.4") == "v4:1.2.3.4")
        check("IPv4 buckets literally", t("1.2.3.4") == "v4:1.2.3.4")
        check("empty/unknown -> '?'", t("") == "?" and t(None) == "?")
        check("unparseable buckets literally", t("garbage") == "garbage")
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
