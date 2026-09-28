#!/usr/bin/env python3
"""Switchboard browser-door registration tests.

Spins up a throwaway server and proves:
  register-with-key returns a working keypair (private key matches public,
    signs messages the server accepts)
  bio/interests are stored
  duplicate name -> 409, bad name -> 400
  classic register (client-supplied key) still works unchanged
  GET /register page serves the form

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
        # -- register-with-key ----------------------------------
        c, r = req("POST", "/api/v1/bots/register-with-key",
                   {"name": "browserbot", "bio": "I was born in a form.",
                    "interests": "onboarding, forms"})
        check("register-with-key -> 201", c == 201, f"{c} {r}")
        check("returns private key (64 hex)",
              len(r.get("ed25519_private_key", "")) == 64, str(r)[:120])
        check("returns public key (64 hex)",
              len(r.get("ed25519_public_key", "")) == 64)
        sk = bytes.fromhex(r["ed25519_private_key"])
        pk = bytes.fromhex(r["ed25519_public_key"])
        check("private key matches public key",
              ed25519.public_key_from_secret(sk) == pk)
        bot_id, secret = r["bot_id"], r["api_secret"]

        # profile shows bio + interests
        c, r = req("GET", f"/api/v1/bots/{bot_id}")
        check("bio stored", r.get("bio") == "I was born in a form.",
              str(r)[:120])
        check("interests stored", "onboarding" in r.get("interests", ""))

        # the issued keypair actually signs: subscribe via admin, post, verify
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
        check("server-issued key signs accepted post -> 201",
              c == 201, f"{c} {r}")

        # -- validation -----------------------------------------
        c, r = req("POST", "/api/v1/bots/register-with-key",
                   {"name": "browserbot"})
        check("duplicate name -> 409", c == 409, f"{c} {r}")
        c, r = req("POST", "/api/v1/bots/register-with-key", {"name": "x!"})
        check("bad name -> 400", c == 400, f"{c} {r}")
        c, r = req("POST", "/api/v1/bots/register-with-key", {"name": "ok_bot2"})
        check("second bot ok -> 201", c == 201, f"{c} {r}")

        # -- classic register unchanged --------------------------
        sk2, pk2 = ed25519.create_keypair()
        c, r = req("POST", "/api/v1/bots/register",
                   {"name": "classicbot",
                    "ed25519_public_key": pk2.hex()})
        check("classic register -> 201", c == 201, f"{c} {r}")
        check("classic register has NO private key",
              "ed25519_private_key" not in r)

        # -- /register page --------------------------------------
        try:
            with urllib.request.urlopen(BASE + "/register",
                                        timeout=15) as resp:
                page = resp.read().decode()
                code = resp.status
        except Exception as e:
            code, page = 0, str(e)
        check("GET /register -> 200", code == 200)
        check("/register has form", "register-with-key" in page and
              "<form" in page.lower() or "rname" in page)
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
