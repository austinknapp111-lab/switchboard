#!/usr/bin/env python3
"""Marketplace listing filters: ?q=, ?min_price=, ?max_price= (additive).

Spins up a throwaway server with a temp DB, creates listings with varied
titles and free-text prices, and proves the filters work over HTTP:
  q matches title+description (case-insensitive)
  min_price/max_price (USD cents) on parseable USD prices
  non-USD prices ('0.2 ETH') are excluded from price-filtered results
  invalid price filters -> 400; no filters -> old behavior unchanged
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
import server

ADMIN = "test-admin-token"
PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name +
          (f"  -- {detail}" if detail and not cond else ""))


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


def now_ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def auth(bot):
    return {"X-Bot-Id": bot["bot_id"], "X-Api-Secret": bot["secret"]}


ADM = {"X-Admin-Token": ADMIN}


def register(name):
    sk, pk = ed25519.create_keypair()
    c, resp = req("POST", "/api/v1/bots/register",
                  {"name": name, "ed25519_public_key": pk.hex()})
    assert c == 201, (c, resp)
    return {"bot_id": resp["bot_id"], "secret": resp["api_secret"],
            "sk": sk.hex()}


def esign(bot, b):
    return ed25519.sign(bytes.fromhex(bot["sk"]), b).hex()


def create_listing(bot, lid, title, desc, price):
    ts = now_ts()
    sig = esign(bot, server.canonical_listing_create(
        lid, title, desc, price, "", ts))
    return req("POST", "/api/v1/marketplace/listings",
               {"listing_id": lid, "title": title, "description": desc,
                "price": price, "terms": "", "timestamp": ts,
                "signature": sig}, auth(bot))


BASE = None


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
    sys.exit("server did not start")


def titles(resp):
    return sorted(l["title"] for l in resp["listings"])


def main():
    db = tempfile.mktemp(prefix="sb-filter-", suffix=".db")
    proc = start_server(8137, db)
    try:
        bot = register("filter-seller")
        c, _ = req("POST", "/api/v1/admin/subscribe",
                   {"bot_id": bot["bot_id"], "tier": "trial", "days": 30}, ADM)
        assert c == 200, (c, _)

        data = [
            ("lst_" + "a" * 16, "GPU hour block", "8x H100 overnight", "$35.20"),
            ("lst_" + "b" * 16, "Labeled tickets", "200k support tickets", "$450"),
            ("lst_" + "c" * 16, "Audit scan", "Solidity reentrancy scan", "$300"),
            ("lst_" + "d" * 16, "Rare GPU pointer", "exotic hardware", "0.2 ETH"),
            ("lst_" + "e" * 16, "Mentor hour", "negotiate in DMs", "negotiable"),
        ]
        for lid, t, d, p in data:
            c, r = create_listing(bot, lid, t, d, p)
            check(f"create '{t}' -> 201", c == 201, f"{c} {r}")

        c, r = req("GET", "/api/v1/marketplace/listings")
        check("no filters -> all 5", c == 200 and len(r["listings"]) == 5,
              f"{c} {len(r['listings'])}")

        c, r = req("GET", "/api/v1/marketplace/listings?q=gpu")
        check("q=gpu -> 2", c == 200 and titles(r) ==
              ["GPU hour block", "Rare GPU pointer"], titles(r))

        c, r = req("GET", "/api/v1/marketplace/listings?q=TICKETS")
        check("q case-insensitive", c == 200 and titles(r) ==
              ["Labeled tickets"], titles(r))

        c, r = req("GET", "/api/v1/marketplace/listings?max_price=5000")
        check("max_price=5000 -> GPU block only", c == 200 and titles(r) ==
              ["GPU hour block"], titles(r))

        c, r = req("GET", "/api/v1/marketplace/listings?min_price=30000")
        check("min_price=30000 -> tickets + scan", c == 200 and titles(r) ==
              ["Audit scan", "Labeled tickets"], titles(r))

        c, r = req("GET", "/api/v1/marketplace/listings?min_price=30000&max_price=40000")
        check("min+max -> scan only", c == 200 and titles(r) ==
              ["Audit scan"], titles(r))

        c, r = req("GET", "/api/v1/marketplace/listings?q=gpu&max_price=100000")
        check("q+max_price -> Rare GPU pointer excluded (non-USD)",
              c == 200 and titles(r) == ["GPU hour block"], titles(r))

        c, r = req("GET", "/api/v1/marketplace/listings?max_price=nope")
        check("max_price=bad -> 400", c == 400, f"{c} {r}")

        c, r = req("GET", "/api/v1/marketplace/listings?min_price=-5")
        check("min_price negative -> 400", c == 400, f"{c} {r}")

        c, r = req("GET", "/api/v1/marketplace/listings?status=open&max_price=46000")
        check("status+max_price combine", c == 200 and titles(r) ==
              ["Audit scan", "GPU hour block", "Labeled tickets"], titles(r))

        # price_to_cents unit checks
        check("price_to_cents $35.20", server.price_to_cents("$35.20") == 3520)
        check("price_to_cents 450", server.price_to_cents("450") == 45000)
        check("price_to_cents 50 USD", server.price_to_cents("50 USD") == 5000)
        check("price_to_cents 0.2 ETH -> None",
              server.price_to_cents("0.2 ETH") is None)
        check("price_to_cents negotiable -> None",
              server.price_to_cents("negotiable") is None)
    finally:
        proc.terminate()

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
