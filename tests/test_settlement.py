#!/usr/bin/env python3
"""Switchboard settlement tests (test credits).

Spins up a throwaway server with a temp SQLite DB, then proves end-to-end:

  experiment seed grant (20000c = 200 TEST) on register / balance + ledger read APIs /
  earned faucet: 403 before any paid deal, grant + daily limit (429) after /
  full deal: propose -> complete moves test credits buyer->seller(net of fee),
  fee->treasury / insufficient funds -> 402 and the listing stays pending /
  double complete -> 409 / ledger hash chain verifies /
  fees table reconciles with fee_credit entries.

Genesis Experiment policy: CREDIT_SEED_CENTS=20000, FAUCET_DAILY_CENTS=20000 (200 TEST)
earned-only (a paid completed deal in the trailing 7 days unlocks it).

Run:  python3 tests/test_settlement.py
"""
import hashlib
import json
import os
import re
import secrets
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
import server  # canonical signing-byte builders

ADMIN = "test-admin-token"
BASE = None
PASS, FAIL = [], []


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
    assert code == 201, resp
    return {"bot_id": resp["bot_id"], "secret": resp["api_secret"],
            "sk": sk.hex(), "pk": pk.hex(), "name": name}


def subscribe(bot):
    code, _ = req("POST", "/api/v1/admin/subscribe",
                  {"bot_id": bot["bot_id"], "tier": "trial", "days": 30}, ADM)
    assert code == 200, code


def esign(bot, msg_bytes):
    return ed25519.sign(bytes.fromhex(bot["sk"]), msg_bytes).hex()


def lid():
    return "lst_" + secrets.token_hex(8)


def create_listing(bot, lid, title, price):
    ts = now_ts()
    sig = esign(bot, server.canonical_listing_create(
        lid, title, "desc", price, "", ts))
    code, resp = req("POST", "/api/v1/marketplace/listings",
                     {"listing_id": lid, "title": title, "description": "desc",
                      "price": price, "terms": "",
                      "timestamp": ts, "signature": sig}, auth(bot))
    assert code == 201, (code, resp)


def propose(seller, lid, buyer_id, cents):
    payload = {"buyer_id": buyer_id, "final_price_cents": cents,
               "currency": "USD"}
    ts = now_ts()
    pjson = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    sig = esign(seller, server.canonical_listing_event(lid, "propose-completion",
                                                       pjson, ts))
    code, resp = req(
        "POST", f"/api/v1/marketplace/listings/{lid}/propose-completion",
        {**payload, "timestamp": ts, "signature": sig}, auth(seller))
    assert code == 200, (code, resp)


def complete(buyer, lid):
    _, detail = req("GET", f"/api/v1/marketplace/listings/{lid}")
    payload = {"buyer_id": buyer["bot_id"],
               "final_price_cents": detail["pending_final_price_cents"],
               "currency": detail["currency"]}
    ts = now_ts()
    pjson = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    sig = esign(buyer, server.canonical_listing_event(lid, "completed", pjson,
                                                      ts))
    return req("POST", f"/api/v1/marketplace/listings/{lid}/complete",
               {"timestamp": ts, "signature": sig}, auth(buyer))


def balance(bot):
    code, resp = req("GET", "/api/v1/credits/balance", headers=auth(bot))
    assert code == 200, (code, resp)
    return resp["balance_cents"]


def ledger(**qs):
    q = urllib.parse.urlencode(qs)
    code, resp = req("GET", "/api/v1/ledger?" + q)
    assert code == 200, (code, resp)
    return resp["entries"]


def ledger_hash_ok(entries):
    """Recompute the chain oldest->newest; entries come newest-first."""
    prev = "0" * 64
    for e in reversed(entries):
        lid = e["listing_id"] or ""
        body = (f"{e['kind']}\n{e['amount_cents']}\n{e['from_acct']}\n"
                f"{e['to_acct']}\n{lid}\n{e['memo']}")
        h = hashlib.sha256(
            f"{prev}\nledger\nglobal\n{e['from_acct']}\n{body}\n{e['created_at']}"
            .encode("utf-8")).hexdigest()
        if h != e["hash"] or e["prev_hash"] != prev:
            return False
        prev = e["hash"]
    return True


def main():
    global BASE
    tmp = tempfile.mkdtemp(prefix="sb-settle-")
    db_path = os.path.join(tmp, "t.db")
    port = 18347
    env = dict(os.environ, PORT=str(port), SWITCHBOARD_DB=db_path,
               SWITCHBOARD_ADMIN_TOKEN=ADMIN,
               SWITCHBOARD_PUBLIC_URL=f"http://127.0.0.1:{port}")
    proc = subprocess.Popen([sys.executable, os.path.join(HERE, "server.py")],
                            env=env, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        BASE = f"http://127.0.0.1:{port}"
        for _ in range(60):
            try:
                if req("GET", "/healthz")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.2)

        seller = register("settle_seller")
        buyer = register("settle_buyer")
        poor = register("settle_poor")
        subscribe(seller)
        subscribe(buyer)
        subscribe(poor)

        # 1. seed grants (experiment: 200 TEST starter)
        check("seed grant 20000 on register (seller)",
              balance(seller) == 20000, balance(seller))
        check("seed grant 20000 on register (buyer)",
              balance(buyer) == 20000, balance(buyer))
        seed_entries = [e for e in ledger(limit=200)
                        if e["kind"] == "credit_issue"]
        check("seed grants in public ledger", len(seed_entries) >= 3)

        # 2. earned faucet: locked before any paid deal
        code, fr = req("POST", "/api/v1/credits/faucet", {}, auth(buyer))
        check("faucet 403 before any paid deal",
              code == 403 and fr.get("error") == "faucet_earned_only",
              (code, fr))

        # 3. happy-path deal: $1.00 -> fee 5c, seller nets 95c
        L1 = lid()
        create_listing(seller, L1, "Test dataset", "$1.00")
        propose(seller, L1, buyer["bot_id"], 100)
        b0, s0 = balance(buyer), balance(seller)
        code, cr = complete(buyer, L1)
        check("complete 200", code == 200, (code, cr))
        st = cr.get("settlement") or {}
        check("settlement block present with 3 ledger ids",
              len(st.get("ledger_entry_ids", [])) == 3, st)
        hashes = st.get("ledger_entry_hashes", [])
        check("settlement block carries 3 ledger entry hashes",
              len(hashes) == 3 and all(
                  isinstance(h, str) and len(h) == 64 for h in hashes), st)
        check("receipt convention documented in settlement block",
              isinstance(st.get("receipt"), str)
              and "ledger_entry_hash" in st["receipt"], st)
        led = ledger(limit=200)
        led_hashes = {e["hash"] for e in led}
        check("receipt hashes verify against public ledger",
              all(h in led_hashes for h in hashes), hashes[:1])
        # bot profile page surfaces the TEST-labeled balance
        with urllib.request.urlopen(
                BASE + "/bot/" + seller["bot_id"], timeout=15) as resp:
            prof_html = resp.read().decode()
        check("bot profile page shows TEST-labeled balance",
              "TEST" in prof_html and "test credits" in prof_html,
              prof_html[:200])
        check("buyer debited 100", balance(buyer) == b0 - 100,
              (b0, balance(buyer)))
        check("seller credited net 95", balance(seller) == s0 + 95,
              (s0, balance(seller)))
        tbal = req("GET", "/api/v1/ledger?acct=treasury&limit=5")[1]["entries"]
        check("treasury got 5c fee",
              sum(e["amount_cents"] for e in tbal
                  if e["kind"] == "fee_credit") == 5, tbal)
        check("treasury balance 5 in settlement block",
              st.get("treasury_balance_cents") == 5, st)

        # 3b. earned faucet: unlocked after the paid deal
        code, fr = req("POST", "/api/v1/credits/faucet", {}, auth(buyer))
        check("faucet grants 20000 after paid deal",
              code == 200 and fr["issued_cents"] == 20000, (code, fr))
        check("faucet bumps balance",
              balance(buyer) == b0 - 100 + 20000, balance(buyer))
        code, fr2 = req("POST", "/api/v1/credits/faucet", {}, auth(buyer))
        check("faucet daily limit -> 429", code == 429, code)

        # 4. insufficient funds -> 402, listing untouched
        L2 = lid()
        create_listing(seller, L2, "Pricey dataset", "$500.00")
        propose(seller, L2, poor["bot_id"], 50000)
        code, cr = complete(poor, L2)
        check("insufficient funds -> 402", code == 402, (code, cr))
        _, det = req("GET", f"/api/v1/marketplace/listings/{L2}")
        check("listing still pending after 402",
              det["status"] != "completed"
              and det["pending_buyer_id"] is not None,
              det["status"])
        check("no balance moved on 402", balance(poor) == 20000, balance(poor))

        # 4b. 402 leaves ZERO trace: no event, no state change, no ledger entry
        L2b = lid()
        create_listing(seller, L2b, "Trace check", "$500.00")
        propose(seller, L2b, poor["bot_id"], 50000)
        _, snap = req("GET", f"/api/v1/marketplace/listings/{L2b}")
        n_ev0 = len(snap["events"])
        head0 = snap["events"][-1]["hash"] if snap["events"] else None
        n_led0 = len(ledger(limit=300))
        b_poor0, b_sell0 = balance(poor), balance(seller)
        code, fs0 = req("GET", "/api/v1/admin/billing/summary", headers=ADM)
        fees0 = sum(l["deal_fees_cents"] for l in fs0.get("lines", [])) \
            if code == 200 else None
        code, cr = complete(poor, L2b)
        check("402 on unfunded complete", code == 402, (code, cr))
        _, det2b = req("GET", f"/api/v1/marketplace/listings/{L2b}")
        check("402: listing status unchanged",
              det2b["status"] == snap["status"], det2b["status"])
        check("402: pending buyer unchanged",
              det2b["pending_buyer_id"] == snap["pending_buyer_id"])
        check("402: no new listing events",
              len(det2b["events"]) == n_ev0, len(det2b["events"]))
        check("402: listing head hash unchanged",
              (det2b["events"][-1]["hash"] if det2b["events"] else None) == head0)
        check("402: balances unchanged",
              balance(poor) == b_poor0 and balance(seller) == b_sell0,
              (balance(poor), balance(seller)))
        check("402: no new ledger entries",
              len(ledger(limit=300)) == n_led0)
        code, fs1 = req("GET", "/api/v1/admin/billing/summary", headers=ADM)
        fees1 = sum(l["deal_fees_cents"] for l in fs1.get("lines", [])) \
            if code == 200 else None
        check("402: fees table unchanged",
              fees0 is not None and fees1 == fees0, (fees0, fees1))

        # 5. double complete -> 409
        code, _ = complete(buyer, L1)
        check("double complete -> 409", code == 409, code)

        # 5b. free deal: $0 propose + complete works, settles nothing
        L3 = lid()
        create_listing(seller, L3, "Freebie", "$0.00")
        propose(seller, L3, buyer["bot_id"], 0)
        b0f, s0f = balance(buyer), balance(seller)
        n_ledf = len(ledger(limit=300))
        code, cr = complete(buyer, L3)
        check("free complete -> 200", code == 200, (code, cr))
        check("free: no settlement block", cr.get("settlement") is None,
              cr.get("settlement"))
        check("free: balances unchanged",
              balance(buyer) == b0f and balance(seller) == s0f,
              (balance(buyer), balance(seller)))
        check("free: no new ledger entries",
              len(ledger(limit=300)) == n_ledf)
        _, det3 = req("GET", f"/api/v1/marketplace/listings/{L3}")
        check("free: listing completed at 0c",
              det3["status"] == "completed"
              and det3["final_price_cents"] == 0
              and det3["buyer_id"] == buyer["bot_id"], det3["status"])

        # 6b. server-minted listing ids (additive, 2026-09-29): omit listing_id,
        # sign the noid canonical bytes, server assigns lst_<16hex>
        def create_listing_noid(bot, title, price):
            ts = now_ts()
            sig = esign(bot, server.canonical_listing_create_noid(
                title, "desc", price, "", ts))
            return req("POST", "/api/v1/marketplace/listings",
                       {"title": title, "description": "desc",
                        "price": price, "terms": "",
                        "timestamp": ts, "signature": sig}, auth(bot))

        code, m1 = create_listing_noid(seller, "Minted One", "$10")
        check("omit listing_id -> 201", code == 201, (code, m1))
        check("minted id matches lst_<16hex>",
              bool(re.fullmatch(r"lst_[0-9a-f]{16}", m1.get("listing_id", ""))),
              m1.get("listing_id"))
        code, m2 = create_listing_noid(seller, "Minted Two", "$20")
        check("second minted create -> 201 with distinct id",
              code == 201 and m2.get("listing_id") != m1.get("listing_id"),
              (code, m2.get("listing_id"), m1.get("listing_id")))
        _, detm = req("GET", f"/api/v1/marketplace/listings/{m1['listing_id']}")
        check("minted listing reads back open",
              detm.get("status") == "open" and detm.get("title") == "Minted One",
              detm.get("status"))
        # minted listing is fully usable: close a deal on it
        propose(seller, m1["listing_id"], buyer["bot_id"], 1000)
        code, cm = complete(buyer, m1["listing_id"])
        check("minted listing completes a deal", code == 200, (code, cm))

        # old-style signature (with id) on an omitted-id body must NOT verify
        ts = now_ts()
        bad = esign(seller, server.canonical_listing_create(
            m1["listing_id"], "Sneaky", "desc", "$5", "", ts))
        code, _ = req("POST", "/api/v1/marketplace/listings",
                      {"title": "Sneaky", "description": "desc", "price": "$5",
                       "terms": "", "timestamp": ts, "signature": bad},
                      auth(seller))
        check("with-id signature on omitted-id body -> 403", code == 403, code)
        # and vice versa: noid signature with a provided id must NOT verify
        ts = now_ts()
        bad2 = esign(seller, server.canonical_listing_create_noid(
            "Sneaky2", "desc", "$5", "", ts))
        code, _ = req("POST", "/api/v1/marketplace/listings",
                      {"listing_id": lid(), "title": "Sneaky2",
                       "description": "desc", "price": "$5", "terms": "",
                       "timestamp": ts, "signature": bad2}, auth(seller))
        check("noid signature with provided id -> 403", code == 403, code)
        # malformed provided id still 400
        ts = now_ts()
        sig3 = esign(seller, server.canonical_listing_create(
            "nope", "Bad", "desc", "$5", "", ts))
        code, r3 = req("POST", "/api/v1/marketplace/listings",
                       {"listing_id": "nope", "title": "Bad", "description": "desc",
                        "price": "$5", "terms": "", "timestamp": ts,
                        "signature": sig3}, auth(seller))
        check("malformed provided id -> 400", code == 400, (code, r3))
        # provided id still works (old path intact)
        L4 = lid()
        create_listing(seller, L4, "Classic", "$30")
        check("provided id path unchanged", True)

        # 6. chain verifies + fees reconcile
        all_entries = ledger(limit=200)
        check("ledger hash chain verifies", ledger_hash_ok(all_entries))
        fee_credits = sum(e["amount_cents"] for e in all_entries
                          if e["kind"] == "fee_credit")
        code, fs = req("GET", "/api/v1/admin/billing/summary", headers=ADM)
        invoiced = sum(l["deal_fees_cents"] for l in fs.get("lines", [])) \
            if code == 200 else None
        check("fee_credit total reconciles with fees table",
              invoiced is not None and fee_credits == invoiced,
              (fee_credits, invoiced))

        print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
        sys.exit(1 if FAIL else 0)
    finally:
        proc.terminate()


if __name__ == "__main__":
    main()
