#!/usr/bin/env python3
"""Switchboard community-projects tests.

Spins up a throwaway server with a temp SQLite DB, then proves end-to-end:

  project create (signed, id format, cut bounds, dup) /
  contributions (source required, signed, bad sig rejected) /
  confirm/dispute votes (one per bot, no self-votes, dispute needs reason) /
  starter review (accept/reject, starter-only) /
  accepted rule (peer confirm w/o dispute, or starter override) /
  complete + list on marketplace /
  atomic settlement SPLIT: buyer debited, starter coordinator cut, equal shares
  to qualifying contributors, 5% fee to treasury, ledger chain verifies /
  project hash chain verifies via /api/v1/chain/verify?project= /
  export JSON contains only accepted contributions /
  UI pages render.

Run:  python3 tests/test_projects.py
"""
import hashlib
import json
import os
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


def raw_req(method, path):
    r = urllib.request.Request(BASE + path, method=method)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, resp.read(), resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        return e.code, b"", ""


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


def cjson(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def ev_sig(bot, pid, kind, payload):
    ts = now_ts()
    pj = cjson(payload)
    sig = esign(bot, server.canonical_project_event(pid, kind, pj, ts))
    return ts, sig, pj


def create_project(bot, pid, title="Test project", brief="Collect things.",
                   cut=15):
    ts = now_ts()
    sig = esign(bot, server.canonical_project_create(pid, title, brief, cut, ts))
    return req("POST", "/api/v1/projects",
               {"project_id": pid, "title": title, "brief": brief,
                "coordinator_cut_pct": cut,
                "timestamp": ts, "signature": sig}, auth(bot))


def contribute(bot, pid, body, source="https://example.com/s"):
    ts, sig, _ = ev_sig(bot, pid, "contribution",
                        {"body": body, "source": source})
    return req("POST", f"/api/v1/projects/{pid}/contributions",
               {"body": body, "source": source,
                "timestamp": ts, "signature": sig}, auth(bot))


def vote(bot, pid, cid, v, reason=""):
    ts, sig, _ = ev_sig(bot, pid, "vote",
                        {"contribution_id": cid, "vote": v, "reason": reason})
    return req("POST", f"/api/v1/projects/{pid}/contributions/{cid}/vote",
               {"vote": v, "reason": reason,
                "timestamp": ts, "signature": sig}, auth(bot))


def review(bot, pid, cid, decision):
    ts, sig, _ = ev_sig(bot, pid, "review",
                        {"contribution_id": cid, "decision": decision})
    return req("POST", f"/api/v1/projects/{pid}/contributions/{cid}/review",
               {"decision": decision,
                "timestamp": ts, "signature": sig}, auth(bot))


def simple_event(bot, pid, action):
    # HTTP action "complete" carries event kind "completed"
    kind = {"complete": "completed"}.get(action, action)
    ts, sig, _ = ev_sig(bot, pid, kind, {})
    return req("POST", f"/api/v1/projects/{pid}/{action}",
               {"timestamp": ts, "signature": sig}, auth(bot))


def project_listing_id(pid):
    return ("lst_" + hashlib.sha256(
        f"project-listing:{pid}".encode("utf-8")).hexdigest()[:16])


def list_project(bot, pid, price="$100.00"):
    # listing_id is deterministic from the project id, so the client can
    # include it in the signed payload.
    lid = project_listing_id(pid)
    ts, sig, _ = ev_sig(bot, pid, "listed",
                        {"project_id": pid, "listing_id": lid,
                         "price": price})
    return req("POST", f"/api/v1/projects/{pid}/list",
               {"price": price, "timestamp": ts, "signature": sig}, auth(bot))


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
    tmp = tempfile.mkdtemp(prefix="sb-proj-")
    db_path = os.path.join(tmp, "t.db")
    port = 18348
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

        starter = register("proj_starter")
        alice = register("proj_alice")
        bob = register("proj_bob")
        carol = register("proj_carol")
        buyer = register("proj_buyer")
        for b in (starter, alice, bob, carol, buyer):
            subscribe(b)

        PID = "prj_" + secrets.token_hex(8)

        # 1. create
        code, cr = create_project(starter, PID, cut=15)
        check("create project 201", code == 201, (code, cr))
        code, _ = create_project(starter, PID)
        check("duplicate project_id 409", code == 409, code)
        code, _ = create_project(starter, "bad-id")
        check("bad project_id format 400", code == 400, code)
        code, _ = create_project(starter, "prj_" + secrets.token_hex(8), cut=51)
        check("coordinator cut >50 rejected 400", code == 400, code)
        ts = now_ts()
        badpid = "prj_" + secrets.token_hex(8)
        bad = esign(alice, server.canonical_project_create(
            badpid, "Test title", "Brief", 15, ts))  # signed by alice, authed as starter
        code, _ = req("POST", "/api/v1/projects",
                      {"project_id": badpid,
                       "title": "Test title", "brief": "Brief",
                       "coordinator_cut_pct": 15,
                       "timestamp": ts, "signature": bad}, auth(starter))
        check("wrong-key signature 403", code == 403, code)

        # 2. contributions
        code, _ = contribute(alice, PID, "", "https://example.com/x")
        check("empty body 400", code == 400, code)
        code, _ = contribute(alice, PID, "data point", "")
        check("missing source 400", code == 400, code)
        code, _ = contribute(alice, PID, "data point", "not-a-url")
        check("bad source URL 400", code == 400, code)
        code, c1 = contribute(alice, PID, "Xe-100: 80MW, Seadrift TX, Dow, pre-construction",
                              "https://example.com/xe100")
        check("contribute 201", code == 201, (code, c1))
        cid1 = c1["contribution_id"]
        code, c2 = contribute(bob, PID, "BWRX-300: 300MW, Darlington ON, OPG, licensed",
                              "https://example.com/bwrx")
        check("second contribution 201", code == 201, (code, c2))
        cid2 = c2["contribution_id"]
        code, c3 = contribute(carol, PID, "Unverified rumor with no backing",
                              "https://example.com/rumor")
        check("third contribution 201", code == 201, (code, c3))
        cid3 = c3["contribution_id"]

        # 3. votes
        code, _ = vote(alice, PID, cid1, "confirm")
        check("no self-vote 403", code == 403, code)
        code, _ = vote(bob, PID, cid1, "confirm")
        check("peer confirm 201", code == 201, code)
        code, _ = vote(bob, PID, cid1, "dispute", "changed my mind")
        check("double vote 409", code == 409, code)
        code, _ = vote(carol, PID, cid2, "dispute")
        check("dispute without reason 400", code == 400, code)
        code, _ = vote(carol, PID, cid2, "dispute", "source is a parked domain")
        check("dispute with reason 201", code == 201, code)
        code, _ = vote(starter, PID, cid2, "confirm")
        check("starter can vote as peer 201", code == 201, code)

        # 4. review (starter-only)
        code, _ = review(alice, PID, cid3, "reject")
        check("non-starter review 403", code == 403, code)
        code, _ = review(starter, PID, cid3, "reject")
        check("starter reject 200", code == 200, code)
        code, _ = review(starter, PID, cid2, "accept")
        check("starter accept overrides dispute 200", code == 200, code)
        code, _ = review(starter, PID, cid2, "reject")
        check("repeat review rejected 409 (final)", code == 409, code)
        code, _ = review(starter, PID, 999999, "accept")
        check("review unknown contribution 404", code == 404, code)

        # 5. detail shows accepted flags
        code, det = req("GET", f"/api/v1/projects/{PID}")
        acc = {c["id"]: c["accepted"] for c in det["contributions"]}
        check("detail 200", code == 200, code)
        check("peer-confirmed contribution accepted", acc.get(cid1) is True, acc)
        check("starter-accepted disputed contribution accepted",
              acc.get(cid2) is True, acc)
        check("starter-rejected contribution not accepted",
              acc.get(cid3) is False, acc)

        # 6. export has only accepted
        code, raw, ct = raw_req("GET", f"/api/v1/projects/{PID}/export")
        doc = json.loads(raw.decode())
        check("export 200 json", code == 200 and "application/json" in ct,
              (code, ct))
        exp_ids = {c["id"] for c in doc["contributions"]}
        check("export contains only accepted",
              exp_ids == {cid1, cid2}, exp_ids)

        # 7. complete
        code, _ = simple_event(alice, PID, "complete")
        check("non-starter complete 403", code == 403, code)
        code, comp = simple_event(starter, PID, "complete")
        check("complete 200", code == 200, (code, comp))
        code, _ = contribute(bob, PID, "late data", "https://example.com/late")
        check("contribute after complete 409", code == 409, code)

        # 8. list on marketplace
        code, lst = list_project(starter, PID, "$100.00")
        check("list project 201", code == 201, (code, lst))
        LID = lst["listing_id"]
        code, ld = req("GET", f"/api/v1/marketplace/listings/{LID}")
        check("listing carries project_id",
              code == 200 and ld.get("project_id") == PID, code)

        # 9. settle: propose + complete; verify the automatic split.
        # deal 10000c: fee 500c -> net 9500c; coord 15% = 1425c to starter;
        # remainder 8075c over {alice, bob} -> 4037/4038 (sorted bot_id order).
        payload = {"buyer_id": buyer["bot_id"],
                   "final_price_cents": 10000, "currency": "USD"}
        ts = now_ts()
        pj = cjson(payload)
        sig = esign(starter, server.canonical_listing_event(
            LID, "propose-completion", pj, ts))
        code, _ = req("POST", f"/api/v1/marketplace/listings/{LID}/propose-completion",
                      {**payload, "timestamp": ts, "signature": sig},
                      auth(starter))
        check("propose 200", code == 200, code)
        b0, a0, bo0, s0 = (balance(buyer), balance(alice), balance(bob),
                           balance(starter))
        ts = now_ts()
        pj = cjson(payload)
        sig = esign(buyer, server.canonical_listing_event(LID, "completed", pj, ts))
        code, done = req("POST", f"/api/v1/marketplace/listings/{LID}/complete",
                         {"timestamp": ts, "signature": sig}, auth(buyer))
        check("complete 200", code == 200, (code, done))
        split = {s["bot_id"]: s["cents"] for s in (done.get("project_split") or [])}
        order = sorted([alice["bot_id"], bob["bot_id"]])
        exp = {starter["bot_id"]: 1425, order[0]: 4038, order[1]: 4037}
        check("project_split in response", split == exp, (split, exp))
        check("buyer debited 10000", balance(buyer) == b0 - 10000,
              (b0, balance(buyer)))
        check("starter got coordinator cut 1425",
              balance(starter) == s0 + 1425, (s0, balance(starter)))
        check("alice got her share", balance(alice) == a0 + exp[alice["bot_id"]],
              (a0, balance(alice)))
        check("bob got his share", balance(bob) == bo0 + exp[bob["bot_id"]],
              (bo0, balance(bob)))
        entries = [e for e in ledger(limit=200) if e["listing_id"] == LID]
        kinds = sorted(e["kind"] for e in entries)
        check("ledger: 1 debit + 3 split credits + 1 fee",
              kinds == ["deal_credit"] * 3 + ["deal_debit", "fee_credit"],
              kinds)
        check("ledger hash chain verifies", ledger_hash_ok(ledger(limit=200)))
        check("treasury got 500c fee",
              any(e["kind"] == "fee_credit" and e["amount_cents"] == 500
                  and e["to_acct"] == "treasury" for e in entries), kinds)
        split_sum = sum(e["amount_cents"] for e in entries
                        if e["kind"] == "deal_credit")
        check("split credits sum to net 9500", split_sum == 9500, split_sum)

        # 10. project hash chain verifies
        code, vc = req("GET", f"/api/v1/chain/verify?project={PID}")
        check("project chain verifies",
              code == 200 and vc.get("ok") is True, (code, vc))

        # 11. list-before-complete blocked; empty project blocked
        PID2 = "prj_" + secrets.token_hex(8)
        code, _ = create_project(carol, PID2)
        assert code == 201
        code, _ = list_project(carol, PID2)
        check("list before complete 409", code == 409, code)
        code, _ = simple_event(carol, PID2, "complete")
        assert code == 200
        code, lr = list_project(carol, PID2)
        check("list with zero accepted 409", code == 409, (code, lr))

        # 12. UI pages
        code, raw, _ = raw_req("GET", "/projects")
        check("/projects renders", code == 200 and b"Projects" in raw, code)
        code, raw, _ = raw_req("GET", f"/projects/{PID}")
        check("project detail renders",
              code == 200 and b"Test project" in raw, code)
        code, raw, _ = raw_req("GET", "/projects/bad")
        check("bad project id 404", code == 404, code)
        code, raw, _ = raw_req("GET", "/")
        check("home shows projects section", code == 200 and b"Community projects" in raw,
              code)

        # 13. list endpoints
        code, lp = req("GET", "/api/v1/projects")
        check("list all projects contains both",
              code == 200 and {PID, PID2} <= {p["project_id"]
                                              for p in lp["projects"]}, code)
        code, lpo = req("GET", "/api/v1/projects?status=open")
        check("open filter excludes completed",
              code == 200 and PID not in {p["project_id"]
                                          for p in lpo["projects"]}, code)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILURES:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    main()
