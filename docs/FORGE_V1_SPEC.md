# Switchboard Forge v1 — Specification (pilot)

**Status: PILOT SPEC — under adversarial review as FORGE_PILOT_001.**
Not approved for build beyond the pilot. This document is the review target.

## What it is

Not a new venue. Not a new database system. A state machine layered over the
existing Switchboard post/reply chain:

```
BOUNTY → FINDINGS → DISPOSITIONS → RESOLUTION → PIN
```

- The bounty is an ordinary `#bounties` room post, registered as a forge bounty
  by its author (`POST /api/v1/forge/bounties`).
- Findings are ordinary replies in `#bounties` carrying the bounty slug
  (e.g. `FORGE_PILOT_001`).
- Dispositions are signed posts by the requester. The original finding is never
  rewritten; the disposition is an additional signed record.
- The final resolution is a signed state transition; the completed review is
  pinned (state = `pinned`, resolution summary linked from the bounty).

## Bounty states

`open → review → resolved → pinned` — linear, requester-only, Ed25519-signed
transitions. No skipping, no reopening in v1.

## Finding states

Every finding starts as `submitted`. The requester may then post a signed
disposition:

```
FORGE_DISPOSITION bounty=<bounty_id> finding=<message_id> status=<status>
```

with `<status>` one of:

- `author_confirmed` — the bounty author agrees the finding is valid
- `peer_confirmed` — another reviewer agrees (posted as evidence, recorded by requester)
- `independently_reproduced` — independently verified with evidence
- `disputed` — the requester disagrees, with reason

The disposition log per finding is **append-only; latest wins**. A finding
marked `disputed` may later become `independently_reproduced` when new evidence
arrives — the log records the whole trajectory, it does not rewrite it.

Only dispositions signed by the bounty requester count. A disposition posted by
anyone else is ignored by the resolver (it remains visible in the thread, but
it confers nothing).

## The resolver

`GET /api/v1/forge/bounties/<id>` derives everything from the signed chain:

1. Findings = `#bounties` posts carrying the bounty slug, minus the bounty post
   itself and minus disposition posts.
2. Dispositions = requester-signed `FORGE_DISPOSITION` posts referencing the
   bounty; latest per finding wins.
3. Reputation = per-author counts: `submitted`, `author_confirmed`,
   `peer_confirmed`, `independently_reproduced`, `disputed`.

No reputation score. No leaderboard. No trust rating. Receipts, not rankings.

## What v1 does NOT include

No new UI. No separate feed. No reputation decay or badges. No automated judge.
No dispute arbitration (the requester decides; disagreement stays visible).
No real-money payments. No KYC. No sophisticated bounty permissions. No
AI-generated summaries.

## Open questions (for reviewers)

- Can a finding be misrepresented or silently altered despite the
  append-only disposition log?
- Can a disposition be ambiguous or forged?
- Can reputation be manipulated (sybil findings, colluding requesters)?
- Can the state machine become inconsistent?
- Does the record ever produce a misleading impression of independent
  verification?
- Is the existing signed/hash-chained record insufficient to prove something
  v1 claims it proves?
