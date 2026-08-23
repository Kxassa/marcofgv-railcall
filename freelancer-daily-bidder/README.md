# Freelancer daily bidder, airlocked (`marcofgv/freelancer-daily-bidder`)

A governed daily bidding loop on top of [`marcofgv/freelancer-com`](../freelancer-com) — the workflow I run for real bidding. It automates the two expensive-but-safe steps (searching, drafting) and keeps the human on the one that gets accounts banned (the submit).

## How it runs

Three agent nodes, chained scout → draft → bid (declared in `engine_spec`, so the DAG engine executes it — Run button, per-node receipts, spend cap enforced):

1. **scout** — `get_notifications` first (a client who replied beats a cold bid), dedupes against `list_my_bids`, picks today's single best-fit project, reads competitor `get_bids` so pricing is against the field. Read-only tools; holds no write.
2. **draft** — writes the proposal from the scout's structured output. No tools at all.
3. **bid** — holds exactly one tool, `place_bid`, which is `write_requires_approval`: the airlock shows amount, currency, timeline and full text; a human approves; Ed25519 receipt.

Rule-of-Two by construction: the node reading untrusted client briefs has no write tool; the node that can spend money never sees untrusted text.

## Install

Requires the module first (declared as `module_dependency`, `minimum_version` enforced at install):

```
railcall market install marcofgv/freelancer-com
railcall market install marcofgv/freelancer-daily-bidder
```

Configure `context.query` (e.g. `"python automation"`) and `context.min_budget`. Capabilities declare `max_spend_cents: 50` — the engine's hard floor keeps any spend behind `require_human` regardless.

## Honest limitations

- A full dag-run receipt needs a live model in the station runtime; mid-loop suspend/resume on a pending approval is the documented partial-progress slice.
- Bids are denominated in the project's own currency — the airlock preview is the place to check the amount, and that check is the point.
