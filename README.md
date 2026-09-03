# marcofgv — RailCall modules & workflows

Source, tests and signed manifests for the [RailCall marketplace](https://railcall.ai/marketplace) listings published by **marcofgv**. Everything an agent does through these listings flows through RailCall's airlock: dry-run preview → human approval → execute → Ed25519 signed receipt.

| Listing | Type | What it is |
|---|---|---|
| [`marcofgv/freelancer-com`](./freelancer-com) | module · 60 commands | The complete Freelancer.com API, governed — bids, milestones (escrow), messaging, contests, tracking |
| [`marcofgv/google-ads-airlock`](./google-ads-airlock) | module · 40 commands | Google Ads™ reads + 18 airlocked writes — no budget change without a human approval |
| [`marcofgv/google-ads-watch`](./google-ads-watch) | module · 22 commands | Free read-only Google Ads™ visibility: spend, budgets, change history |
| [`marcofgv/airtable-airlock`](./airtable-airlock) | module · 12 commands | Airtable, governed — 6 reads an agent may run freely, 6 writes it cannot fire without a human approval; cell values return wrapped as untrusted, and update/delete put the overwritten value in the receipt |
| [`marcofgv/freelancer-daily-bidder`](./freelancer-daily-bidder) | workflow | A governed daily bidding loop on top of freelancer-com (engine_spec, runnable) |

## Layout

Each module directory ships the exact published bundle plus its tests:

```
<module>/
  module.json     # signed manifest — commands with mode, risk, input_schema, sandbox block
  module.sig      # Ed25519 signature over the bundle
  handlers/       # stdlib-only handler (credentials via RailCall vault, never env/logged)
  tests/          # offline conformance/contract tests — python3 -m pytest tests/ -q
```

`tests/test_manifest_conformance.py` proves every command in the manifest maps to a handler function and accepts a schema-valid minimal input (network stubbed). The airlock module adds `tests/test_handler.py`, an offline contract suite over captured API fixtures.

## Install

```
railcall market install marcofgv/<listing>
```

Credentials are BYOK, saved in Studio → Integrations (RailCall's local vault). Nothing here ever reads `os.environ` or logs a token.

Not affiliated with Google or Freelancer.com; product names are used descriptively.
