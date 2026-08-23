# Ad Spend Watch · for Google Ads™ (`marcofgv/google-ads-watch`)

**See every dollar your AI agent is about to spend — before it spends it.** Read-only visibility into Google Ads for AI agents: 22 read commands, zero writes. Your agent can watch a runaway campaign; it can't touch a cent.

**Who it's for:** anyone letting an agent near an ad account. In 2026 the #1 way an agent burns money is ad spend — a recursive loop can drain a weekend's budget before anyone looks.

## What it does — 22 reads

`get_account_spend_today` is the one number to guard: today's accrued cost, ready for a ceiling alert. The other 21 cover campaigns, budgets (including shared budgets and how many campaigns they move), ad groups, keywords and negatives, ads, audiences, conversion actions and stats, assets, Google's own recommendations, the change-history audit, search-term reports (waste discovery), account metadata, accessible customers, and a bounded **SELECT-only** GAQL escape hatch (`search_gaql`, row-capped).

Every command declares `mode: read` and a `risk` tier; financial reads (`get_spend`, `get_account_spend_today`, `search_gaql`, `get_change_history`…) are `risk: medium`, the rest `low`.

## Install & example

```
railcall market install marcofgv/google-ads-watch
```

Then in Studio, run `list_campaigns` with `{"account": "1234567890"}` → each campaign with status, channel type, bidding strategy and current daily budget — the agent's starting map. `get_account_spend_today {"account": "1234567890"}` → `{"cost_micros": ..., "currency": "..."}` for a spend-ceiling alert.

## Credentials (BYOK)

Google Ads API developer token + OAuth2 (`developer_token`, `client_id`, `client_secret`, `refresh_token` — or `developer_token` + `access_token`). Saved in Studio → Integrations; resolved from RailCall's local vault, never `os.environ`, never logged. Egress allowlisted to `googleads.googleapis.com` + `oauth2.googleapis.com`; no subprocess; no filesystem writes (sandbox block declared in the manifest).

## Tests

`python3 -m pytest tests/ -q` — manifest↔handler conformance, 22/22, network stubbed.

## Honest limitations

- Reads only — pausing a runaway needs **Ad Spend Airlock** (the paid sibling with 18 governed writes).
- A Google Ads **developer token with test-account access** works instantly; production-account access requires Google's Basic Access approval on your token (Google's process, not ours).
- `get_change_history` snaps `days` to Google's valid enum {7, 14, 30}.

Not affiliated with Google; "Google Ads" is used descriptively. MIT licensed, stdlib-only handler.
