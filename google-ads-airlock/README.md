# Ad Spend Airlock · for Google Ads™ (`marcofgv/google-ads-airlock`)

**No AI-driven budget change without a human approval and a signed receipt.** 40 commands: the full read surface of Ad Spend Watch (22 reads) plus 18 governed writes covering the money loop — budgets, bids, campaign/ad-group/ad state, keywords and negatives, assets.

**Who it's for:** teams letting agents *manage* ad spend. An unsupervised agent can burn a weekend's budget; here every mutation stops at the airlock (dry-run preview → human approve → execute → Ed25519 signed receipt), which turns "the AI changed my budget" into an auditable, human-approved event.

**Status: proven live against a real Google Ads test account (API v25) — 40/40 commands**, building a campaign end-to-end (budget → campaign → ad group → keywords → ad → state changes).

## The write surface (all `write_requires_approval`)

`create_budget`, `set_budget`, `set_bid_strategy`, `create_campaign`, `pause_campaign` / `enable_campaign`, `create_ad_group`, `set_ad_group_bid`, `pause_ad_group` / `enable_ad_group`, `add_keywords`, `remove_keywords`, `add_negative_keywords`, `create_ad`, `pause_ad` / `enable_ad`, `remove_ad`, `add_asset`. Spend-affecting and destructive writes are `risk: high`; reversible pauses are `medium`. `validateOnly` wiring powers the dry-run preview.

## Install & example

```
railcall market install marcofgv/google-ads-airlock
```

Example loop: `get_account_spend_today` crosses your ceiling → agent stages `pause_campaign {"account":"1234567890","campaign_id":"..."}` → the airlock shows the exact mutation → you approve → receipt. Nothing fires without the approval.

## Credentials (BYOK)

Same as Watch: developer token + OAuth2, stored in Studio → Integrations (RailCall vault only — never env, never logged). Egress allowlisted to Google hosts; no subprocess; no filesystem writes.

## Tests

`python3 -m pytest tests/ -q` — 40/40 manifest↔handler conformance plus an offline contract suite (`test_handler.py`) proving each command targets the right v25 endpoint and builds the right GAQL / `:mutate` payload (snake_case updateMask, composite resource names, validateOnly), over captured fixtures — no network, no credentials.

## Honest limitations

- Applying arbitrary Google *recommendations* is deliberately out of v1 (blast radius too fuzzy for a clean preview).
- Production accounts need Google's Basic Access approval on your developer token; test accounts work instantly.
- A non-serving test account can't prove delivery metrics — reads were validated for shape, writes for acceptance.

Not affiliated with Google; "Google Ads" is used descriptively. Proprietary license, license-gated install.
