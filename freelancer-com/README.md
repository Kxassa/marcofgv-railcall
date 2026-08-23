# Freelancer.com for RailCall

The complete [Freelancer.com](https://www.freelancer.com) API, governed. **60 commands** covering both sides of the platform — through the official API, with
every action that spends money or commits you publicly routed through
RailCall's airlock (preview → approve → execute → signed receipt).

## Why this module exists (a true story)

I run an automated bidding operation on Freelancer.com. Before this contest existed I built a human approval gate: every drafted bid queues until a person has seen the exact amount, proposal and project. That gate caught a bid in the wrong currency, an overclaiming proposal, and a credential-phishing project. RailCall's airlock is that same gate, generalized. Industry data agrees: bots that automate the submit click get banned in months; tools that draft but keep a human on the submit survive years. The airlock is exactly that boundary.


## What it does — 60 commands

**Reads (`side_effects: none`)** — browse freely, nothing fires:
`search_projects`, `get_project` (brief returned in `<UNTRUSTED_BRIEF>` tags),
`get_bids` (competitor low/high/avg), `list_my_bids`, `get_jobs`, `search_jobs`,
`list_milestones`, `get_milestone`, `get_threads`, `get_messages`,
`search_messages`, `whoami`, `get_user`, `search_freelancers`, `get_reputation`,
`get_portfolio`, `search_contests`, `get_contest`, `get_tracking`, `get_currencies`, `get_notifications` (client replied/awarded/hired), `get_balance`, `list_my_projects`, `list_milestone_requests`, `get_project_reviews`, `get_categories`, `get_countries`, `get_timezones`, `list_my_contests`, `get_my_skills`, `get_bid`.

**Writes (`side_effects: external` → airlock)** — a human approves each:
- Bid lifecycle: `place_bid`, `update_bid`, `retract_bid`, `highlight_bid`, `accept_bid`, `award_bid`, `revoke_bid`
- Milestone lifecycle: `request_milestone`, `create_milestone` (funds escrow — **moves money**), `release_milestone` (**moves money**), `request_release_milestone`, `cancel_milestone`, `accept_milestone_request`, `reject_milestone_request`, `delete_milestone_request`
- Messaging: `send_message`, `start_thread`, `send_attachment`, `mark_thread_read`
- Trust & safety: `report_project`
- Employer files: `upload_project_file`
- Reputation & profile: `post_review`, `add_skills`, `set_skills`, `remove_skills`
- Employer side: `create_project`, `create_hourly_project`
- Time tracking: `start_tracking`, `update_tracking`

The two money-moving commands (`create_milestone`, `release_milestone`) are the
hardest floor — the airlock preview shows the exact amount and recipient before
anything moves.

## Setup

1. Generate a token at [accounts.freelancer.com/settings/develop](https://accounts.freelancer.com/settings/develop) → **Generate Token** (personal, instant, free).
2. Save it in Studio → Integrations as the `freelancer` credential (`oauth_token`) — RailCall's local vault. The handler reads only `vault_get("freelancer")`, never the environment.
3. Rehearsal mode: set `base_url=https://www.freelancer-sandbox.com` in the same credential with a
   sandbox token to run the whole loop, placed bids included, against
   Freelancer's test environment. `whoami` always reports which environment
   you're in.

Smoke test right after install: `whoami` returns your user id, membership, bid
quota, review count and completion rate.

## Security posture (governance-first, as the platform expects)

- **Egress allowlist** — the handler pins the host to the Freelancer API (or its
  official sandbox) and refuses anything else before a socket opens. SSRF /
  data-exfiltration surface closed.
- **No secret logging** — the token is read from the RailCall vault, sent only in the
  request header, never printed, returned, or logged.
- **Untrusted input labelled** — client briefs and messages are wrapped in
  `<UNTRUSTED_BRIEF>` tags so a downstream agent treats them as data, not
  instructions (indirect-prompt-injection defense: spotlighting).
- **Hard timeouts + honest errors** — every call is bounded; non-200 responses
  surface the API's own message to the airlock preview.
- **Schema-guarded inputs** — every command declares constraints and
  `additionalProperties: false`, so malformed or injected params fail closed.

Stdlib-only handler (no dependencies), MIT licensed. Reads tested end-to-end
against the real API; money-touching commands follow the official API and are
gated behind the airlock by design.

## Honest limitations

- Contest **entry submission** isn't wrapped yet (different API surface; planned).
- The token grants full account access — treat it like a password. This module
  never logs it and sends it only to the Freelancer host you're configured for.

Built with LLM assistance; every read command was executed against the live API
before publishing.
