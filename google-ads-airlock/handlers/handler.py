"""
Google Ads Airlock — RailCall handler (Google Ads API v25).

Stdlib only (urllib) against the official Google Ads REST API. RailCall dispatches a
command by calling the top-level function whose name equals the manifest command `id`;
each takes (inputs, context) and returns a JSON-serialisable dict. Credentials arrive
from the RailCall vault via vault_get("google-ads") (never os.environ; never logged;
resolved from the station's local credential vault file).

Auth — the 'google-ads' vault credential (a common first-timer trap):
  developer_token      — developer token (required on every call)
  login_customer_id    — MCC/login customer id, digits (optional; for manager access)
  and an OAuth2 access token, supplied one of two ways:
    (a) access_token   — a pre-minted Bearer token (expires ~1h), OR
    (b) refresh flow, so the module mints/rotates its own short-lived token:
        client_id, client_secret, refresh_token
The refresh path is preferred: an access token dies in an hour, so a module that only
takes (a) breaks mid-session. If both are present the static token is used until it
401s, then a refresh is attempted.

Reads run one GAQL SELECT via customers/{id}/googleAds:search (auto-paginated). Writes
call the matching *:mutate endpoint and are declared mode=write_requires_approval, so
RailCall's airlock (preview -> human approve -> execute -> signed receipt) wraps them:
each write also honours inputs["validate_only"] to drive a real dry-run PREVIEW that
mutates nothing (Google's own validateOnly), which is what the approval screen shows.

Version note: pinned to v25 (current as of 2026-08; v17..v21 are sunset). The API
version lives in ONE constant so the yearly upgrade is a one-line change.
"""

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

_API_VERSION = "v25"
_BASE = f"https://googleads.googleapis.com/{_API_VERSION}"
_OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
_TIMEOUT_S = 30
_RETRIES = 3                     # transient 429/5xx only
_PAGE_SIZE = 10000

# module-local access-token cache (refresh flow); {token, expires_at}
_TOKEN_CACHE = {}   # {cred_key: {"token","expires_at"}} — keyed so a rotation self-corrects


class GAdsError(Exception):
    """Carries the Google Ads request-id when the API returned one (for support)."""
    def __init__(self, message, request_id=None, code=None):
        super().__init__(message)
        self.request_id = request_id
        self.code = code


def _gads_creds() -> dict:
    """Google Ads credentials from the RailCall vault (Studio -> Integrations,
    provider 'google-ads'), NEVER os.environ — os.environ credential reads fail
    marketplace review. __rc_helpers__ is injected into the module namespace by
    the station loader; vault_get is the governed credential surface."""
    try:
        return __rc_helpers__["vault_get"]("google-ads") or {}  # noqa: F821 (loader-injected)
    except Exception:
        return {}


def _date(v) -> str:
    """Validate a caller-supplied date is YYYY-MM-DD before it is string-interpolated
    into GAQL — the schema advertises a string and the field is single-quoted, so
    a stray quote would otherwise be a (read-only, low-impact) GAQL-injection nit."""
    s = str(v)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        raise GAdsError(f"date must be YYYY-MM-DD, got {s!r}")
    return s


def _cred_key(cid: str, refresh: str) -> str:
    """Cache key derived from the credential identity so a credential rotation
    does not keep serving the previous identity's cached access token."""
    return hashlib.sha256(f"{cid}\x00{refresh}".encode()).hexdigest()[:16]


# --------------------------------------------------------------- helpers -----

def _digits(customer) -> str:
    """Customer ids carry no dashes in the REST path (123-456-7890 -> 1234567890)."""
    return "".join(ch for ch in str(customer or "") if ch.isdigit())


def _redact(text: str) -> str:
    """Never let a Bearer token or refresh token reach a log or an error string."""
    out = str(text)
    creds = _gads_creds()
    for field in ("access_token", "refresh_token", "client_secret", "developer_token"):
        val = str(creds.get(field) or "").strip()
        if val and len(val) >= 6 and val in out:
            out = out.replace(val, f"<google-ads:{field}:redacted>")
    return out


def _oauth_access_token(force_refresh: bool = False) -> str:
    """Return a usable OAuth2 access token.

    Prefer a static GOOGLE_ADS_ACCESS_TOKEN; if absent (or force_refresh after a 401)
    and a refresh triple is present, mint one at oauth2.googleapis.com and cache it
    until ~60s before expiry.
    """
    creds = _gads_creds()
    static = str(creds.get("access_token") or "").strip()
    if static and not force_refresh:
        return static

    cid = str(creds.get("client_id") or "").strip()
    secret = str(creds.get("client_secret") or "").strip()
    refresh = str(creds.get("refresh_token") or "").strip()
    if not (cid and secret and refresh):
        if static:                       # force_refresh asked but no way to refresh
            return static
        raise GAdsError(
            "No OAuth2 access token available. Configure the 'google-ads' credential "
            "in Studio -> Integrations: an access_token, or the refresh triple "
            "client_id / client_secret / refresh_token.")

    now = time.time()
    ck = _cred_key(cid, refresh)
    ent = _TOKEN_CACHE.get(ck)
    if not force_refresh and ent and ent["expires_at"] > now + 60:
        return ent["token"]

    data = urllib.parse.urlencode({
        "client_id": cid, "client_secret": secret,
        "refresh_token": refresh, "grant_type": "refresh_token",
    }).encode()
    req = urllib.request.Request(_OAUTH_TOKEN_URL, method="POST", data=data,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            tok = json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        raise GAdsError(_redact(f"OAuth2 refresh failed ({exc.code}): {exc.reason}"))
    except urllib.error.URLError as exc:
        raise GAdsError(f"Network error reaching oauth2.googleapis.com: {exc.reason}")
    access = tok.get("access_token")
    if not access:
        raise GAdsError("OAuth2 refresh returned no access_token.")
    _TOKEN_CACHE[ck] = {"token": access, "expires_at": now + int(tok.get("expires_in") or 3600)}
    return access


def _headers(access_token: str) -> dict:
    creds = _gads_creds()
    dev = str(creds.get("developer_token") or "").strip()
    if not dev:
        raise GAdsError("developer_token must be set in the 'google-ads' credential "
                        "(Studio -> Integrations).")
    h = {"Authorization": f"Bearer {access_token}",
         "developer-token": dev,
         "Content-Type": "application/json"}
    mcc = _digits(creds.get("login_customer_id") or "")
    if mcc:
        h["login-customer-id"] = mcc
    return h


def _parse_error(exc: "urllib.error.HTTPError"):
    """Pull a human message + request-id out of a GoogleAdsFailure body."""
    request_id = exc.headers.get("request-id") if exc.headers else None
    try:
        body = json.loads(exc.read().decode())
    except Exception:
        return (exc.reason, request_id)
    err = body.get("error") or {}
    msg = err.get("message") or exc.reason
    # GoogleAdsFailure detail (first concrete error, if present)
    for det in err.get("details") or []:
        for e in det.get("errors") or []:
            if e.get("message"):
                msg = e["message"]
                break
    return (msg, request_id)


def _request(path: str, body: dict) -> dict:
    """POST with auth, transient retry/backoff, one 401 token-refresh, redaction."""
    url = f"{_BASE}/{path}"
    payload = json.dumps(body).encode()
    refreshed = False
    for attempt in range(_RETRIES):
        access = _oauth_access_token(force_refresh=refreshed)
        req = urllib.request.Request(url, method="POST", data=payload,
                                     headers=_headers(access))
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
                return json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as exc:
            msg, rid = _parse_error(exc)
            if exc.code == 401 and not refreshed:
                refreshed = True                      # access token expired -> mint a new one
                continue
            if exc.code in (429, 500, 502, 503, 504) and attempt < _RETRIES - 1:
                time.sleep(0.5 * (2 ** attempt))      # backoff on transient/quota
                continue
            raise GAdsError(_redact(f"Google Ads API {exc.code}: {msg}"),
                            request_id=rid, code=exc.code)
        except urllib.error.URLError as exc:
            if attempt < _RETRIES - 1:
                time.sleep(0.5 * (2 ** attempt))
                continue
            raise GAdsError(f"Network error reaching Google Ads: {exc.reason}")
    raise GAdsError("Google Ads API: exhausted retries.")


def _get(path: str) -> dict:
    """GET with auth + one 401 refresh (for the non-GAQL endpoints like
    customers:listAccessibleCustomers)."""
    url = f"{_BASE}/{path}"
    refreshed = False
    for attempt in range(_RETRIES):
        access = _oauth_access_token(force_refresh=refreshed)
        req = urllib.request.Request(url, method="GET", headers=_headers(access))
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
                return json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as exc:
            msg, rid = _parse_error(exc)
            if exc.code == 401 and not refreshed:
                refreshed = True
                continue
            if exc.code in (429, 500, 502, 503, 504) and attempt < _RETRIES - 1:
                time.sleep(0.5 * (2 ** attempt))
                continue
            raise GAdsError(_redact(f"Google Ads API {exc.code}: {msg}"),
                            request_id=rid, code=exc.code)
        except urllib.error.URLError as exc:
            if attempt < _RETRIES - 1:
                time.sleep(0.5 * (2 ** attempt))
                continue
            raise GAdsError(f"Network error reaching Google Ads: {exc.reason}")
    raise GAdsError("Google Ads API: exhausted retries.")


def _search(customer, gaql: str, max_rows: int = 50000) -> list:
    """Run a GAQL SELECT via googleAds:search and return rows (auto-paginated,
    capped at max_rows to bound memory)."""
    cid = _digits(customer)
    rows, page_token = [], None
    while True:
        # NOTE: googleAds:search rejects an explicit pageSize (fixed at 10000 rows);
        # paginate with pageToken only.
        body = {"query": gaql}
        if page_token:
            body["pageToken"] = page_token
        r = _request(f"customers/{cid}/googleAds:search", body)
        rows.extend(r.get("results") or [])
        page_token = r.get("nextPageToken")
        if not page_token or len(rows) >= max_rows:
            return rows[:max_rows]


def _mutate(customer, resource: str, operations: list, inputs) -> dict:
    """POST to customers/{cid}/{resource}:mutate.

    Honours inputs['validate_only']: when true, Google validates and rolls back
    (nothing changes) — this is the dry-run that powers the airlock PREVIEW. Also
    sets partialFailure=false so a bad op fails the whole batch, not silently half.
    """
    cid = _digits(customer)
    body = {
        "operations": operations,
        "partialFailure": False,
        "validateOnly": bool(_flag(inputs, "validate_only")),
    }
    return _request(f"customers/{cid}/{resource}:mutate", body)


def _flag(inputs, key, default=False):
    v = inputs.get(key, default)
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on")
    return bool(v)


def _to_units(micros) -> float:
    """Micros -> currency units. 1_000_000 micros = 1 unit of the account currency."""
    try:
        return round(int(micros) / 1_000_000, 2)
    except (TypeError, ValueError):
        return 0.0


def _to_micros(units) -> int:
    return int(round(float(units) * 1_000_000))


def _res(customer, kind, *ids) -> str:
    """Build a resource name, e.g. customers/123/campaignBudgets/456."""
    tail = "~".join(str(i) for i in ids)
    return f"customers/{_digits(customer)}/{kind}/{tail}"


def _preview(inputs) -> bool:
    return _flag(inputs, "validate_only")


# ============================================================ READS (22) =====

def list_campaigns(inputs, context):
    rows = _search(inputs["account"],
        "SELECT campaign.id, campaign.name, campaign.status, "
        "campaign.advertising_channel_type, campaign.bidding_strategy_type "
        "FROM campaign ORDER BY campaign.id")
    out = [{
        "id": (r.get("campaign") or {}).get("id"),
        "name": (r.get("campaign") or {}).get("name"),
        "status": (r.get("campaign") or {}).get("status"),
        "channel": (r.get("campaign") or {}).get("advertisingChannelType"),
        "bidding": (r.get("campaign") or {}).get("biddingStrategyType"),
    } for r in rows]
    return {"account": inputs["account"], "count": len(out), "campaigns": out}


def get_campaign(inputs, context):
    cid = int(inputs["campaign"])
    rows = _search(inputs["account"],
        "SELECT campaign.id, campaign.name, campaign.status, "
        "campaign.advertising_channel_type, campaign.bidding_strategy_type, "
        "campaign.campaign_budget "
        f"FROM campaign WHERE campaign.id = {cid}")
    if not rows:
        raise GAdsError(f"Campaign {cid} not found on {inputs['account']}.")
    c = rows[0].get("campaign") or {}
    return {"account": inputs["account"], "campaign": c}


def get_budget(inputs, context):
    cid = int(inputs["campaign"])
    rows = _search(inputs["account"],
        "SELECT campaign_budget.id, campaign_budget.name, campaign_budget.amount_micros, "
        "campaign_budget.delivery_method, campaign_budget.explicitly_shared "
        f"FROM campaign WHERE campaign.id = {cid}")
    if not rows:
        raise GAdsError(f"Campaign {cid} not found on {inputs['account']}.")
    b = rows[0].get("campaignBudget") or {}
    return {"account": inputs["account"], "campaign_id": cid,
            "budget_id": b.get("id"), "name": b.get("name"),
            "daily": _to_units(b.get("amountMicros")),
            "amount_micros": b.get("amountMicros"),
            "delivery": b.get("deliveryMethod"),
            "shared": bool(b.get("explicitlyShared")),
            "note": ("SHARED budget — changing it affects every campaign that uses it."
                     if b.get("explicitlyShared") else "Dedicated to this campaign.")}


def get_spend(inputs, context):
    where = [f"segments.date BETWEEN '{_date(inputs['since'])}' AND '{_date(inputs['until'])}'"]
    if inputs.get("campaign"):
        where.append(f"campaign.id = {int(inputs['campaign'])}")
    gaql = ("SELECT campaign.id, campaign.name, metrics.cost_micros, metrics.impressions, "
            "metrics.clicks, metrics.conversions, metrics.conversions_value "
            "FROM campaign WHERE " + " AND ".join(where))
    out, total = [], 0
    for row in _search(inputs["account"], gaql):
        m = row.get("metrics") or {}
        cost = int(m.get("costMicros") or 0)
        total += cost
        conv = float(m.get("conversions") or 0)
        val = float(m.get("conversionsValue") or 0)
        out.append({
            "campaign_id": (row.get("campaign") or {}).get("id"),
            "campaign": (row.get("campaign") or {}).get("name"),
            "spend": _to_units(cost),
            "impressions": int(m.get("impressions") or 0),
            "clicks": int(m.get("clicks") or 0),
            "conversions": conv,
            "cpa": round(_to_units(cost) / conv, 2) if conv else None,
            "roas": round(val / _to_units(cost), 2) if cost else None,
        })
    return {"account": inputs["account"], "since": inputs["since"],
            "until": inputs["until"], "total_spend": _to_units(total), "rows": out}


def get_account_spend_today(inputs, context):
    rows = _search(inputs["account"],
        "SELECT metrics.cost_micros FROM customer WHERE segments.date DURING TODAY")
    micros = sum(int((r.get("metrics") or {}).get("costMicros") or 0) for r in rows)
    return {"account": inputs["account"], "date": "today",
            "spend_micros": micros, "spend": _to_units(micros),
            "note": "Watch this against your intended daily ceiling."}


def list_ad_groups(inputs, context):
    where = ""
    if inputs.get("campaign"):
        where = f" WHERE campaign.id = {int(inputs['campaign'])}"
    rows = _search(inputs["account"],
        "SELECT ad_group.id, ad_group.name, ad_group.status, ad_group.cpc_bid_micros, "
        "campaign.id FROM ad_group" + where + " ORDER BY ad_group.id")
    out = [{
        "id": (r.get("adGroup") or {}).get("id"),
        "name": (r.get("adGroup") or {}).get("name"),
        "status": (r.get("adGroup") or {}).get("status"),
        "cpc_bid": _to_units((r.get("adGroup") or {}).get("cpcBidMicros")),
        "campaign_id": (r.get("campaign") or {}).get("id"),
    } for r in rows]
    return {"account": inputs["account"], "count": len(out), "ad_groups": out}


def get_ad_group(inputs, context):
    ag = int(inputs["ad_group"])
    rows = _search(inputs["account"],
        "SELECT ad_group.id, ad_group.name, ad_group.status, ad_group.cpc_bid_micros, "
        "ad_group.cpm_bid_micros, campaign.id "
        f"FROM ad_group WHERE ad_group.id = {ag}")
    if not rows:
        raise GAdsError(f"Ad group {ag} not found.")
    return {"account": inputs["account"], "ad_group": rows[0].get("adGroup"),
            "campaign_id": (rows[0].get("campaign") or {}).get("id")}


def list_keywords(inputs, context):
    where = ["ad_group_criterion.type = 'KEYWORD'",
             "ad_group_criterion.negative = false"]
    if inputs.get("ad_group"):
        where.append(f"ad_group.id = {int(inputs['ad_group'])}")
    rows = _search(inputs["account"],
        "SELECT ad_group_criterion.criterion_id, ad_group_criterion.keyword.text, "
        "ad_group_criterion.keyword.match_type, ad_group_criterion.status, ad_group.id "
        "FROM ad_group_criterion WHERE " + " AND ".join(where))
    out = [{
        "criterion_id": (r.get("adGroupCriterion") or {}).get("criterionId"),
        "text": ((r.get("adGroupCriterion") or {}).get("keyword") or {}).get("text"),
        "match_type": ((r.get("adGroupCriterion") or {}).get("keyword") or {}).get("matchType"),
        "status": (r.get("adGroupCriterion") or {}).get("status"),
        "ad_group_id": (r.get("adGroup") or {}).get("id"),
    } for r in rows]
    return {"account": inputs["account"], "count": len(out), "keywords": out}


def list_negative_keywords(inputs, context):
    where = ["ad_group_criterion.type = 'KEYWORD'",
             "ad_group_criterion.negative = true"]
    if inputs.get("ad_group"):
        where.append(f"ad_group.id = {int(inputs['ad_group'])}")
    rows = _search(inputs["account"],
        "SELECT ad_group_criterion.criterion_id, ad_group_criterion.keyword.text, "
        "ad_group_criterion.keyword.match_type, ad_group.id "
        "FROM ad_group_criterion WHERE " + " AND ".join(where))
    out = [{
        "criterion_id": (r.get("adGroupCriterion") or {}).get("criterionId"),
        "text": ((r.get("adGroupCriterion") or {}).get("keyword") or {}).get("text"),
        "match_type": ((r.get("adGroupCriterion") or {}).get("keyword") or {}).get("matchType"),
        "ad_group_id": (r.get("adGroup") or {}).get("id"),
    } for r in rows]
    return {"account": inputs["account"], "count": len(out), "negatives": out}


def list_ads(inputs, context):
    where = ""
    if inputs.get("ad_group"):
        where = f" WHERE ad_group.id = {int(inputs['ad_group'])}"
    rows = _search(inputs["account"],
        "SELECT ad_group_ad.ad.id, ad_group_ad.ad.type, ad_group_ad.status, "
        "ad_group_ad.ad.final_urls, ad_group.id FROM ad_group_ad" + where)
    out = [{
        "ad_id": ((r.get("adGroupAd") or {}).get("ad") or {}).get("id"),
        "type": ((r.get("adGroupAd") or {}).get("ad") or {}).get("type"),
        "status": (r.get("adGroupAd") or {}).get("status"),
        "final_urls": ((r.get("adGroupAd") or {}).get("ad") or {}).get("finalUrls"),
        "ad_group_id": (r.get("adGroup") or {}).get("id"),
    } for r in rows]
    return {"account": inputs["account"], "count": len(out), "ads": out}


def get_ad(inputs, context):
    ad = int(inputs["ad"])
    rows = _search(inputs["account"],
        "SELECT ad_group_ad.ad.id, ad_group_ad.ad.type, ad_group_ad.status, "
        "ad_group_ad.ad.final_urls, ad_group_ad.ad.responsive_search_ad.headlines, "
        "ad_group_ad.ad.responsive_search_ad.descriptions, ad_group.id "
        f"FROM ad_group_ad WHERE ad_group_ad.ad.id = {ad}")
    if not rows:
        raise GAdsError(f"Ad {ad} not found.")
    return {"account": inputs["account"], "ad": rows[0].get("adGroupAd")}


def list_audiences(inputs, context):
    rows = _search(inputs["account"],
        "SELECT audience.id, audience.name, audience.description, audience.status "
        "FROM audience")
    out = [{"id": (r.get("audience") or {}).get("id"),
            "name": (r.get("audience") or {}).get("name"),
            "description": (r.get("audience") or {}).get("description"),
            "status": (r.get("audience") or {}).get("status")} for r in rows]
    return {"account": inputs["account"], "count": len(out), "audiences": out}


def list_conversion_actions(inputs, context):
    rows = _search(inputs["account"],
        "SELECT conversion_action.id, conversion_action.name, conversion_action.type, "
        "conversion_action.status, conversion_action.category "
        "FROM conversion_action")
    out = [{"id": (r.get("conversionAction") or {}).get("id"),
            "name": (r.get("conversionAction") or {}).get("name"),
            "type": (r.get("conversionAction") or {}).get("type"),
            "status": (r.get("conversionAction") or {}).get("status"),
            "category": (r.get("conversionAction") or {}).get("category")} for r in rows]
    return {"account": inputs["account"], "count": len(out), "conversion_actions": out}


def get_conversion_stats(inputs, context):
    # Conversions are metrics on a spend-bearing resource (campaign), optionally
    # broken down by conversion action via the segments.conversion_action segment.
    # (You cannot SELECT metrics FROM conversion_action.)
    where = [f"segments.date BETWEEN '{_date(inputs['since'])}' AND '{_date(inputs['until'])}'"]
    if inputs.get("campaign"):
        where.append(f"campaign.id = {int(inputs['campaign'])}")
    by_action = _flag(inputs, "by_action")
    seg = "segments.conversion_action_name, " if by_action else ""
    gaql = ("SELECT campaign.id, campaign.name, " + seg +
            "metrics.conversions, metrics.conversions_value "
            "FROM campaign WHERE " + " AND ".join(where))
    out = []
    for r in _search(inputs["account"], gaql):
        m = r.get("metrics") or {}
        row = {"campaign_id": (r.get("campaign") or {}).get("id"),
               "campaign": (r.get("campaign") or {}).get("name"),
               "conversions": float(m.get("conversions") or 0),
               "value": float(m.get("conversionsValue") or 0)}
        if by_action:
            row["action"] = (r.get("segments") or {}).get("conversionActionName")
        out.append(row)
    return {"account": inputs["account"], "since": inputs["since"],
            "until": inputs["until"], "by_action": by_action, "rows": out}


def list_assets(inputs, context):
    rows = _search(inputs["account"],
        "SELECT asset.id, asset.name, asset.type FROM asset")
    out = [{"id": (r.get("asset") or {}).get("id"),
            "name": (r.get("asset") or {}).get("name"),
            "type": (r.get("asset") or {}).get("type")} for r in rows]
    return {"account": inputs["account"], "count": len(out), "assets": out}


def get_recommendations(inputs, context):
    rows = _search(inputs["account"],
        "SELECT recommendation.type, recommendation.campaign, "
        "recommendation.dismissed FROM recommendation WHERE recommendation.dismissed = false")
    out = [{"type": (r.get("recommendation") or {}).get("type"),
            "campaign": (r.get("recommendation") or {}).get("campaign"),
            "resource_name": (r.get("recommendation") or {}).get("resourceName")} for r in rows]
    return {"account": inputs["account"], "count": len(out), "recommendations": out}


def get_change_history(inputs, context):
    # change_event REQUIRES a LIMIT and a bounded change_date_time window in v25.
    days = min((7, 14, 30), key=lambda d: abs(d - int(inputs.get("days", 14))))  # GAQL enum
    limit = int(inputs.get("limit", 200))
    rows = _search(inputs["account"],
        "SELECT change_event.change_date_time, change_event.user_email, "
        "change_event.client_type, change_event.change_resource_type, "
        "change_event.resource_change_operation "
        f"FROM change_event WHERE change_event.change_date_time DURING LAST_{days}_DAYS "
        f"ORDER BY change_event.change_date_time DESC LIMIT {limit}")
    out = [{"when": (r.get("changeEvent") or {}).get("changeDateTime"),
            "user": (r.get("changeEvent") or {}).get("userEmail"),
            "client": (r.get("changeEvent") or {}).get("clientType"),
            "resource": (r.get("changeEvent") or {}).get("changeResourceType"),
            "op": (r.get("changeEvent") or {}).get("resourceChangeOperation")} for r in rows]
    return {"account": inputs["account"], "count": len(out), "changes": out}


def search_gaql(inputs, context):
    """Escape hatch: run a caller-supplied SELECT. Read-only by construction —
    googleAds:search cannot mutate. Bounded by an optional row limit."""
    q = str(inputs["query"]).strip()
    if not q.lower().startswith("select"):
        raise GAdsError("search_gaql accepts SELECT queries only.")
    cap = max(1, min(int(inputs.get("max_rows", 1000)), 50000))
    rows = _search(inputs["account"], q, max_rows=cap + 1)
    return {"account": inputs["account"], "returned": min(len(rows), cap),
            "truncated": len(rows) > cap, "rows": rows[:cap]}


def get_search_terms(inputs, context):
    """The actual search queries that triggered your ads, with cost and clicks — the
    basis for spotting wasted spend and negative-keyword candidates. Read-only."""
    where = ([f"segments.date BETWEEN '{_date(inputs['since'])}' AND '{_date(inputs['until'])}'"]
             if inputs.get("since") else ["segments.date DURING LAST_30_DAYS"])
    if inputs.get("campaign"):
        where.append(f"campaign.id = {int(inputs['campaign'])}")
    gaql = ("SELECT search_term_view.search_term, search_term_view.status, "
            "metrics.clicks, metrics.impressions, metrics.cost_micros, metrics.conversions "
            "FROM search_term_view WHERE " + " AND ".join(where) +
            f" ORDER BY metrics.cost_micros DESC LIMIT {int(inputs.get('limit', 200))}")
    out = []
    for r in _search(inputs["account"], gaql):
        m = r.get("metrics") or {}
        stv = r.get("searchTermView") or {}
        out.append({"term": stv.get("searchTerm"), "status": stv.get("status"),
                    "clicks": int(m.get("clicks") or 0),
                    "impressions": int(m.get("impressions") or 0),
                    "cost": _to_units(m.get("costMicros")),
                    "conversions": float(m.get("conversions") or 0)})
    return {"account": inputs["account"], "count": len(out), "search_terms": out}


# --------------------------------------------------- safety-context reads (3) -
# Added after the v25 doc review: not more money-movers, but the context that lets
# a human approve a write knowing WHICH account, in WHAT currency, live or test,
# and WHO ELSE a shared budget touches.

def list_accessible_customers(inputs, context):
    """Which customer accounts this token can reach (non-GAQL endpoint). The first
    thing to call in an MCC: it names the accounts before any account-scoped read."""
    r = _get("customers:listAccessibleCustomers")
    names = r.get("resourceNames") or []
    return {"count": len(names), "resource_names": names,
            "customer_ids": [n.split("/")[-1] for n in names]}


def get_account_metadata(inputs, context):
    """Currency, time zone, and TEST-vs-LIVE status — so a budget number is never
    ambiguous and the airlock preview can say 'live account, in BRL'."""
    rows = _search(inputs["account"],
        "SELECT customer.id, customer.descriptive_name, customer.currency_code, "
        "customer.time_zone, customer.test_account, customer.manager, "
        "customer.auto_tagging_enabled FROM customer")
    if not rows:
        raise GAdsError(f"Account {inputs['account']} not accessible.")
    c = rows[0].get("customer") or {}
    return {"account": inputs["account"], "id": c.get("id"),
            "name": c.get("descriptiveName"), "currency": c.get("currencyCode"),
            "time_zone": c.get("timeZone"), "test_account": bool(c.get("testAccount")),
            "manager": bool(c.get("manager")),
            "auto_tagging": bool(c.get("autoTaggingEnabled")),
            "note": ("TEST account — mutations never serve or spend."
                     if c.get("testAccount") else
                     "LIVE account — writes move real money.")}


def list_budget_campaigns(inputs, context):
    """Shared-budget blast radius: every campaign attached to a given budget. Makes
    set_budget's shared-budget warning concrete before a human approves it."""
    account = inputs["account"]
    budget_id = int(inputs["budget_id"])
    budget_resource = _res(account, "campaignBudgets", budget_id)
    rows = _search(account,
        "SELECT campaign.id, campaign.name, campaign.status, campaign.campaign_budget "
        f"FROM campaign WHERE campaign.campaign_budget = '{budget_resource}'")
    camps = [{"id": (r.get("campaign") or {}).get("id"),
              "name": (r.get("campaign") or {}).get("name"),
              "status": (r.get("campaign") or {}).get("status")} for r in rows]
    return {"account": account, "budget_id": budget_id,
            "campaign_count": len(camps), "campaigns": camps,
            "shared": len(camps) > 1,
            "note": (f"{len(camps)} campaigns share this budget — a change hits ALL of them."
                     if len(camps) > 1 else "Only one campaign uses this budget.")}


# ==================================================== WRITES (16, airlocked) ==
# Every write honours inputs["validate_only"] -> Google validateOnly (dry-run for
# the airlock preview; nothing changes). On execute it mutates and reports OLD->NEW.

def set_budget(inputs, context):
    account, campaign = inputs["account"], int(inputs["campaign"])
    if inputs.get("amount_micros") is None and inputs.get("amount") is None:
        raise GAdsError("set_budget needs amount or amount_micros.")
    new_micros = int(inputs["amount_micros"]) if inputs.get("amount_micros") is not None \
        else _to_micros(inputs["amount"])
    rows = _search(account,
        "SELECT campaign_budget.resource_name, campaign_budget.amount_micros, "
        "campaign_budget.explicitly_shared "
        f"FROM campaign WHERE campaign.id = {campaign}")
    if not rows:
        raise GAdsError(f"Campaign {campaign} not found on {account}.")
    cb = rows[0].get("campaignBudget") or {}
    budget_resource = cb.get("resourceName")
    old_micros = int(cb.get("amountMicros") or 0)
    shared = bool(cb.get("explicitlyShared"))
    resp = _mutate(account, "campaignBudgets", [{
        "updateMask": "amount_micros",
        "update": {"resourceName": budget_resource, "amountMicros": new_micros},
    }], inputs)
    return {"changed": not _preview(inputs), "preview": _preview(inputs),
            "account": account, "campaign_id": campaign,
            "budget_resource": budget_resource, "shared_budget": shared,
            "old_daily": _to_units(old_micros), "new_daily": _to_units(new_micros),
            "delta_daily": _to_units(new_micros - old_micros),
            "results": resp.get("results"),
            "warning": ("This is a SHARED budget — the change affects every campaign "
                        "using it, not only this one." if shared else None)}


def create_budget(inputs, context):
    """Create a (non-shared) daily campaign budget. Prerequisite for create_campaign."""
    account = inputs["account"]
    if inputs.get("amount_micros") is None and inputs.get("amount") is None:
        raise GAdsError("create_budget needs amount or amount_micros.")
    micros = int(inputs["amount_micros"]) if inputs.get("amount_micros") is not None \
        else _to_micros(inputs["amount"])
    op = {"create": {"name": inputs.get("name", "RailCall budget"),
                     "amountMicros": micros, "deliveryMethod": "STANDARD",
                     "explicitlyShared": False}}
    resp = _mutate(account, "campaignBudgets", [op], inputs)
    rn = ((resp.get("results") or [{}])[0]).get("resourceName")
    return {"changed": not _preview(inputs), "preview": _preview(inputs),
            "account": account, "budget_resource": rn, "daily": _to_units(micros),
            "results": resp.get("results")}


def create_ad_group(inputs, context):
    """Create an ad group under a campaign (ENABLED by default). Prerequisite for
    keywords/ads."""
    account, campaign = inputs["account"], int(inputs["campaign"])
    op = {"create": {"name": inputs["name"],
                     "campaign": _res(account, "campaigns", campaign),
                     "status": str(inputs.get("status", "ENABLED")).upper(),
                     "type": "SEARCH_STANDARD"}}
    if inputs.get("cpc_bid_micros") is not None:
        op["create"]["cpcBidMicros"] = int(inputs["cpc_bid_micros"])
    resp = _mutate(account, "adGroups", [op], inputs)
    rn = ((resp.get("results") or [{}])[0]).get("resourceName")
    return {"changed": not _preview(inputs), "preview": _preview(inputs),
            "account": account, "campaign_id": campaign, "ad_group_resource": rn,
            "results": resp.get("results")}


def set_bid_strategy(inputs, context):
    account, campaign = inputs["account"], int(inputs["campaign"])
    strategy = str(inputs["strategy"]).upper()  # e.g. MANUAL_CPC, MAXIMIZE_CONVERSIONS
    rows = _search(account,
        "SELECT campaign.resource_name, campaign.bidding_strategy_type "
        f"FROM campaign WHERE campaign.id = {campaign}")
    if not rows:
        raise GAdsError(f"Campaign {campaign} not found.")
    old = (rows[0].get("campaign") or {}).get("biddingStrategyType")
    resource = (rows[0].get("campaign") or {}).get("resourceName")
    spec = _STRATEGY_FIELD.get(strategy)
    if not spec:
        raise GAdsError(f"Unsupported strategy '{strategy}'. "
                        f"Known: {', '.join(sorted(_STRATEGY_FIELD))}.")
    body, mask = spec                   # message to set, snake_case leaf mask
    update = {"resourceName": resource}
    update.update(body)
    resp = _mutate(account, "campaigns", [{"updateMask": mask, "update": update}], inputs)
    return {"changed": not _preview(inputs), "preview": _preview(inputs),
            "account": account, "campaign_id": campaign,
            "old_strategy": old, "new_strategy": strategy,
            "results": resp.get("results")}


# strategy -> (message body to set, snake_case updateMask). A oneof strategy message
# with subfields can't be masked at the parent when empty ("field with subfields"), so
# MANUAL_CPC targets a concrete leaf. Smart strategies need conversion tracking configured
# on the account; target CPA/ROAS values are a later refinement.
_STRATEGY_FIELD = {
    "MANUAL_CPC": ({"manualCpc": {"enhancedCpcEnabled": False}}, "manual_cpc.enhanced_cpc_enabled"),
    "MAXIMIZE_CONVERSIONS": ({"maximizeConversions": {}}, "maximize_conversions"),
    "MAXIMIZE_CONVERSION_VALUE": ({"maximizeConversionValue": {}}, "maximize_conversion_value"),
    "TARGET_SPEND": ({"targetSpend": {}}, "target_spend"),
}


def _set_status(account, resource_coll, resource_name, status, inputs):
    return _mutate(account, resource_coll, [{
        "updateMask": "status",
        "update": {"resourceName": resource_name, "status": status},
    }], inputs)


def pause_campaign(inputs, context):
    account, campaign = inputs["account"], int(inputs["campaign"])
    resp = _set_status(account, "campaigns", _res(account, "campaigns", campaign),
                       "PAUSED", inputs)
    return {"changed": not _preview(inputs), "preview": _preview(inputs),
            "account": account, "campaign_id": campaign, "status": "PAUSED",
            "results": resp.get("results")}


def enable_campaign(inputs, context):
    account, campaign = inputs["account"], int(inputs["campaign"])
    resp = _set_status(account, "campaigns", _res(account, "campaigns", campaign),
                       "ENABLED", inputs)
    return {"changed": not _preview(inputs), "preview": _preview(inputs),
            "account": account, "campaign_id": campaign, "status": "ENABLED",
            "results": resp.get("results")}


def create_campaign(inputs, context):
    """Create a PAUSED Search campaign bound to an existing budget. Paused-by-default
    so a fresh campaign never serves before a human enables it."""
    account = inputs["account"]
    budget_resource = inputs.get("budget_resource")
    if not budget_resource and inputs.get("budget_id"):
        budget_resource = _res(account, "campaignBudgets", int(inputs["budget_id"]))
    if not budget_resource:
        raise GAdsError("create_campaign needs budget_resource or budget_id "
                        "(create the budget first).")
    op = {"create": {
        "name": str(inputs["name"]),
        "advertisingChannelType": "SEARCH",
        "status": "PAUSED",
        "campaignBudget": budget_resource,
        "manualCpc": {},
        # Now a required declaration on campaign creation.
        "containsEuPoliticalAdvertising": "DOES_NOT_CONTAIN_EU_POLITICAL_ADVERTISING",
        # Search campaigns require networkSettings; default to Google Search only.
        "networkSettings": {
            "targetGoogleSearch": True,
            "targetSearchNetwork": False,
            "targetContentNetwork": False,
            "targetPartnerSearchNetwork": False,
        },
    }}
    resp = _mutate(account, "campaigns", [op], inputs)
    return {"changed": not _preview(inputs), "preview": _preview(inputs),
            "account": account, "name": inputs["name"], "status": "PAUSED",
            "results": resp.get("results"),
            "note": "Created PAUSED — enable it explicitly when ready."}


def set_ad_group_bid(inputs, context):
    account, ag = inputs["account"], int(inputs["ad_group"])
    if inputs.get("cpc_bid_micros") is None and inputs.get("cpc_bid") is None:
        raise GAdsError("set_ad_group_bid needs cpc_bid_micros or cpc_bid.")
    new_micros = int(inputs["cpc_bid_micros"]) if inputs.get("cpc_bid_micros") is not None \
        else _to_micros(inputs["cpc_bid"])
    resp = _mutate(account, "adGroups", [{
        "updateMask": "cpc_bid_micros",
        "update": {"resourceName": _res(account, "adGroups", ag),
                   "cpcBidMicros": new_micros},
    }], inputs)
    return {"changed": not _preview(inputs), "preview": _preview(inputs),
            "account": account, "ad_group_id": ag,
            "new_cpc_bid": _to_units(new_micros), "results": resp.get("results")}


def pause_ad_group(inputs, context):
    account, ag = inputs["account"], int(inputs["ad_group"])
    resp = _set_status(account, "adGroups", _res(account, "adGroups", ag), "PAUSED", inputs)
    return {"changed": not _preview(inputs), "preview": _preview(inputs),
            "account": account, "ad_group_id": ag, "status": "PAUSED",
            "results": resp.get("results")}


def enable_ad_group(inputs, context):
    account, ag = inputs["account"], int(inputs["ad_group"])
    resp = _set_status(account, "adGroups", _res(account, "adGroups", ag), "ENABLED", inputs)
    return {"changed": not _preview(inputs), "preview": _preview(inputs),
            "account": account, "ad_group_id": ag, "status": "ENABLED",
            "results": resp.get("results")}


def add_keywords(inputs, context):
    account, ag = inputs["account"], int(inputs["ad_group"])
    ag_resource = _res(account, "adGroups", ag)
    match = str(inputs.get("match_type", "BROAD")).upper()
    ops = [{"create": {
        "adGroup": ag_resource,
        "status": str(inputs.get("status", "ENABLED")).upper(),
        "keyword": {"text": kw, "matchType": match},
    }} for kw in inputs["keywords"]]
    resp = _mutate(account, "adGroupCriteria", ops, inputs)
    return {"changed": not _preview(inputs), "preview": _preview(inputs),
            "account": account, "ad_group_id": ag, "added": len(ops),
            "match_type": match, "results": resp.get("results")}


def remove_keywords(inputs, context):
    account = inputs["account"]
    ag = int(inputs["ad_group"])
    ops = [{"remove": _res(account, "adGroupCriteria", ag, cid)}
           for cid in inputs["criterion_ids"]]
    resp = _mutate(account, "adGroupCriteria", ops, inputs)
    return {"changed": not _preview(inputs), "preview": _preview(inputs),
            "account": account, "ad_group_id": ag, "removed": len(ops),
            "results": resp.get("results")}


def add_negative_keywords(inputs, context):
    account, ag = inputs["account"], int(inputs["ad_group"])
    ag_resource = _res(account, "adGroups", ag)
    match = str(inputs.get("match_type", "BROAD")).upper()
    ops = [{"create": {
        "adGroup": ag_resource,
        "negative": True,
        "keyword": {"text": kw, "matchType": match},
    }} for kw in inputs["keywords"]]
    resp = _mutate(account, "adGroupCriteria", ops, inputs)
    return {"changed": not _preview(inputs), "preview": _preview(inputs),
            "account": account, "ad_group_id": ag, "added": len(ops),
            "results": resp.get("results")}


def create_ad(inputs, context):
    """Create a Responsive Search Ad (PAUSED by default) in an ad group."""
    account, ag = inputs["account"], int(inputs["ad_group"])
    heads = [{"text": t} for t in inputs["headlines"]]
    descs = [{"text": t} for t in inputs["descriptions"]]
    op = {"create": {
        "adGroup": _res(account, "adGroups", ag),
        "status": str(inputs.get("status", "PAUSED")).upper(),
        "ad": {"responsiveSearchAd": {"headlines": heads, "descriptions": descs},
               "finalUrls": inputs["final_urls"]},
    }}
    resp = _mutate(account, "adGroupAds", [op], inputs)
    return {"changed": not _preview(inputs), "preview": _preview(inputs),
            "account": account, "ad_group_id": ag,
            "headlines": len(heads), "descriptions": len(descs),
            "results": resp.get("results"),
            "note": "RSA needs >=3 headlines and >=2 descriptions to serve."}


def pause_ad(inputs, context):
    account, ag, ad = inputs["account"], int(inputs["ad_group"]), int(inputs["ad"])
    resp = _set_status(account, "adGroupAds", _res(account, "adGroupAds", ag, ad),
                       "PAUSED", inputs)
    return {"changed": not _preview(inputs), "preview": _preview(inputs),
            "account": account, "ad_group_id": ag, "ad_id": ad, "status": "PAUSED",
            "results": resp.get("results")}


def enable_ad(inputs, context):
    account, ag, ad = inputs["account"], int(inputs["ad_group"]), int(inputs["ad"])
    resp = _set_status(account, "adGroupAds", _res(account, "adGroupAds", ag, ad),
                       "ENABLED", inputs)
    return {"changed": not _preview(inputs), "preview": _preview(inputs),
            "account": account, "ad_group_id": ag, "ad_id": ad, "status": "ENABLED",
            "results": resp.get("results")}


def remove_ad(inputs, context):
    """Permanently remove an ad from its ad group — the counterpart to create_ad
    (pause_ad only stops it serving; this deletes it)."""
    account, ag, ad = inputs["account"], int(inputs["ad_group"]), int(inputs["ad"])
    resp = _mutate(account, "adGroupAds",
                   [{"remove": _res(account, "adGroupAds", ag, ad)}], inputs)
    return {"changed": not _preview(inputs), "preview": _preview(inputs),
            "account": account, "ad_group_id": ag, "ad_id": ad,
            "results": resp.get("results")}


def add_asset(inputs, context):
    """Create a TEXT asset (the safe, common case). type-specific assets can follow."""
    account = inputs["account"]
    op = {"create": {"name": inputs.get("name"), "type": "TEXT",
                     "textAsset": {"text": inputs["text"]}}}
    resp = _mutate(account, "assets", [op], inputs)
    return {"changed": not _preview(inputs), "preview": _preview(inputs),
            "account": account, "results": resp.get("results")}


# ------------------------------------------------------------ dispatch table -
# RailCall calls the function whose name == command id; this table is a self-check
# that every manifest command has a handler (see the __main__ smoke test).

LOCAL_HANDLERS = {
    # reads
    "list_campaigns": list_campaigns, "get_campaign": get_campaign,
    "get_budget": get_budget, "get_spend": get_spend,
    "get_account_spend_today": get_account_spend_today,
    "list_ad_groups": list_ad_groups, "get_ad_group": get_ad_group,
    "list_keywords": list_keywords, "list_negative_keywords": list_negative_keywords,
    "list_ads": list_ads, "get_ad": get_ad, "list_audiences": list_audiences,
    "list_conversion_actions": list_conversion_actions,
    "get_conversion_stats": get_conversion_stats, "list_assets": list_assets,
    "get_recommendations": get_recommendations, "get_change_history": get_change_history,
    "search_gaql": search_gaql, "get_search_terms": get_search_terms,
    # safety-context reads (added after v25 doc review)
    "list_accessible_customers": list_accessible_customers,
    "get_account_metadata": get_account_metadata,
    "list_budget_campaigns": list_budget_campaigns,
    # writes
    "create_budget": create_budget, "create_ad_group": create_ad_group,
    "set_budget": set_budget, "set_bid_strategy": set_bid_strategy,
    "pause_campaign": pause_campaign, "enable_campaign": enable_campaign,
    "create_campaign": create_campaign, "set_ad_group_bid": set_ad_group_bid,
    "pause_ad_group": pause_ad_group, "enable_ad_group": enable_ad_group,
    "add_keywords": add_keywords, "remove_keywords": remove_keywords,
    "add_negative_keywords": add_negative_keywords, "create_ad": create_ad,
    "pause_ad": pause_ad, "enable_ad": enable_ad, "remove_ad": remove_ad,
    "add_asset": add_asset,
}
