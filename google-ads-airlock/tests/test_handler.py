"""
Offline contract tests for the Google Ads Airlock handler.

No network, no credentials: the transport layer (_request / _get / _oauth_access_token)
is monkeypatched so every command runs against captured fixtures. What this PROVES is
the part a live account can't teach us cheaply — that each command targets the right
v25 endpoint, builds the right GAQL / :mutate payload (snake_case updateMask, ~ in
composite resource names, validateOnly wiring), and shapes its result correctly.

What it deliberately does NOT prove: that Google accepts these payloads on a real
account (field names, permissions, enum values). That needs the free test-account
round-trip — this suite is the gate you run BEFORE spending that round-trip.

Run: python3 -m pytest tests/test_handler.py -q   (or: python3 tests/test_handler.py)
"""

import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "handlers"))
import handler as H

# --- test harness: capture the network layer -------------------------------

_CALLS = {"request": [], "get": []}
_NEXT_RESULT = {"value": {"results": []}}


def _fake_request(path, body):
    _CALLS["request"].append({"path": path, "body": body})
    return _NEXT_RESULT["value"]


def _fake_get(path):
    _CALLS["get"].append({"path": path})
    return _NEXT_RESULT["value"]


def _install():
    H._request = _fake_request
    H._get = _fake_get
    H._oauth_access_token = lambda force_refresh=False: "fake-token"


def _reset(result=None):
    _CALLS["request"].clear()
    _CALLS["get"].clear()
    _NEXT_RESULT["value"] = result if result is not None else {"results": []}


def _last_request():
    assert _CALLS["request"], "expected a _request call, got none"
    return _CALLS["request"][-1]


# --- assertions -------------------------------------------------------------

_PASS = []
_FAIL = []


def check(name, cond, detail=""):
    (_PASS if cond else _FAIL).append(name)
    mark = "ok  " if cond else "FAIL"
    line = f"  [{mark}] {name}"
    if not cond and detail:
        line += f"\n         -> {detail}"
    print(line)


# --- pure helpers -----------------------------------------------------------

def test_helpers():
    print("helpers")
    check("digits strips dashes", H._digits("123-456-7890") == "1234567890")
    check("micros->units", H._to_units(50_000_000) == 50.0)
    check("units->micros", H._to_micros(2.5) == 2_500_000)
    check("micros roundtrip", H._to_units(H._to_micros(7.5)) == 7.5)
    check("composite resource uses ~",
          H._res("123", "adGroupCriteria", 55, 999) == "customers/123/adGroupCriteria/55~999")
    check("single resource uses /",
          H._res("1-2-3", "campaigns", 7) == "customers/123/campaigns/7")
    check("flag parses truthy strings", H._flag({"v": "true"}, "v") is True)
    check("flag parses falsey", H._flag({"v": "no"}, "v") is False)
    # redaction: a secret in the env must not survive into an error string
    import os
    os.environ["GOOGLE_ADS_DEVELOPER_TOKEN"] = "SUPERSECRETDEVTOKEN"
    red = H._redact("boom SUPERSECRETDEVTOKEN boom")
    check("redacts developer token", "SUPERSECRETDEVTOKEN" not in red, red)


# --- dispatch table ---------------------------------------------------------

def test_dispatch_table():
    print("dispatch table")
    lh = H.LOCAL_HANDLERS
    reads = 22
    writes = 18
    check(f"has {reads+writes} handlers", len(lh) == reads + writes, f"got {len(lh)}")
    check("all handlers callable", all(callable(f) for f in lh.values()))
    # a spot-check that the id maps to a function of the same name
    check("id maps to same-named fn",
          all(f.__name__ == cid for cid, f in lh.items()),
          str([cid for cid, f in lh.items() if f.__name__ != cid]))


# --- reads: GAQL shape ------------------------------------------------------

def test_reads():
    print("reads")
    _install()

    _reset({"results": [{"campaign": {"id": "1", "name": "C", "status": "ENABLED",
                                      "advertisingChannelType": "SEARCH",
                                      "biddingStrategyType": "MANUAL_CPC"}}]})
    out = H.list_campaigns({"account": "123-456-7890"}, {})
    req = _last_request()
    check("list_campaigns hits googleAds:search",
          req["path"] == "customers/1234567890/googleAds:search", req["path"])
    check("list_campaigns query is a SELECT",
          req["body"]["query"].lstrip().upper().startswith("SELECT"))
    check("list_campaigns normalizes row", out["campaigns"][0]["channel"] == "SEARCH")

    _reset({"results": [{"metrics": {"costMicros": "12000000"}}]})
    out = H.get_account_spend_today({"account": "123"}, {})
    check("spend_today DURING TODAY", "DURING TODAY" in _last_request()["body"]["query"])
    check("spend_today converts micros", out["spend"] == 12.0, str(out))

    _reset({"results": []})
    H.get_change_history({"account": "123", "days": 14, "limit": 50}, {})
    q = _last_request()["body"]["query"]
    check("change_history has LIMIT", "LIMIT 50" in q, q)
    check("change_history bounds date", "change_event.change_date_time" in q)

    _reset({"results": []})
    H.list_keywords({"account": "123", "ad_group": "77"}, {})
    q = _last_request()["body"]["query"]
    check("keywords enum is quoted", "= 'KEYWORD'" in q, q)
    check("keywords filters negative=false", "negative = false" in q)

    # search_gaql must refuse a non-SELECT (no mutation through the read hatch)
    _reset({"results": []})
    refused = False
    try:
        H.search_gaql({"account": "123", "query": "UPDATE campaign SET x=1"}, {})
    except H.GAdsError:
        refused = True
    check("search_gaql refuses non-SELECT", refused)

    _reset({"results": []})
    H.get_search_terms({"account": "123"}, {})
    q = _last_request()["body"]["query"]
    check("search_terms hits search_term_view", "FROM search_term_view" in q, q)
    check("search_terms bounds by date", "segments.date" in q)


def test_safety_reads():
    print("safety reads")
    _install()
    _reset({"resourceNames": ["customers/111", "customers/222"]})
    out = H.list_accessible_customers({}, {})
    check("accessible uses listAccessibleCustomers endpoint",
          _CALLS["get"][-1]["path"] == "customers:listAccessibleCustomers")
    check("accessible extracts ids", out["customer_ids"] == ["111", "222"], str(out))

    _reset({"results": [{"customer": {"id": "123", "currencyCode": "BRL",
                                      "timeZone": "America/Recife", "testAccount": True}}]})
    out = H.get_account_metadata({"account": "123"}, {})
    check("metadata reports currency", out["currency"] == "BRL")
    check("metadata flags test account", out["test_account"] is True and "TEST" in out["note"])

    _reset({"results": [{"campaign": {"id": "1", "name": "A", "status": "ENABLED"}},
                        {"campaign": {"id": "2", "name": "B", "status": "PAUSED"}}]})
    out = H.list_budget_campaigns({"account": "123", "budget_id": "9"}, {})
    check("budget_campaigns detects sharing", out["shared"] is True and out["campaign_count"] == 2)


# --- writes: :mutate payloads ----------------------------------------------

def test_writes():
    print("writes")
    _install()

    # create_budget: creates a non-shared budget with amountMicros
    _reset({"results": [{"resourceName": "customers/123/campaignBudgets/9"}]})
    out = H.create_budget({"account": "123", "amount": 25.0}, {})
    op = _last_request()["body"]["operations"][0]["create"]
    check("create_budget amountMicros", op["amountMicros"] == 25000000, str(op))
    check("create_budget not shared", op["explicitlyShared"] is False)

    # create_campaign carries the now-required fields (EU political + networkSettings)
    _reset({"results": [{"resourceName": "customers/123/campaigns/5"}]})
    H.create_campaign({"account": "123", "name": "C",
                       "budget_resource": "customers/123/campaignBudgets/9"}, {})
    op = _last_request()["body"]["operations"][0]["create"]
    check("create_campaign declares EU political",
          op.get("containsEuPoliticalAdvertising") == "DOES_NOT_CONTAIN_EU_POLITICAL_ADVERTISING")
    check("create_campaign has networkSettings", "networkSettings" in op)

    # create_ad_group: under a campaign, SEARCH_STANDARD
    _reset({"results": [{"resourceName": "customers/123/adGroups/77"}]})
    op = None
    H.create_ad_group({"account": "123", "campaign": "5", "name": "AG"}, {})
    op = _last_request()["body"]["operations"][0]["create"]
    check("create_ad_group binds campaign",
          op["campaign"] == "customers/123/campaigns/5", str(op))
    check("create_ad_group type SEARCH_STANDARD", op["type"] == "SEARCH_STANDARD")

    # set_budget: reads current budget, then updates amount_micros (snake_case mask)
    _reset({"results": [{"campaignBudget": {"resourceName": "customers/123/campaignBudgets/9",
                                            "amountMicros": "10000000",
                                            "explicitlyShared": False}}]})
    out = H.set_budget({"account": "123", "campaign": "1", "amount_micros": 50000000}, {})
    req = _last_request()
    op = req["body"]["operations"][0]
    check("set_budget hits campaignBudgets:mutate",
          req["path"] == "customers/123/campaignBudgets:mutate", req["path"])
    check("set_budget updateMask is snake_case amount_micros",
          op["updateMask"] == "amount_micros", str(op))
    check("set_budget sends new amountMicros",
          op["update"]["amountMicros"] == 50000000, str(op))
    check("set_budget reports OLD->NEW", out["old_daily"] == 10.0 and out["new_daily"] == 50.0)
    check("set_budget changed=True on execute", out["changed"] is True)

    # validate_only must NOT change and must set validateOnly at top level
    _reset({"results": [{"campaignBudget": {"resourceName": "customers/123/campaignBudgets/9",
                                            "amountMicros": "10000000",
                                            "explicitlyShared": True}}]})
    out = H.set_budget({"account": "123", "campaign": "1", "amount_micros": 50000000,
                        "validate_only": True}, {})
    check("preview sets validateOnly=true", _last_request()["body"]["validateOnly"] is True)
    check("preview reports changed=False", out["changed"] is False and out["preview"] is True)
    check("shared budget raises a warning", out.get("warning") is not None)

    # status writes
    _reset({"results": [{}]})
    H.pause_campaign({"account": "123", "campaign": "5"}, {})
    op = _last_request()["body"]["operations"][0]
    check("pause_campaign sets status PAUSED + mask",
          op["update"]["status"] == "PAUSED" and op["updateMask"] == "status", str(op))
    check("pause_campaign resource name",
          op["update"]["resourceName"] == "customers/123/campaigns/5")

    # bid strategy: snake_case mask, camelCase body key
    _reset({"results": [{"campaign": {"resourceName": "customers/123/campaigns/5",
                                      "biddingStrategyType": "MANUAL_CPC"}}]})
    H.set_bid_strategy({"account": "123", "campaign": "5",
                        "strategy": "maximize_conversions"}, {})
    op = _last_request()["body"]["operations"][0]
    check("bid_strategy updateMask snake_case",
          op["updateMask"] == "maximize_conversions", str(op))
    check("bid_strategy body camelCase key",
          "maximizeConversions" in op["update"], str(op))

    # ad-group bid
    _reset({"results": [{}]})
    H.set_ad_group_bid({"account": "123", "ad_group": "77", "cpc_bid_micros": 1500000}, {})
    op = _last_request()["body"]["operations"][0]
    check("ad_group_bid mask cpc_bid_micros", op["updateMask"] == "cpc_bid_micros")
    check("ad_group_bid value", op["update"]["cpcBidMicros"] == 1500000)

    # add keywords: keyword sits directly on the criterion
    _reset({"results": [{}]})
    H.add_keywords({"account": "123", "ad_group": "77",
                    "keywords": ["mars cruise", "moon trip"], "match_type": "exact"}, {})
    req = _last_request()
    check("add_keywords hits adGroupCriteria:mutate",
          req["path"] == "customers/123/adGroupCriteria:mutate")
    check("add_keywords one op per keyword", len(req["body"]["operations"]) == 2)
    op0 = req["body"]["operations"][0]["create"]
    check("keyword directly on criterion", op0["keyword"]["text"] == "mars cruise")
    check("match_type upcased", op0["keyword"]["matchType"] == "EXACT")

    # remove keywords: composite resource name with ~
    _reset({"results": [{}]})
    H.remove_keywords({"account": "123", "ad_group": "77", "criterion_ids": ["999"]}, {})
    op = _last_request()["body"]["operations"][0]
    check("remove_keywords uses ~ composite",
          op["remove"] == "customers/123/adGroupCriteria/77~999", str(op))

    # negatives: negative=true, no status/bid
    _reset({"results": [{}]})
    H.add_negative_keywords({"account": "123", "ad_group": "77", "keywords": ["free"]}, {})
    op = _last_request()["body"]["operations"][0]["create"]
    check("negative flag set", op.get("negative") is True)
    check("negative has no status", "status" not in op)

    # create ad: RSA with finalUrls sibling of responsiveSearchAd inside ad
    _reset({"results": [{}]})
    H.create_ad({"account": "123", "ad_group": "77",
                 "headlines": ["H1", "H2", "H3"], "descriptions": ["D1", "D2"],
                 "final_urls": ["https://example.com"]}, {})
    op = _last_request()["body"]["operations"][0]["create"]
    check("create_ad default status PAUSED", op["status"] == "PAUSED")
    check("finalUrls sibling of responsiveSearchAd",
          "finalUrls" in op["ad"] and "responsiveSearchAd" in op["ad"], str(op["ad"].keys()))
    check("RSA headlines are {text:..}",
          op["ad"]["responsiveSearchAd"]["headlines"][0] == {"text": "H1"})

    # pause ad: composite adGroupAds/~ resource
    _reset({"results": [{}]})
    H.pause_ad({"account": "123", "ad_group": "77", "ad": "42"}, {})
    op = _last_request()["body"]["operations"][0]
    check("pause_ad composite resource",
          op["update"]["resourceName"] == "customers/123/adGroupAds/77~42", str(op))

    # create campaign: paused Search, needs a budget
    _reset({"results": [{}]})
    H.create_campaign({"account": "123", "name": "New", "budget_id": "9"}, {})
    op = _last_request()["body"]["operations"][0]["create"]
    check("create_campaign is PAUSED SEARCH",
          op["status"] == "PAUSED" and op["advertisingChannelType"] == "SEARCH")
    check("create_campaign binds budget resource",
          op["campaignBudget"] == "customers/123/campaignBudgets/9")
    # and refuses without a budget
    _reset({"results": [{}]})
    refused = False
    try:
        H.create_campaign({"account": "123", "name": "X"}, {})
    except H.GAdsError:
        refused = True
    check("create_campaign refuses without budget", refused)

    # remove_ad: REMOVE op with the composite adGroupAds/~ resource
    _reset({"results": [{}]})
    H.remove_ad({"account": "123", "ad_group": "77", "ad": "42"}, {})
    op = _last_request()["body"]["operations"][0]
    check("remove_ad uses REMOVE on composite resource",
          op.get("remove") == "customers/123/adGroupAds/77~42", str(op))

    # add asset: text asset carries type
    _reset({"results": [{}]})
    H.add_asset({"account": "123", "text": "My headline", "name": "hl"}, {})
    op = _last_request()["body"]["operations"][0]["create"]
    check("add_asset type=TEXT", op.get("type") == "TEXT")
    check("add_asset textAsset.text", op["textAsset"]["text"] == "My headline")


def main():
    for t in (test_helpers, test_dispatch_table, test_reads, test_safety_reads, test_writes):
        t()
    total = len(_PASS) + len(_FAIL)
    print(f"\n{len(_PASS)}/{total} passed")
    if _FAIL:
        print("FAILED:", ", ".join(_FAIL))
        sys.exit(1)
    print("all green")


if __name__ == "__main__":
    main()
