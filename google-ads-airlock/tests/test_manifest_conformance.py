"""Manifest<->handler conformance: for every command, a schema-valid minimal
`inputs` must be ACCEPTED by the handler (no KeyError). Network is stubbed, so a
domain-level GAdsError (e.g. 'not found') is fine; a KeyError means the manifest
input_schema drifted from what the handler reads. This is the check that would
have caught the v0.1.0 schema drift."""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "handlers"))
import handler as H

MANIFEST = os.path.join(os.path.dirname(__file__), "..", "module.json")

def _minimal(schema):
    props = schema.get("properties", {})
    req = list(schema.get("required", []))
    # for the "one of two" writes, also fill one optional partner so the happy path runs
    extra = {"create_campaign": ["budget_id"], "set_ad_group_bid": ["cpc_bid_micros"]}
    inp = {}
    for name in req:
        inp[name] = _dummy(props.get(name, {}), name)
    return inp, props

def _dummy(spec, name):
    t = spec.get("type")
    if t == "array":
        it = (spec.get("items") or {}).get("type", "string")
        n = max(1, spec.get("minItems", 1))
        return [_dummy({"type": it}, name) for _ in range(n)]
    if t == "integer": return 1
    if t == "number": return 1.0
    if t == "boolean": return True
    if spec.get("enum"): return spec["enum"][0]
    if name == "account": return "1234567890"
    return "1"

def main():
    d = json.load(open(MANIFEST))
    # stub network so handlers exercise input-reading, not real calls
    H._search = lambda *a, **k: []
    H._mutate = lambda *a, **k: {"results": []}
    fails = []
    for c in d["commands"]:
        cid = c["id"]; fn = H.LOCAL_HANDLERS.get(cid)
        assert fn, f"no handler for {cid}"
        inp, props = _minimal(c["input_schema"])
        for opt in {"create_campaign": ["budget_id"], "set_ad_group_bid": ["cpc_bid_micros"]}.get(cid, []):
            if opt in props: inp[opt] = _dummy(props[opt], opt)
        try:
            fn(inp, {})
        except (KeyError, IndexError) as e:
            fails.append((cid, type(e).__name__, str(e)[:60]))
        except H.GAdsError:
            pass  # clean domain error on stubbed/empty data — conformant
        except Exception as e:
            # anything else that references a missing input is also a failure signal
            if "inputs[" in str(e) or isinstance(e, TypeError):
                fails.append((cid, type(e).__name__, str(e)[:60]))
    total = len(d["commands"])
    if fails:
        print(f"CONFORMANCE FAIL: {len(fails)}/{total}")
        for f in fails: print("  ", f)
        sys.exit(1)
    print(f"CONFORMANCE PASS: {total}/{total} commands accept a schema-valid minimal input")

if __name__ == "__main__":
    main()
