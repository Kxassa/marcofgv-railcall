"""Manifest<->handler conformance for the Freelancer module: every command's
schema-valid minimal `inputs` must be ACCEPTED by the handler (no KeyError).
Network/file I/O stubbed; a domain FlnError (e.g. 'File not found') is conformant."""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "handlers"))
import handler as H
MANIFEST = os.path.join(os.path.dirname(__file__), "..", "module.json")

def _dummy(spec, name):
    t = spec.get("type")
    if t == "array":
        it = (spec.get("items") or {}).get("type", "string")
        return [_dummy({"type": it}, name) for _ in range(max(1, spec.get("minItems", 1)))]
    if t == "integer": return 1
    if t == "number": return 1.0
    if t == "boolean": return True
    if spec.get("enum"): return spec["enum"][0]
    if t == "object": return {}
    # description>=100 chars for proposal bodies
    if name == "description": return "x" * 120
    return "1"

def main():
    d = json.load(open(MANIFEST))
    H._call = lambda *a, **k: {}
    if hasattr(H, "_self_id"): H._self_id = lambda *a, **k: 1
    if hasattr(H, "_upload_attachment"): H._upload_attachment = lambda *a, **k: None
    fails = []
    for c in d["commands"]:
        cid = c["id"]; fn = getattr(H, cid, None)
        assert fn, f"no handler for {cid}"
        props = c["input_schema"].get("properties", {})
        inp = {n: _dummy(props.get(n, {}), n) for n in c["input_schema"].get("required", [])}
        try:
            fn(inp, {})
        except (KeyError, IndexError) as e:
            fails.append((cid, type(e).__name__, str(e)[:60]))
        except H.FlnError:
            pass
        except Exception as e:
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
