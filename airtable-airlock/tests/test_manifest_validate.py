#!/usr/bin/env python3
"""Every command must pass the REAL station validator with 0 rejections.

This is the check that separates "the manifest looks right" from "the station
will accept it". It loads `validate()` straight out of the installed station
(`~/.railcall/station/workbench/approval_airlock.py`) instead of reimplementing
it, because a reimplementation drifts and then agrees with itself.

Two traps this is built to avoid, both of which have produced false PASSes here:

  * an EMPTY payload passes any manifest — so the sample fills every declared
    field, and a second pass fills only the required ones;
  * building the sample by iterating `input_schema.items()` would, on a
    JSON-Schema-shaped manifest, produce `{"properties": ..., "required": ...}`
    as the payload — the instrument's artefact matching on both sides, with the
    defect cancelling out. Field names therefore come from `properties` when it
    exists, i.e. from what a real caller would actually send.

Skips (exit 0) when no station is installed, so it is safe in CI.

Run:  python3 tests/test_manifest_validate.py   (ou python3 -m pytest tests/ -q)
"""
import importlib.util
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
AIRLOCK = pathlib.Path.home() / ".railcall/station/workbench/approval_airlock.py"

if not AIRLOCK.is_file():
    print("SKIP: nenhuma station instalada em %s" % AIRLOCK)
    raise SystemExit(0)

spec = importlib.util.spec_from_file_location("approval_airlock", AIRLOCK)
airlock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(airlock)

MANIFEST = json.loads((ROOT / "module.json").read_text())
SAMPLES = {"array": ["x"], "number": 1, "object": {"k": "v"}, "string": "x", None: "x"}


def real_fields(schema):
    """The field names a real caller sends: JSON Schema -> properties, flat map -> the keys."""
    if isinstance(schema.get("properties"), dict):
        req = schema.get("required") or []
        return {k: {**v, "required": k in req} for k, v in schema["properties"].items()}
    return {k: v for k, v in schema.items() if isinstance(v, dict)}


def sample(fspec):
    return SAMPLES.get(fspec.get("type"), "x")


fail = []
print("%s v%s — %d comandos\n" % (MANIFEST["id"], MANIFEST["version"], len(MANIFEST["commands"])))
for c in MANIFEST["commands"]:
    fields = real_fields(c.get("input_schema") or {})
    for label, payload in (
            ("todos os campos", {f: sample(s) for f, s in fields.items()}),
            ("so obrigatorios", {f: sample(s) for f, s in fields.items() if s.get("required")})):
        ok, errs = airlock.validate(c, payload)
        if not ok:
            fail.append("%s (%s): %s" % (c["id"], label, "; ".join(errs)))
    print("  %-26s %-6s %-7s ok" % (c["id"], c["mode"].split("_")[0], c["risk"]))

print("\nCONTROLES QUE DEVEM REPROVAR (sem eles a medicao acima nao vale nada):")
ctl = {"id": "ctl", "input_schema": {"type": "object",
                                     "properties": {"query": {"type": "string"}},
                                     "required": ["query"]}}
ok, errs = airlock.validate(ctl, {"query": "x"})
print("  manifest em JSON Schema        -> %s" % ("PASSOU (INSTRUMENTO QUEBRADO)" if ok else errs[0]))
if ok:
    fail.append("controle A: JSON Schema passou")

c0 = MANIFEST["commands"][1]
ok, errs = airlock.validate(c0, {"base_id": []})
print("  obrigatorio recebendo []       -> %s" % ("PASSOU (QUEBRADO)" if ok else errs[0]))
if ok:
    fail.append("controle B: obrigatorio vazio passou")

ok, errs = airlock.validate(c0, {"base_id": "app1", "nao_declarado": "x"})
print("  campo nao declarado            -> %s" % ("PASSOU (QUEBRADO)" if ok else errs[0]))
if ok:
    fail.append("controle C: campo desconhecido passou")

ids = [c["id"] for c in MANIFEST["commands"]]
norm = {re.sub(r"[^A-Za-z0-9_-]", "_", i) for i in ids}
print("  cids unicos apos normalizacao MCP -> %s" % ("ok" if len(norm) == len(ids) else "COLISAO"))
if len(norm) != len(ids):
    fail.append("colisao de alias MCP entre cids")

print("\n%s" % ("FALHAS:\n - " + "\n - ".join(fail) if fail else "0 rejeicoes em %d comandos" % len(ids)))
raise SystemExit(1 if fail else 0)
