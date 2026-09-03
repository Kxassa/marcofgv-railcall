#!/usr/bin/env python3
"""No command of ours may collide with a module already on the station.

Why this test exists — it caught a real, silent failure. The station ships
`sami666/airtable`, whose single command id is **`airtable.create_record`**. Our
manifest declared **`airtable_create_record`**. Those two ids never collide at the
`cid` layer (routes/modules.py:1344 compares ids literally, so both modules load
and everything looks installed), but the MCP tool-name layer builds an alias set
per command — `"<slug_tail>.<cid>"`, the deduped name, and the bare `cid` — and
then normalises every alias through `re.sub(r"[^A-Za-z0-9_-]", "_", ...)`. That
folds `.` into `_`, so BOTH modules claim the alias `airtable_create_record`, and
mcp_server.py resolves the tie by dropping it from the index of BOTH:

    for alias in collisions:
        index.pop(alias, None)

The comment there explains why: "Any tie-break rule is a rule an attacker can
play … Refusing to resolve is the only answer that cannot be gamed."

The symptom is the worst kind: install succeeds, the command list looks right,
and the tool simply is not there. So we renamed ours to `airtable_insert_record`
and made the check permanent — prefixing by provider is NOT sufficient, because
the collision happens after normalisation, not before.

Skips (exit 0) when no station is installed.

Run:  python3 tests/test_no_alias_collision.py
"""
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
MODULES = pathlib.Path.home() / ".railcall/station/modules"
SLUG_TAIL = "airtable-airlock"


def legal(name):
    """Mirror of mcp_server._mcp_legal_tool_name."""
    return re.sub(r"[^A-Za-z0-9_-]", "_", str(name))[:128]


def alias_set(slug_tail, cid):
    """Mirror of the alias set mcp_server builds per command."""
    base = {"%s.%s" % (slug_tail, cid), str(cid)}
    return base | {legal(a) for a in base}


def claimed_by_station():
    """alias -> (module dir, cid) for every module currently installed."""
    out = {}
    if not MODULES.is_dir():
        return None
    for d in sorted(MODULES.iterdir()):
        mj = d / "module.json"
        if not mj.is_file():
            continue
        try:
            man = json.loads(mj.read_text())
        except Exception:
            continue
        tail = str(man.get("id", "")).split("/")[-1] or d.name
        for c in man.get("commands") or []:
            for a in alias_set(tail, c.get("id")):
                out[a] = (d.name, c.get("id"))
    return out


claimed = claimed_by_station()
if claimed is None:
    print("SKIP: nenhuma station instalada em %s" % MODULES)
    raise SystemExit(0)

mine = [c["id"] for c in json.loads((ROOT / "module.json").read_text())["commands"]]
print("station: %d aliases ja reclamados | nosso modulo: %d comandos\n"
      % (len(claimed), len(mine)))

fail = []
for cid in mine:
    hits = {a: claimed[a] for a in alias_set(SLUG_TAIL, cid) if a in claimed}
    if hits:
        for a, who in hits.items():
            fail.append("%s -> alias %r ja e de %s (cid %r)" % (cid, a, who[0], who[1]))
        print("  %-26s COLIDE  %s" % (cid, hits))
    else:
        print("  %-26s ok" % cid)

# Nossos 12 tambem nao podem colidir entre si depois da normalizacao.
norm = [legal(c) for c in mine]
if len(set(norm)) != len(norm):
    fail.append("dois cids nossos colapsam no mesmo alias normalizado")

# CONTROLE: o detector tem de PEGAR uma colisao conhecida. Sem isto, um scanner
# que nunca acha nada passa por scanner correto.
print("\nCONTROLE (tem de ser detectado):")
probe = "airtable_create_record"          # o nome que tivemos de abandonar
found = {a: claimed[a] for a in alias_set(SLUG_TAIL, probe) if a in claimed}
if found:
    print("  %-26s detectado -> %s" % (probe, found))
else:
    print("  %-26s NAO detectado — o detector esta cego OU sami666/airtable nao esta\n"
          "  %-26s instalado nesta station. Confira antes de confiar no verde acima."
          % (probe, ""))
    fail.append("controle: colisao conhecida nao foi detectada")

print("\n%s" % ("FALHAS:\n - " + "\n - ".join(fail) if fail else
                "nenhuma colisao — os %d comandos sao unicos apos a normalizacao MCP" % len(mine)))
raise SystemExit(1 if fail else 0)
