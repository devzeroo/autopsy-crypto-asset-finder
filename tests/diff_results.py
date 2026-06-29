#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import csv, os, sys

_BASE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.environ.get("CAF_MANIFEST", os.path.join(_BASE, "expected_results.csv"))
EXPORT = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("CAF_EXPORT", "")
if not EXPORT:
    sys.exit("uso: python3 diff_results.py <export_do_autopsy.csv>\n"
             "(o CSV exportado pelo CryptoAssetReport / Autopsy)")

# ---- parse manifesto (positivos + negativos) ----
positives = []   # dict(value, rede, tipo, validacao, token, arquivo)
negatives = []   # dict(value, motivo, arquivo)
with open(MANIFEST, newline="") as f:
    r = csv.reader(f)
    rows = list(r)
mode = "pos"
for row in rows:
    if not row or not row[0].strip():
        continue
    if row[0].startswith("#"):
        mode = "neg"; continue
    if row[0] in ("arquivo",):       # cabecalhos
        continue
    if mode == "pos":
        arquivo, rede, tipo, valor, val, tok = row[0], row[1], row[2], row[3], row[4], row[5]
        positives.append(dict(value=valor, rede=rede, tipo=tipo, validacao=val,
                              token=tok, arquivo=arquivo))
    else:
        negatives.append(dict(value=row[1], motivo=row[2], arquivo=row[0]))

# ---- parse export do Autopsy ----
actual = []
with open(EXPORT, newline="") as f:
    r = csv.DictReader(f)
    for row in r:
        actual.append(dict(
            file=row["Source Name"].strip(),
            value=(row["Endereco/Valor"] or "").strip(),
            rede=(row["Rede"] or "").strip(),
            tipo=(row["Tipo de artefato"] or "").strip(),
            validacao=(row["Validacao"] or "").strip(),
            token=(row.get("Token classificado") or "").strip(),
        ))

# ---- matching por valor (multiset) ----
from collections import defaultdict
pool = defaultdict(list)
for a in actual:
    pool[a["value"]].append(a)

matched, mismatched, missing = [], [], []
for e in positives:
    cands = pool.get(e["value"])
    if not cands:
        missing.append(e); continue
    a = cands.pop(0)
    problems = []
    if a["rede"] != e["rede"]:
        problems.append("rede: esperado '%s', obtido '%s'" % (e["rede"], a["rede"]))
    if a["validacao"] != e["validacao"]:
        problems.append("validacao: esperado '%s', obtido '%s'" % (e["validacao"], a["validacao"]))
    if (e["token"] or "") != (a["token"] or ""):
        problems.append("token: esperado '%s', obtido '%s'" % (e["token"] or "-", a["token"] or "-"))
    if problems:
        mismatched.append((e, a, problems))
    else:
        matched.append((e, a))

extra = [a for v in pool.values() for a in v]

# ---- negativos: nao podem aparecer ----
actual_values = set(a["value"] for a in actual)
neg_fail = [n for n in negatives if n["value"] in actual_values]
neg_ok = [n for n in negatives if n["value"] not in actual_values]

# ---- relatorio ----
def short(v, n=24):
    return v if len(v) <= n else v[:n-3] + "..."

print("="*64)
print("RELATORIO DE AFERICAO - CryptoAssetFinder")
print("="*64)
print("Esperados (manifesto): %d positivos + %d negativos" % (len(positives), len(negatives)))
print("Export do Autopsy:     %d artifacts" % len(actual))
print("-"*64)
print("OK (valor+rede+validacao+token): %d/%d" % (len(matched), len(positives)))
print("Divergencias de classificacao:   %d" % len(mismatched))
print("Faltando (esperado, ausente):    %d" % len(missing))
print("Extras (presente, nao esperado): %d" % len(extra))
print("Negativos corretamente ausentes: %d/%d" % (len(neg_ok), len(negatives)))
print("Negativos que VAZARAM:           %d" % len(neg_fail))
print("="*64)

if mismatched:
    print("\n## DIVERGENCIAS DE CLASSIFICACAO")
    for e, a, probs in mismatched:
        print("  [%s] %s" % (e["rede"], short(e["value"], 30)))
        for p in probs: print("     - " + p)

if missing:
    print("\n## FALTANDO (esperado no manifesto, ausente no export)")
    for e in missing:
        print("  [%-16s] %-22s  %s  (%s)" % (e["rede"], e["tipo"], short(e["value"], 30), e["arquivo"].split("/")[-1]))

if extra:
    print("\n## EXTRAS (no export, fora do manifesto)")
    for a in extra:
        print("  %-22s  [%s/%s]  arquivo=%s" % (short(a["value"], 30), a["rede"], a["validacao"], a["file"]))

if neg_fail:
    print("\n## FALHA - negativos que apareceram (falso-positivo)")
    for n in neg_fail:
        print("  %s  (%s)" % (short(n["value"], 30), n["motivo"]))
else:
    print("\nNegativos: todos corretamente rejeitados. OK.")
