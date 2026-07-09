"""
validate_sheet.py
Check the classification sheet is complete and clean before tallying:
 - every row has evadability + breadth filled
 - controlled columns use only allowed lowercase values
 - evasion_types is filled iff evadability is full/partial (empty for none/broken)
 - flag any stray whitespace / capitalisation
"""
from pathlib import Path
import pandas as pd

DATA = Path(__file__).resolve().parent.parent / "data"
df = pd.read_csv(DATA / "classification_sheet.csv").fillna("")

EVAD = {"full", "partial", "none", "broken"}
BREADTH = {"broad", "moderate", "narrow"}
TYPES = {"insertion", "substitution", "omission", "reordering", "recoding"}

problems = []
for i, r in df.iterrows():
    tag = f"row {i} ({r['title'][:40]})"
    ev, br = r["evadability"], r["breadth"]

    if ev.strip() != ev or br.strip() != br:
        problems.append(f"{tag}: stray whitespace in a controlled column")
    ev_s, br_s = ev.strip(), br.strip()

    if ev_s == "":
        problems.append(f"{tag}: evadability BLANK")
    elif ev_s not in EVAD:
        problems.append(f"{tag}: bad evadability '{ev}' (allowed: {EVAD})")

    if br_s == "":
        problems.append(f"{tag}: breadth BLANK")
    elif br_s not in BREADTH:
        problems.append(f"{tag}: bad breadth '{br}' (allowed: {BREADTH})")

    ets = [t.strip() for t in str(r["evasion_types"]).split(";") if t.strip()]
    bad = [t for t in ets if t not in TYPES]
    if bad:
        problems.append(f"{tag}: bad evasion_type(s) {bad} (allowed: {TYPES})")
    if ev_s in {"full", "partial"} and not ets:
        problems.append(f"{tag}: {ev_s} but evasion_types EMPTY")
    if ev_s in {"none", "broken"} and ets:
        problems.append(f"{tag}: {ev_s} should have NO evasion_types, has {ets}")

print(f"Rows: {len(df)}  (expected 66)")
if problems:
    print(f"\n{len(problems)} PROBLEM(S):")
    for p in problems:
        print("  -", p)
else:
    print("\nAll rows complete and clean. Ready to tally.")