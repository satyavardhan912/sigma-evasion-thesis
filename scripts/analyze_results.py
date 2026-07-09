"""
analyze_results.py
Tally the completed classification into SQ1/SQ2/SQ3 results.
Reports both ALL 66 and IN-SCOPE 65 (excluding the mis-tagged scheduled-task
rule, EID 4698, which detects task creation not service install).
"""
from pathlib import Path
import pandas as pd

DATA = Path(__file__).resolve().parent.parent / "data"
df = pd.read_csv(DATA / "classification_sheet.csv").fillna("")

# Mis-scoped rule: OilRig "Schedule Task Persistence - Security" (EID 4698)
OUT_OF_SCOPE_TITLE = "OilRig APT Schedule Task Persistence - Security"
scope = df[df["title"] != OUT_OF_SCOPE_TITLE].copy()

def pct(n, total):
    return f"{n} ({100*n/total:.0f}%)" if total else "0"

def section(frame, label):
    n = len(frame)
    print("\n" + "=" * 68)
    print(f"{label}  (N = {n})")
    print("=" * 68)

    # --- SQ1: evadability overall ---
    print("\nSQ1 - Evadability (overall):")
    ev = frame["evadability"].value_counts()
    for cat in ["full", "partial", "none", "broken"]:
        print(f"  {cat:8} {pct(ev.get(cat, 0), n)}")
    evadable = ev.get("full", 0) + ev.get("partial", 0)
    print(f"  --> evadable (full+partial): {pct(evadable, n)}")

    # --- SQ1: evadability x technique ---
    print("\nSQ1 - Evadability x technique:")
    ct = pd.crosstab(frame["technique"], frame["evadability"])
    for c in ["full", "partial", "none", "broken"]:
        if c not in ct.columns:
            ct[c] = 0
    ct = ct[["full", "partial", "none", "broken"]]
    ct["TOTAL"] = ct.sum(axis=1)
    print(ct.to_string())

    # --- SQ1: evadability x event_class ---
    print("\nSQ1 - Evadability x event class:")
    ce = pd.crosstab(frame["event_class"], frame["evadability"])
    for c in ["full", "partial", "none", "broken"]:
        if c not in ce.columns:
            ce[c] = 0
    print(ce[["full", "partial", "none", "broken"]].to_string())

    # --- SQ2: evasion types ---
    print("\nSQ2 - Evasion-type frequency (evadable rules):")
    types = {}
    for v in frame["evasion_types"]:
        for t in str(v).split(";"):
            t = t.strip()
            if t:
                types[t] = types.get(t, 0) + 1
    for t, c in sorted(types.items(), key=lambda x: -x[1]):
        print(f"  {t:14} {c}")

    # --- SQ3: evadability x breadth ---
    print("\nSQ3 - Evadability x breadth:")
    cb = pd.crosstab(frame["evadability"], frame["breadth"])
    for c in ["broad", "moderate", "narrow"]:
        if c not in cb.columns:
            cb[c] = 0
    print(cb[["broad", "moderate", "narrow"]].to_string())

section(df, "ALL RULES")
section(scope, "IN-SCOPE (scheduled-task rule excluded)")

print("\n" + "=" * 68)
print("Note: 'evadable' = full + partial. 'none' = robust. 'broken' = faulty.")