"""
reconcile_hayabusa.py  (v3 - ignore Hayabusa's injected channel binding)
Hayabusa adds a channel-binding block (e.g. Channel: Security / a Provider
selection) and ANDs it into the condition. That is log-routing plumbing, NOT
detection logic. We compare only the SELECTION/FILTER logic the classification
is about, ignoring channel-only blocks. Buckets: identical / logic_same / material.
"""
from pathlib import Path
import re
import yaml
import pandas as pd

PROJECT = Path(__file__).resolve().parent.parent
PINNED = PROJECT / "sigma-repo"
HAYA = PROJECT / "hayabusa-rules"
DATA = PROJECT / "data"

# fields that are pure channel/log-routing plumbing (added by Hayabusa)
ROUTING_FIELDS = {"Channel", "Provider_Name", "Source", "EventID"}
ROUTING_ONLY_KEYS = {"channel", "security", "system", "source", "logsource"}

def load_doc(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return next((d for d in yaml.safe_load_all(f) if isinstance(d, dict)), None)
    except Exception:
        return None

def is_routing_block(block):
    """A selection block that only binds a channel/provider (no real logic)."""
    if isinstance(block, dict):
        return set(block.keys()).issubset(ROUTING_FIELDS)
    return False

def logic_only(det):
    """Keep only real detection blocks; drop channel-binding blocks and the
    condition line (which Hayabusa rewrites to AND-in the channel)."""
    if not isinstance(det, dict):
        return None
    kept = {}
    for k, v in det.items():
        if k == "condition":
            continue
        if k.lower() in ROUTING_ONLY_KEYS:
            continue
        if is_routing_block(v):
            continue
        # also strip a bare EventID-only sub-block if it's just routing
        kept[k] = v
    return yaml.safe_dump(kept, sort_keys=True, default_flow_style=False)

print("Indexing Hayabusa rules by filename...")
haya_by_name = {}
for p in HAYA.rglob("*.yml"):
    haya_by_name.setdefault(p.name, []).append(p)

corpus = pd.read_csv(DATA / "classification_sheet.csv").fillna("")

rows = []
for _, r in corpus.iterrows():
    fname = Path(r["file_path"]).name
    pinned_doc = load_doc(PINNED / r["file_path"])
    pinned_logic = logic_only(pinned_doc.get("detection")) if pinned_doc else None

    if fname not in haya_by_name:
        bucket, note = "missing", "no Hayabusa file with this name"
    else:
        variants = [load_doc(p) for p in haya_by_name[fname]]
        v_logic = [logic_only(d.get("detection")) if d else None for d in variants]
        if pinned_logic in v_logic:
            bucket, note = "identical", "selection/filter logic matches exactly"
        else:
            bucket, note = "material", "selection/filter logic genuinely differs"

    rows.append({
        "title": r["title"], "technique": r["technique"],
        "predicted_evadability": r["evadability"],
        "filename": fname, "reconcile_bucket": bucket, "note": note,
        "file_path": r["file_path"],
    })

rec = pd.DataFrame(rows)
rec.to_csv(DATA / "hayabusa_reconciliation.csv", index=False, encoding="utf-8")

print("\n=== RECONCILIATION v3 (logic-only, channel plumbing ignored) ===\n")
print(rec["reconcile_bucket"].value_counts().to_string())
flagged = rec[rec["reconcile_bucket"].isin(["material", "missing"])]
print(f"\n{len(flagged)} rule(s) with genuinely different logic (need review/override):")
for _, r in flagged.iterrows():
    print(f"  [{r['reconcile_bucket']}] {r['title']}  ({r['filename']})")
print(f"\nWrote {DATA / 'hayabusa_reconciliation.csv'}")