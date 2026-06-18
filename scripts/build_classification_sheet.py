"""
build_classification_sheet.py
Build the static-classification worksheet: one row per rule with a readable
summary of its detection logic, the rule's description and the author's listed
false positives, and blank columns to fill per the codebook.
"""
from pathlib import Path
import yaml
import pandas as pd

PROJECT = Path(__file__).resolve().parent.parent
SIGMA = PROJECT / "sigma-repo"
DATA = PROJECT / "data"


def render_value(v):
    if isinstance(v, list):
        items = [str(x) for x in v]
        if len(items) > 8:
            return "[" + ", ".join(items[:8]) + f", ...(+{len(items) - 8})]"
        return "[" + ", ".join(items) + "]"
    return str(v)


def render_block(block):
    if isinstance(block, list):
        return " ; ".join(render_block(b) for b in block)
    if isinstance(block, dict):
        return "; ".join(f"{k}: {render_value(v)}" for k, v in block.items())
    return str(block)


def rule_fields(rel_path):
    with open(SIGMA / rel_path, "r", encoding="utf-8") as f:
        rule = next(d for d in yaml.safe_load_all(f) if isinstance(d, dict))
    det = rule.get("detection") or {}
    parts = [f"{name} {{{render_block(block)}}}"
             for name, block in det.items() if name != "condition"]
    detection = " || ".join(parts) + f"  || COND: {det.get('condition', '')}"
    desc = str(rule.get("description") or "").replace("\n", " ").strip()
    fp = rule.get("falsepositives") or []
    fp = "; ".join(str(x) for x in fp) if isinstance(fp, list) else str(fp)
    return detection, desc, fp


df = pd.read_csv(DATA / "corpus_final.csv").fillna("")
df = df.sort_values(["technique", "event_class", "title"]).reset_index(drop=True)
records = [rule_fields(p) for p in df["file_path"]]

sheet = pd.DataFrame({
    "technique": df["technique"],
    "title": df["title"],
    "event_class": df["event_class"],
    "logsource": df["logsource_category"] + "/" + df["logsource_service"],
    "description": [r[1] for r in records],
    "detection_summary": [r[0] for r in records],
    "falsepositives": [r[2] for r in records],
    "evadability": "",      # full | partial | none | broken
    "evasion_types": "",    # insertion;substitution;omission;reordering;recoding
    "breadth": "",          # broad | moderate | narrow
    "rationale": "",        # short justification
    "file_path": df["file_path"],
})

out = DATA / "classification_sheet.csv"
sheet.to_csv(out, index=False, encoding="utf-8")
print(f"Wrote {out} with {len(sheet)} rules to classify.")
print("\nAllowed values:")
print("  evadability: full | partial | none | broken")
print("  evasion_types (evadable rules only): insertion, substitution, "
      "omission, reordering, recoding (semicolon-separated)")
print("  breadth: broad | moderate | narrow")