"""
parse_rules.py
Walks the pinned SigmaHQ repo, finds every rule tagged with the three target
persistence techniques, extracts key metadata, and writes a CSV.

    T1547.001 - Registry Run Keys / Startup Folder
    T1543.003 - Windows Service
    T1136.001 - Local Account Creation
"""

from pathlib import Path
import yaml
import pandas as pd

# Paths are resolved relative to this script, so it runs from anywhere
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SIGMA_DIR = PROJECT_ROOT / "sigma-repo"
DATA_DIR = PROJECT_ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)

# Sigma tags are lowercase; map the tag to a clean technique label
TARGET_TAGS = {
    "attack.t1547.001": "T1547.001",
    "attack.t1543.003": "T1543.003",
    "attack.t1136.001": "T1136.001",
}
PARENT_TAGS = {"attack.t1547", "attack.t1543", "attack.t1136"}


def get_detection_fields(detection):
    """Collect the field names a rule matches on (e.g. TargetObject, ImagePath)."""
    fields = set()
    if not isinstance(detection, dict):
        return fields
    for key, block in detection.items():
        if key == "condition":
            continue
        blocks = block if isinstance(block, list) else [block]
        for b in blocks:
            if isinstance(b, dict):
                for field in b.keys():
                    fields.add(str(field).split("|")[0])  # strip |modifiers
    return fields


matched = []
parent_only = []
parse_errors = 0

for path in SIGMA_DIR.rglob("*.yml"):
    try:
        with open(path, "r", encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))
    except Exception:
        parse_errors += 1
        continue

    for rule in docs:
        if not isinstance(rule, dict):
            continue
        tags = [str(t).lower() for t in (rule.get("tags") or [])]
        hits = sorted({TARGET_TAGS[t] for t in tags if t in TARGET_TAGS})
        rel_path = path.relative_to(SIGMA_DIR).as_posix()

        if hits:
            ls = rule.get("logsource") or {}
            fields = sorted(get_detection_fields(rule.get("detection") or {}))
            matched.append({
                "technique": ";".join(hits),
                "title": rule.get("title", ""),
                "rule_id": rule.get("id", ""),
                "status": rule.get("status", ""),
                "level": rule.get("level", ""),
                "logsource_category": ls.get("category", ""),
                "logsource_product": ls.get("product", ""),
                "logsource_service": ls.get("service", ""),
                "detection_fields": ";".join(fields),
                "collection": rel_path.split("/")[0],
                "file_path": rel_path,
                "tags": ";".join(tags),
            })
        elif any(t in PARENT_TAGS for t in tags):
            parent_only.append({
                "title": rule.get("title", ""),
                "tags": ";".join(t for t in tags if t.startswith("attack.t")),
                "file_path": rel_path,
            })

df = pd.DataFrame(matched)
df.to_csv(DATA_DIR / "corpus_raw.csv", index=False, encoding="utf-8")
pd.DataFrame(parent_only).to_csv(DATA_DIR / "parent_tagged_review.csv",
                                 index=False, encoding="utf-8")

print(f"YAML files that failed to parse: {parse_errors}")
print(f"Matched rules (exact sub-technique tag): {len(df)}")
if len(df):
    print("\nPer technique:")
    print(df["technique"].value_counts().to_string())
    print("\nPer source collection:")
    print(df["collection"].value_counts().to_string())
print(f"\nParent-only tagged rules (for manual review): {len(parent_only)}")
print("\nWrote data/corpus_raw.csv and data/parent_tagged_review.csv")