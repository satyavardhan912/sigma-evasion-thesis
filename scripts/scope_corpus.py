"""
scope_corpus.py
Apply the agreed scoping rules to the raw corpus and split it into three
documented files. Filters run in priority order, so each rule lands in exactly
one bucket with a recorded reason.

Locked decisions:
  - Windows only.
  - Drop deprecated / unsupported rules.
  - Set aside process_creation and ps_script (command/script-based; overlaps
    Uetz's covered/prototyped territory).
  - Keep event-based rules: registry, service-install (EID 7045),
    security-log (EID 4720/4697), file_event, driver_load.
  - driver_load kept but tagged, for separate reporting if needed.
"""
from pathlib import Path
import pandas as pd

DATA = Path(__file__).resolve().parent.parent / "data"
df = pd.read_csv(DATA / "corpus_raw.csv").fillna("(none)")

SETASIDE = {"process_creation", "ps_script"}
DROP = {"deprecated", "unsupported"}


def event_class(row):
    cat, svc = row["logsource_category"], row["logsource_service"]
    if cat in ("registry_set", "registry_event"):
        return "registry"
    if cat == "driver_load":
        return "driver_load"
    if cat == "file_event":
        return "file_event"
    if cat == "(none)" and svc == "system":
        return "service_install"   # EID 7045
    if cat == "(none)" and svc == "security":
        return "security_log"      # EID 4720 (account) / 4697 (service)
    return "other"


def classify(row):
    if row["logsource_product"] != "windows":
        reason = ("no log source" if row["logsource_product"] == "(none)"
                  else f'non-Windows ({row["logsource_product"]})')
        return "excluded", reason
    if row["status"] in DROP or row["collection"] in DROP:
        return "excluded", f'retired ({row["status"]}/{row["collection"]})'
    if row["logsource_category"] in SETASIDE:
        label = ("process-creation (command-line, overlaps Uetz)"
                 if row["logsource_category"] == "process_creation"
                 else "ps_script (PowerShell, overlaps Uetz prototype)")
        return "set_aside", label
    return "novel", "event-based, non-command-line"


df[["bucket", "reason"]] = df.apply(classify, axis=1, result_type="expand")
df["event_class"] = df.apply(
    lambda r: event_class(r) if r["bucket"] == "novel" else "", axis=1)

novel = df[df["bucket"] == "novel"].copy()
setaside = df[df["bucket"] == "set_aside"].copy()
excluded = df[df["bucket"] == "excluded"].copy()

novel.to_csv(DATA / "corpus_novel.csv", index=False, encoding="utf-8")
setaside.to_csv(DATA / "corpus_setaside.csv", index=False, encoding="utf-8")
excluded.to_csv(DATA / "corpus_excluded.csv", index=False, encoding="utf-8")

print("=== Bucket totals ===")
print(df["bucket"].value_counts().to_string())

print(f"\n=== NOVEL CORPUS: {len(novel)} rules ===")
print("\nPer technique:")
print(novel["technique"].value_counts().to_string())
print("\nTechnique x event class:")
print(pd.crosstab(novel["technique"], novel["event_class"]).to_string())

print(f"\n=== SET ASIDE: {len(setaside)} ===")
print(setaside["reason"].value_counts().to_string())

print(f"\n=== EXCLUDED: {len(excluded)} ===")
print(excluded["reason"].value_counts().to_string())

print("\nWrote corpus_novel.csv, corpus_setaside.csv, corpus_excluded.csv")