"""
finalize_corpus.py
Apply the documented manual-review decisions to the novel corpus.
  REMOVE 7 driver_load rules - vulnerable-driver abuse (BYOVD, T1068) or
    known-bad driver IOCs; a distinct threat model from service-creation
    persistence, not suited to parameter-level evasion analysis.
  ADD 5 rules tagged only with the parent technique that are genuine
    Run-Key / Startup-Folder / service-installation event rules.
"""
from pathlib import Path
import yaml
import pandas as pd

PROJECT = Path(__file__).resolve().parent.parent
SIGMA = PROJECT / "sigma-repo"
DATA = PROJECT / "data"

REMOVE = {
    "rules/windows/driver_load/driver_load_win_mal_drivers.yml",
    "rules/windows/driver_load/driver_load_win_mal_drivers_names.yml",
    "rules/windows/driver_load/driver_load_win_susp_temp_use.yml",
    "rules/windows/driver_load/driver_load_win_vuln_drivers.yml",
    "rules/windows/driver_load/driver_load_win_vuln_drivers_names.yml",
    "rules/windows/driver_load/driver_load_win_vuln_hevd_driver.yml",
    "rules/windows/driver_load/driver_load_win_vuln_winring0_driver.yml",
}

ADD = {
    "rules/windows/registry/registry_event/registry_event_runkey_winekey.yml": "T1547.001",
    "rules/windows/file/file_event/file_event_win_ripzip_attack.yml": "T1547.001",
    "rules/windows/builtin/security/win_security_service_installation_by_unusal_client.yml": "T1543.003",
    "rules/windows/builtin/system/service_control_manager/win_system_krbrelayup_service_installation.yml": "T1543.003",
    "rules/windows/builtin/system/service_control_manager/win_system_service_install_sups_unusal_client.yml": "T1543.003",
}


def get_detection_fields(detection):
    fields = set()
    if isinstance(detection, dict):
        for key, block in detection.items():
            if key == "condition":
                continue
            for b in (block if isinstance(block, list) else [block]):
                if isinstance(b, dict):
                    for f in b.keys():
                        fields.add(str(f).split("|")[0])
    return fields


def event_class(cat, svc):
    if cat in ("registry_set", "registry_event"):
        return "registry"
    if cat == "file_event":
        return "file_event"
    if cat == "(none)" and svc == "system":
        return "service_install"
    if cat == "(none)" and svc == "security":
        return "security_log"
    return "other"


def parse_rule(rel_path, technique):
    with open(SIGMA / rel_path, "r", encoding="utf-8") as f:
        rule = next(d for d in yaml.safe_load_all(f) if isinstance(d, dict))
    ls = rule.get("logsource") or {}
    cat = ls.get("category") or "(none)"
    prod = ls.get("product") or "(none)"
    svc = ls.get("service") or "(none)"
    tags = [str(t).lower() for t in (rule.get("tags") or [])]
    return {
        "technique": technique, "title": rule.get("title", ""),
        "rule_id": rule.get("id", ""), "status": rule.get("status", ""),
        "level": rule.get("level", ""), "logsource_category": cat,
        "logsource_product": prod, "logsource_service": svc,
        "detection_fields": ";".join(sorted(get_detection_fields(rule.get("detection") or {}))),
        "collection": rel_path.split("/")[0], "file_path": rel_path,
        "tags": ";".join(tags), "bucket": "novel",
        "reason": "added in review (parent-only tag; genuine in-scope rule)",
        "event_class": event_class(cat, svc),
    }


novel = pd.read_csv(DATA / "corpus_novel.csv").fillna("(none)")

removed = novel[novel["file_path"].isin(REMOVE)].copy()
removed["bucket"] = "excluded"
removed["reason"] = "driver-load: BYOVD/IOC, not service-creation persistence"
kept = novel[~novel["file_path"].isin(REMOVE)].copy()

added = pd.DataFrame([parse_rule(p, t) for p, t in ADD.items()])
final = pd.concat([kept, added], ignore_index=True)

final.to_csv(DATA / "corpus_final.csv", index=False, encoding="utf-8")
removed.to_csv(DATA / "corpus_review_removed.csv", index=False, encoding="utf-8")

print(f"Started from novel corpus: {len(novel)}")
print(f"Removed (driver-load): {len(removed)}")
print(f"Added (parent-only, in-scope): {len(added)}")
print(f"\n=== FINAL CORPUS: {len(final)} rules ===")
print("\nPer technique:")
print(final["technique"].value_counts().to_string())
print("\nTechnique x event class:")
print(pd.crosstab(final["technique"], final["event_class"]).to_string())
print("\nWrote corpus_final.csv and corpus_review_removed.csv")