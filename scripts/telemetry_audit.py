"""
telemetry_audit.py
For each rule in the final corpus, map it to the Windows event it depends on,
the telemetry source, what the lab must capture it, and whether the planned
lab can produce it. Tally the result - this is the Week-4 go/no-go gate.
"""
from pathlib import Path
import yaml
import pandas as pd

PROJECT = Path(__file__).resolve().parent.parent
SIGMA = PROJECT / "sigma-repo"
DATA = PROJECT / "data"

MAP = {
    "registry":        ("Sysmon 12/13/14", "Sysmon (registry)", "Sysmon registry config + exclusion fix"),
    "file_event":      ("Sysmon 11",       "Sysmon (file)",     "Sysmon FileCreate config"),
    "service_install": ("System 7045",     "System log (SCM)",  "built-in (System log)"),
}
SECURITY = {
    "T1136.001": ("Security 4720", "Security log", "audit policy: User Account Management"),
    "T1543.003": ("Security 4697", "Security log", "audit policy: Security System Extension"),
}


def extract_event_ids(rel_path):
    """Pull any explicit EventID/EventCode values from a rule's detection."""
    ids = set()
    with open(SIGMA / rel_path, "r", encoding="utf-8") as f:
        rule = next(d for d in yaml.safe_load_all(f) if isinstance(d, dict))

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if str(k).split("|")[0] in ("EventID", "EventCode"):
                    for x in (v if isinstance(v, list) else [v]):
                        ids.add(str(x))
                else:
                    walk(v)
        elif isinstance(o, list):
            for x in o:
                walk(x)

    walk(rule.get("detection") or {})
    return ";".join(sorted(ids))


df = pd.read_csv(DATA / "corpus_final.csv").fillna("(none)")

rows = []
for _, r in df.iterrows():
    ec = r["event_class"]
    if ec == "security_log":
        eid, source, req = SECURITY.get(r["technique"], ("Security (other)", "Security log", "audit policy"))
    else:
        eid, source, req = MAP.get(ec, ("(unknown)", "(unknown)", "(unknown)"))
    rows.append({
        "technique": r["technique"], "title": r["title"], "event_class": ec,
        "expected_event": eid, "explicit_event_ids": extract_event_ids(r["file_path"]),
        "telemetry_source": source, "lab_requirement": req,
        "producible": "yes" if eid != "(unknown)" else "review",
        "file_path": r["file_path"],
    })

audit = pd.DataFrame(rows)
audit.to_csv(DATA / "telemetry_audit.csv", index=False, encoding="utf-8")

print(f"=== TELEMETRY AUDIT: {len(audit)} rules ===")
print("\nProducible:")
print(audit["producible"].value_counts().to_string())
print("\nExpected event by technique:")
print(pd.crosstab(audit["technique"], audit["expected_event"]).to_string())
print("\nTelemetry source counts:")
print(audit["telemetry_source"].value_counts().to_string())
print("\nWrote telemetry_audit.csv")