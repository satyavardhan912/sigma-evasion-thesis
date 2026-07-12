"""
select_test_subset.py
Build the Phase-3 empirical test subset from the completed classification.
Design: ALL predicted-robust (none) rules + a purposively-selected set of
predicted-evadable (full) rules covering every technique, event class, and
detection pattern. Purposive (not random) because the aim is SQ4 prediction
accuracy across the full RANGE of rule types, not population estimation.
Outputs test_subset.csv with blank columns for recording empirical evidence.
"""
from pathlib import Path
import pandas as pd

DATA = Path(__file__).resolve().parent.parent / "data"
df = pd.read_csv(DATA / "classification_sheet.csv").fillna("")

# --- All predicted-robust rules: reason = robustness mechanism ---
NONE_REASONS = {
    "Creation of a Local Hidden User Account by Registry":
        "robust: intrinsic SAM \\Names\\ path + $ marker",
    "ServiceDll Hijack":
        "robust: ServiceDll write is the invariant action",
    "Modify User Shell Folders Startup Value":
        "robust: Startup-folder redirect value is the invariant",
    "Narrator's Feedback-Hub Persistence":
        "robust: invariant hijack command key",
    "Windows Event Log Access Tampering Via Registry":
        "robust: SDDL restriction (NOTE: mis-tagged defence-evasion; optional)",
    "Startup Folder File Write":
        "robust: bare Startup-folder write (invariant event)",
    "Service Installed By Unusual Client - System":
        "robust: PID-0 install-method invariant (EID 7045)",
    "Hidden Local User Creation":
        "robust: $ suffix intrinsic to hidden account (EID 4720)",
    "Local User Creation":
        "robust: bare EID 4720 event (invariant)",
    "Service Installed By Unusual Client - Security":
        "robust: PID-0 install-method invariant (EID 4697)",
}

# --- Purposively-selected evadable rules: reason = pattern covered ---
FULL_SELECTED = {
    # registry (10) - cover enumerated-list, IOC-name, suspicious-path, command
    "CurrentVersion Autorun Keys Modification":
        "flagship Run/RunOnce enumerated-list (most-abused ASEP)",
    "CurrentVersion NT Autorun Keys Modification":
        "Winlogon Shell/Userinit enumerated-list",
    "Classes Autorun Keys Modification":
        "Classes shell-extension enumerated-list",
    "Leviathan Registry Key Activity":
        "single hardcoded value-name IOC (ntkd)",
    "WINEKEY Registry Modification":
        "single hardcoded value-name IOC (Backup Mgr)",
    "New RUN Key Pointing to Suspicious Folder":
        "suspicious-path exemplar (evadable AND noisy)",
    "Suspicious PowerShell In Registry Run Keys":
        "command-content behavioural rule",
    "Wow6432Node CurrentVersion Autorun Keys Modification":
        "32-bit Run-key variant (tests WoW redirection)",
    "Potential KamiKakaBot Activity - Winlogon Shell Persistence":
        "Winlogon Shell + command-content IOC",
    "Session Manager Autorun Keys Modification":
        "Session Manager ASEP enumerated-list (different hive)",
    # service-install (6)
    "Moriya Rootkit - System":
        "single hardcoded service-name IOC (ZzNetSvc)",
    "KrbRelayUp Service Installation":
        "single hardcoded service-name IOC (KrbSCM)",
    "CobaltStrike Service Installations - System":
        "ImagePath command-content IOC (EID 7045)",
    "Remote Access Tool Services Have Been Installed - System":
        "enumerated service-name list (RAT tools)",
    "Service Installation in Suspicious Folder":
        "suspicious ImagePath folder (AppData)",
    "Service Installation with Suspicious Folder Pattern":
        "regex length/pattern constraint (evade via longer name)",
    # file-event (3)
    "Potential Startup Shortcut Persistence Via PowerShell.EXE":
        "process-pinned (PowerShell writer) - cleanest cosmetic-process case",
    "Suspicious Startup Folder Persistence":
        "extension-list misses .lnk (evade via .lnk drop)",
    "WinRAR Creating Files in Startup Locations":
        "process-pinned CVE rule (WinRAR writer)",
    # security-log (2)
    "Suspicious Windows ANONYMOUS LOGON Local Account Created":
        "only evadable account rule (masquerade name, EID 4720)",
    "CobaltStrike Service Installations - Security":
        "command-content IOC via EID 4697 (twin of 7045 - tests consistency)",
}

# --- Sanity checks: every hard-coded title must exist and match its class ---
titles = set(df["title"])
missing = [t for t in {**NONE_REASONS, **FULL_SELECTED} if t not in titles]
if missing:
    print("WARNING - these selected titles were NOT found in the sheet:")
    for t in missing:
        print("   -", t)
    print("   (fix the title text before trusting the subset)\n")

rows = []
for _, r in df.iterrows():
    t = r["title"]
    if r["evadability"] == "none" and t in NONE_REASONS:
        reason = NONE_REASONS[t]
    elif r["evadability"] == "full" and t in FULL_SELECTED:
        reason = FULL_SELECTED[t]
    else:
        continue
    rows.append({
        "technique": r["technique"],
        "title": t,
        "event_class": r["event_class"],
        "predicted_evadability": r["evadability"],
        "predicted_evasion_types": r["evasion_types"],
        "breadth": r["breadth"],
        "selection_reason": reason,
        "detection_summary": r["detection_summary"],
        # --- blanks to fill during lab execution (Phase 3) ---
        "tp_action": "",          # command/action used for the true positive
        "baseline_fires": "",     # yes/no - does unmodified TP trigger the rule
        "evasion_used": "",       # the functionally-equivalent modification
        "evasion_evades": "",     # yes/no - does the evasion avoid detection
        "persistence_verified": "",  # yes/no - does persistence still work
        "empirical_outcome": "",  # full/partial/none/broken (observed)
        "evidence_event_id": "",  # event captured (e.g. 7045, 4720, 13)
        "notes": "",
    })

sub = pd.DataFrame(rows).sort_values(
    ["predicted_evadability", "technique", "event_class", "title"])
out = DATA / "test_subset.csv"
sub.to_csv(out, index=False, encoding="utf-8")

print(f"Selected {len(sub)} rules for empirical testing.\n")
print("By predicted evadability:")
print(sub["predicted_evadability"].value_counts().to_string())
print("\nPredicted-evadability x technique:")
print(pd.crosstab(sub["technique"], sub["predicted_evadability"]).to_string())
print("\nPredicted-evadability x event class:")
print(pd.crosstab(sub["event_class"], sub["predicted_evadability"]).to_string())
print(f"\nWrote {out}")