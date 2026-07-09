# Reproducibility Log

**Thesis:** Evasion Robustness of SigmaHQ Persistence Rules

## 1. Analysis environment

| Component | Version |
|-----------|---------|
| Operating system | Microsoft Windows 11 Home Single Language |
| Git | 2.53.0.windows.1 |
| Python | 3.14.0 |
| pip | 25.2 |
| pandas | 3.0.3 |
| NumPy | 2.4.6 |
| PyYAML | 6.0.3 |

Complete dependency list pinned in `requirements.txt` (generated with `pip freeze`).

## 2. Rule corpus snapshot (frozen)

| Field | Value |
|-------|-------|
| Source repository | https://github.com/SigmaHQ/sigma |
| Commit hash | 98781da19cf60c48ce6e7f2d3ad11c9ba389191a |
| Commit date | 2026-06-11 17:23:23 +0200 |
| Date pulled | 2026-06-17 |
| Total `.yml` files at this commit | 4192 |

This commit is the frozen snapshot for the entire study. `sigma-repo` is not
updated after this point.

## 3. Change log

| Date | Entry |
|------|-------|
| 2026-06-17 | Environment set up (Python 3.14, pandas, PyYAML). SigmaHQ cloned and pinned at commit `98781da`. 4192 YAML files in repo. |
| 2026-06-17 | Corpus finalised: 66 rules (T1547.001: 34, T1543.003: 28, T1136.001: 4). Built by tag-match (113 raw) -> scope (Windows-only; drop deprecated/unsupported; set aside process-creation and PowerShell) -> manual review (added 5 parent-only in-scope rules, removed 7 driver-load BYOVD/IOC rules). |
| 2026-06-17 | Telemetry audit: all 66 rules producible -> Week-4 gate cleared at Tier 1 (all three techniques testable). Lab telemetry: Sysmon (registry 12/13/14, file 11), System log (SCM 7045), Security log + audit policy (account 4720, service 4697). |
| 2026-07-09 | Static classification complete + validated (66 rules, 0 blanks/typos). Results: 85% evadable (55/65 in-scope full; 0 partial; 10 none; 0 broken). Substitution = sole evasion type (55/55). SQ3 evadability x breadth confirms independence (5 none+narrow, 2 none+broad). |