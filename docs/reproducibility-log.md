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