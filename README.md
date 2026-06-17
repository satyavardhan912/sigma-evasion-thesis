# Evasion Robustness of SigmaHQ Persistence Rules

Master's thesis. Empirical measurement of how easily public SigmaHQ detection
rules for three Windows persistence techniques can be evaded through
functionally-equivalent, parameter-level modifications:

- T1547.001 — Registry Run Keys
- T1543.003 — Windows Service Creation
- T1136.001 — Local Account Creation

Extends Uetz et al. (USENIX Security 2024). Analysis in Python (pandas, PyYAML).