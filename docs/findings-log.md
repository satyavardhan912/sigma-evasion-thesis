# Running Findings Log (for discussion chapter + report)

Cross-cutting observations captured during classification. These are the
qualitative findings that sit alongside the SQ1/SQ2/SQ3 numbers - not the
per-rule labels (those live in classification_sheet.csv), but the patterns,
data-quality issues, and methodological points that the discussion chapter is
built from.

## A. Mis-tagged rules (tagged persistence, actually another tactic)
Several rules carry a T1547.001/T1543.003/T1136.001 tag but detect a different
ATT&CK tactic; they touch a persistence-adjacent registry area incidentally.
Finding: SigmaHQ technique tagging is noisy for persistence - relevant to any
"coverage by technique" metric (ties to the coverage-as-metric critique thread).
- #28 Windows Event Log Access Tampering - really DEFENSE EVASION (log-access
  restriction via SDDL); tagged T1547.001 only because it writes under
  CurrentControlSet\Services.
- #2 CobaltStrike Service Install (registry) / #15 Narrator Feedback-Hub - IOC/
  exploit-artifact rules wearing a persistence tag (revisit whether these are
  "persistence detection" in spirit).
  [ADD MORE AS FOUND]

## B. Enumerated-list rules are structurally evadable
The dominant registry pattern: match a fixed LIST of autostart locations. Always
FULL by substitution - a bounded list cannot cover every ASEP in T1547.001, so
an off-list location within the same technique evades. The rule's own filter
list is evidence of its false-positive surface.
Finding (SQ1/SQ2): registry persistence rules are predominantly evadable, and
evadable for a single structural reason (location enumeration), not diverse ones.

## C. Evadable AND noisy - the SQ3 off-diagonal
Rules that are FULL (evadable) yet BROAD (high false-positive surface):
behavioural rules keyed on suspicious PATH / COMMAND / SOURCE (#16, #19, #22,
#23). Relocate/re-encode to evade (FULL), yet legit software trips them (BROAD).
Finding (SQ3): evasion-resistance and false-positive proneness are independent -
these rules are the worst of both. Also: NONE rules can be NARROW (#0, #3, #14),
the opposite corner. Confirms breadth != inverse-of-evadability.

## D. Robust rules match a true invariant
NONE is earned only when the rule matches the invariant of its specific method:
SAM \Names\ + `$` (#0), ServiceDll write (#3), Startup-folder redirect value
(#14), the specific hijack command key (#15/#28 arguable). Pattern: robustness
comes from pinning the one action the technique cannot avoid.

## E. Scoping judgment: classify against the tagged technique
Where a rule is robust under a super-narrow method definition (LSP injection,
SDDL tampering) but evadable under its broad T1547.001 tag, rated against the
tag (#27, #28). Methodological point to state explicitly in the write-up.

## F. Registry technique summary (fill after batch tally)
32 registry rules: mostly FULL (enumerated lists + IOC-tailored), NONE reserved
for true-invariant rules. [INSERT FINAL COUNTS from classification_sheet.csv]