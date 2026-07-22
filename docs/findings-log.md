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
  - #3, #4 New PDQDeploy Service (Client/Server) - detect a legitimate deployment
  tool's own service install, not an attack technique; tagged T1543.003. This is
  "detect a specific admin tool," not "detect persistence."

- #6 ProcessHacker Privilege Elevation - really PRIVILEGE ESCALATION / tool
  detection (service used to elevate to LocalSystem), tagged T1543.003.
- #5 (sec) OilRig "Schedule Task Persistence" - detects EID 4698 (SCHEDULED TASK
  creation), tagged T1543.003 (service). Both mis-tagged AND out-of-scope:
  scheduled tasks (T1053) were deliberately excluded from this thesis. Slipped
  into corpus via the T1543.003 tag. Corpus-hygiene finding; report as a limit
  of tag-based rule selection. (Service analog of #28 Event Log mis-tag.)

  - #1 (file) PSEXEC Remote Execution File Artefact - detects a PsExec .key
  artifact = LATERAL MOVEMENT tool artifact, tagged T1543.003. Mis-scoped.
- #0 (file) Moriya Rootkit File Created - a driver .sys IOC file drop; borderline
  with the excluded driver-load surface, kept because tagged T1543.003 + file event.


## B. Enumerated-list rules are structurally evadable
The dominant registry pattern: match a fixed LIST of autostart locations. Always
FULL by substitution - a bounded list cannot cover every ASEP in T1547.001, so
an off-list location within the same technique evades. The rule's own filter
list is evidence of its false-positive surface.
Finding (SQ1/SQ2): registry persistence rules are predominantly evadable, and
evadable for a single structural reason (location enumeration), not diverse ones.

- #6 (file) Suspicious Startup Folder Persistence enumerates executable
  extensions (.bat/.dll/.exe...) but OMITS .lnk - the most common Startup payload.
  A .lnk drop evades it -> FULL. Lesson: an extension allow-list is still an
  enumerated list; "matches executable files" != invariant if it misses a vector.

## C. Evadable AND noisy - the SQ3 off-diagonal
Rules that are FULL (evadable) yet BROAD (high false-positive surface):
behavioural rules keyed on suspicious PATH / COMMAND / SOURCE (#16, #19, #22,
#23). Relocate/re-encode to evade (FULL), yet legit software trips them (BROAD).
Finding (SQ3): evasion-resistance and false-positive proneness are independent -
these rules are the worst of both. Also: NONE rules can be NARROW (#0, #3, #14),
the opposite corner. Confirms breadth != inverse-of-evadability.

- Service-install: #8 (Service Install in Suspicious Folder), #9 (Suspicious
  Folder Pattern via ImagePath regex) - FULL by relocating the binary, BROAD
  because legit software also installs services from those paths.

## D. Robust rules match a true invariant
NONE is earned only when the rule matches the invariant of its specific method:
SAM \Names\ + `$` (#0), ServiceDll write (#3), Startup-folder redirect value
(#14), the specific hijack command key (#15/#28 arguable). Pattern: robustness
comes from pinning the one action the technique cannot avoid.

- #5 (file) Startup Folder File Write - matches ANY write to the Startup folder
  (no process/extension pin) = the invariant of Startup-folder persistence -> NONE
  (broad). The file-event analog of bare-4720 (#1 sec). Third bare-event NONE rule.

## E. Scoping judgment: classify against the tagged technique
Where a rule is robust under a super-narrow method definition (LSP injection,
SDDL tampering) but evadable under its broad T1547.001 tag, rated against the
tag (#27, #28). Methodological point to state explicitly in the write-up.

## F. Registry technique summary (fill after batch tally)
32 registry rules: mostly FULL (enumerated lists + IOC-tailored), NONE reserved
for true-invariant rules. [INSERT FINAL COUNTS from classification_sheet.csv]

## G. Service-install rules: robustness only via install-method, never bare event
18 service-install rules. 17 are FULL by substitution - every one keys on a
COSMETIC specific: attacker-chosen ServiceName (Sliver, WerFaultSvc, KrbSCM...),
tool name-lists (RAT list, PDQ), or suspicious ImagePath content/paths. Exactly
ONE is NONE: #10 (Service Installed By Unusual Client), robust because it matches
an install-METHOD invariant (ProcessId 0 = remote/SCM-injected install), not a
name or path.
KEY FINDING (SQ1/SQ2): NO service-install rule detects the bare "a service was
installed" event (EID 7045 alone). Robustness, where it exists, comes from a
behavioural install-property, not from covering the technique invariant. Sharp
contrast with account creation, which HAS a bare-4720 rule (#6, NONE/broad).
Implication: service-install detection is almost entirely IOC-based and thus
almost entirely evadable - a stronger evadability result than registry.

- CONFIRMED across security-log service rules too: #7 (sec, PID-0) is the 4697
  twin NONE; all name/IOC-based 4697 rules are FULL. The 7045/4697 pairs behave
  identically, reinforcing the finding.

## H. Rules already defending against Uetz-style evasions
- #14 Suspicious Service Installation Script uses the `windash` modifier, which
  matches both `-` and `/` flag prefixes - i.e. the author explicitly defends
  against SUBSTITUTION (hyphen/slash swap, Uetz type 2). Evidence that some
  evasions are known to rule authors; relevant to SQ2 (not all five types are
  equally "open"). Watch for more modifier-based hardening (windash, etc.).

  ## I. Corpus-level results (FINAL, in-scope N=65)
- SQ1: 85% evadable (55 full, 0 partial, 10 none, 0 broken). ~2x Uetz's 44%
  for process-creation -> persistence-event rules are markedly weaker.
- Zero partials: event-based detection is structurally binary (pin a cosmetic
  detail = full; match the invariant event = none). No OR-branch middle ground.
- SQ2: substitution is the ONLY evasion type (55/55). Confirms Part 2 prediction
  - structured fields (identifiers/paths) admit only substitution/recoding, not
  the command-line-bound types. Evasion surface collapses to "use another value".
- SQ3: full rules span all breadths (16 broad / 13 mod / 26 narrow); none rules
  span all breadths too (5 narrow-invariant, 2 broad bare-event). Evasion
  resistance and FP surface are INDEPENDENT (off-diagonal populated both ways).
- Per technique: registry 88% evadable, service 89%, account 25% - but account's
  "robustness" is coverage-poverty (only 4 rules; 3 are blunt bare-event matches),
  not strong detection. Service = 17 evadable IOC rules, ~no invariant coverage.
- The 10 NONE rules earn robustness one of two ways: (a) match a true invariant
  (SAM $, ServiceDll, Startup-redirect - narrow), or (b) match the bare event
  (4720, Startup-write - broad). Robustness always = "match what the technique
  cannot avoid."

  ## Isolation of same-key stateful tests (methods)
IOC-rename evasions write to the SAME registry key as the baseline. reg add does
not remove the prior value, and the baseline's write event lingers in the capture
window -> false "detected" on the evasion (observed R03). Procedure: delete the
baseline artifact before the evasion capture and/or use a tight (1-min) window.
Different-key evasions (e.g. R02 native-vs-Wow6432Node) are immune.



## Rule overlap (running tally - answers "why not combine rules?")
- R02: evaded Wow6432Node rule via native path; Direct Autorun caught native write.
- R03: evaded Leviathan IOC rule via rename; Direct Autorun / CurrentVersion /
  New RUN Key all still fired on the same write.
Pattern: IOC/specific rules evade easily, but generic behavioural Run-key rules
provide residual technique coverage. Evading one rule != evading the technique.


## Rules with structural conditions un-reproducible in single-VM lab
- R09 "Service Installed By Unusual Client - System" (EID 7045, ProcessId=0) and
  its Security twin (EID 4697, ProcessId/ClientProcessId=0) key on a STRUCTURAL
  install property (remote/system-context service creation). A local interactive
  sc.exe create produces a real PID (verified), so the true positive cannot be
  staged in a single-VM lab. Recorded as static-only (prediction 'none' holds by
  reasoning; excluded from empirical SQ4). Finding: robust rules that key on
  structural install-method properties are hard to reproduce, hence under-tested
  - the robustness comes precisely from matching a non-cosmetic condition.


  ## Rule-title mismatches (SigmaHQ vs Hayabusa) - methods caution
Hayabusa sometimes renames rules from their SigmaHQ titles. Test-TargetRule
matches on title, so a mismatch causes a FALSE "did NOT fire". Critical for
none rules (a false non-detection reads as evasion) and baselines. Confirmed:
- "Hidden Local User Creation" (SigmaHQ) = "Hidden User Account Created" (Hayabusa).
Procedure: on any "did NOT fire", cross-check the actual detections list before
recording. Recommend pre-mapping all 31 subset titles to Hayabusa titles.

## Rule-quality findings (for discussion chapter)
- R10 "Hidden Local User Creation": the filter_main_homegroup exclusion
  (intended to whitelist the benign HomeGroupUser$ account) is INEFFECTIVE in
  Hayabusa 3.10.0 - an account named exactly HomeGroupUser$ still fires the rule.
  Event confirmed the name matched the filter string. Likely a TargetUserName
  field-resolution mismatch. Result: rule is more robust in practice than its
  logic suggests, but the benign-exclusion the author intended does not function.


  ## Hayabusa reassigns BOTH title and ID at runtime (critical methods finding)
Hayabusa's scan-time CSV output uses a different RuleTitle AND RuleID than the
rule's YAML file - neither is predictable from the files (confirmed: YAML title
"Hidden Local User Creation"/id 23013005... -> CSV "Hidden User Account
Created"/RuleID 70b8b1bd...). So target detection cannot be verified by
pre-mapping titles or IDs. MANDATORY procedure: verify each result against the
actual CSV detection list, matching the target by its detection logic/keywords.
For NONE rules especially: run Show-Detections on both phases and confirm the
target's presence, since a missed rename would falsely record robust-as-evaded.
Renaming is deterministic per Hayabusa version, so a rule's runtime title, once
observed, is reliable for that rule.


- R13: relocating the service binary out of \AppData\ evaded BOTH path-based
  rules ("Service Installation in Suspicious Folder" AND "Suspicious Service
  Path") simultaneously. Unlike name-IOC evasions (where a generic behavioural
  sibling still fires), path-based rules share the same weakness - moving the
  binary defeats all of them at once, leaving NO residual path-rule coverage.
  Only the generic "Svc Installed" (any service install) remained. Implication:
  path-based detection is more brittle as a family than behavioural detection.



  ## Substring title collisions in Test-TargetRule (methods caution)
"CurrentVersion Autorun Keys Modification" is a substring of "Wow6432Node
CurrentVersion Autorun Keys Modification", so Test-TargetRule's -like match hits
both. For these paired native/Wow6432Node rules, verify with exact-match (-eq)
against the CSV RuleTitle, not the -like helper. Confirmed R15.

## Capture-window contamination is TIME-based, not key-based (correction)
Even when baseline and evasion write to DIFFERENT registry keys, if run within
the capture window they both appear in the log and can fire different rules
(observed R15: native baseline write lingered in the Wow6432Node evasion
capture, firing the native rule). Rule: always age out / tighten window between
phases in the same log, regardless of key. Time is the axis, not key identity.