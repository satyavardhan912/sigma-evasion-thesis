# Codebook - Evasion Robustness Classification

The same four-way scheme is applied STATICALLY (reading the rule, Phase 2) and
EMPIRICALLY (executing persistence + evasion in the lab, Phase 3). The static
label is a PREDICTION of the empirical outcome; applying identical categories
to both is what makes the static-vs-empirical comparison (SQ4) valid.

## What counts as an evasion
A functionally-equivalent modification to the persistence action: the attacker
changes HOW the technique is performed so a rule no longer detects it, while the
persistence still works (survives reboot / runs the payload / creates the
account). Modifications that break the persistence do NOT count.
Enabling assumption (after Uetz): an attacker who can perform the persistence
action can also alter its parameters - the registry path/value, the service
name/image path, the account name.

## Categories (aligned to Uetz et al. 2024)

### FULL
The rule can be completely evaded by a functionally-equivalent modification:
it does not fire at all on the malicious action, and persistence still works.

### PARTIAL
The rule's detection is a disjunction of multiple OR-branches (alternative
detection conditions), and a functionally-equivalent modification evades at
least one branch but not all. The rule still catches the variants covered by
the branch(es) that cannot be evaded. (Per Uetz, the least common outcome - 7%.)

### NONE
No functionally-equivalent modification evades the rule. Statically: the rule
matches the invariant core of the technique (the autostart write, the 7045
service install, the 4720 account creation) rather than attacker-controllable
specifics. NOTE: empirically, "none" means no evasion was found, which is not
the same as provably robust (cf. Uetz's 51 suspected-but-unconfirmed rules) -
this gap is what SQ4 measures.

### BROKEN
The rule is faulty independent of evasion: a logic error, an impossible
condition, a field that does not exist for its log source, or a wrong log
source - so it does not fire on the true-positive action it claims to detect.
Excluded from the evadability proportions, reported separately, fixes
contributed to SigmaHQ. Empirically identified by the baseline test: the rule
fails to fire on the UNMODIFIED true-positive action.

## Governing heuristic
Evadability tracks dependence on attacker-controllable specifics vs the
invariant core (Uetz attribute evadable rules to authors tailoring a rule to a
concrete attack without anticipating variations):
- Matches a specific name / path / value the attacker can change -> evadable.
- Matches the invariant event of the technique -> robust (NONE).
This is also the false-positive axis in SQ3: robust rules tend to be broad
(noisy); precise rules tend to be evadable.

## Worked examples (from this corpus)
- Registry rule matching `TargetObject|endswith: '\CurrentVersion\Run'` only:
  writing to `\CurrentVersion\RunOnce` (also autostarts) is functionally
  equivalent and unmatched -> FULL. If it matched `|contains:
  '\CurrentVersion\Run'`, RunOnce contains that substring and is still caught -
  the modifier alone changes the outcome.
- Service rule matching EID 7045 with a specific ServiceName or ImagePath:
  renaming the service or relocating its binary still installs and runs it ->
  FULL (or PARTIAL if it is one of several OR-branches and another still fires).
- Rule matching only EID 4720 with no further constraint: any local account
  creation fires it, no functionally-equivalent change avoids the event -> NONE
  (robust, but broad - high false-positive surface).

## Source alignment (verified against Uetz et al. 2024, USENIX Security)
Corpus: Windows process-creation Sigma rules, repo commit 12054544 (4 Feb 2021).
Labels: full (completely evaded), partial (OR-branches, some-not-all evaded),
none (no evasion found), broken (faulty). Results: 110 full (38%), 19 partial
(7%), 12 broken (4 fixes merged to SigmaHQ); 51 (17%) suspected-but-unconfirmed.
The five evasion types (Table 1), adapted to persistence fields in Part 2:
- Insertion  - add ignored chars (quotes/spaces): /create -> /"create"
- Substitution - synonymous chars/args (hyphen for slash): -O -> --remote-name
- Omission   - drop unnecessary chars (shorten): cscript.exe -> cscript
- Reordering - reorder arguments: -ma ls -> ls -ma
- Recoding   - re-encode arguments: 127.0.0.1 -> 2130706433
Uetz created >=3 matching and >=3 evading variants per evadable rule for
variability; the empirical phase adopts this practice.




# Part 2 - Evasion-type adaptation (SQ2 instrument)

Uetz's five types were built for command-line STRINGS. Most of our rules match
STRUCTURED values, so a type applies only if the field's structure admits it.
These are PREDICTED applicabilities, confirmed against actual rule logic and
telemetry during classification; a cell that turns out otherwise is a finding.

## Field classes
- PATH - hierarchical, order-fixed: registry key (`TargetObject`), service
  registry path, startup-folder file path (`TargetFilename`), ImagePath location.
- IDENTIFIER - atomic, attacker-chosen: service name (`ServiceName`), account
  name (`TargetUserName`).
- COMMAND-STRING - free-form, command-line-like: `ImagePath` with arguments,
  registry value-data (`Details`) holding a command. Admits all five types.

## What each type means per field class
INSERTION (add ignored characters)
- Command-string: insert quotes/spaces/carets - `C:\evil.exe` -> `C:\"evil".exe`. APPLIES.
- Path / Identifier: structured values reject ignored insertions; a changed
  identifier is just a different value (= substitution). N/A.

SUBSTITUTION (synonymous token) - dominant
- Path: equivalent autostart LOCATION (`\Run` <-> `\RunOnce` <-> Startup folder);
  hive aliases (`HKLM` <-> `HKEY_LOCAL_MACHINE`) - but telemetry may normalise
  these (verify empirically). APPLIES.
- Identifier: any value works; use a non-matched one (`Updater`, `svc-help`).
  APPLIES (strongest evasion for identifier-matching rules).
- Command-string: synonymous tools/flags (`sc create` <-> `New-Service`;
  `net user /add` <-> `New-LocalUser`). APPLIES.

OMISSION (drop unnecessary characters)
- Command-string: drop `.exe`, drop optional flags, shorten. APPLIES.
- Path: drop trailing `.exe` in value-data commands only; key paths cannot
  shorten. LIMITED.
- Identifier: nothing unnecessary to drop. N/A.

REORDERING (reorder tokens) - narrowest
- Command-string: reorder command arguments (`binPath= X type= own` -> reorder). APPLIES.
- Path / Identifier: hierarchical or atomic; nothing to reorder. N/A.

RECODING (re-encode value) - co-dominant with substitution
- Path: env-var (`%windir%` <-> `C:\Windows`, Uetz's own registry example),
  8.3 short names (`PROGRA~1`), native object paths. APPLIES.
- Command-string: env vars, encoded commands. APPLIES.
- Identifier: case / Unicode homoglyph / trailing dot-space (Windows
  normalises). LIMITED and brittle.

## Per-technique instantiation
- T1547.001 (registry): PATH (key) + sometimes COMMAND (value-data). Key rules
  -> substitution + recoding. Value-data rules -> all five. Startup-folder file
  rules -> substitution (location) + recoding (8.3) + naming.
- T1543.003 (service): IDENTIFIER (ServiceName) + PATH/COMMAND (ImagePath) +
  PATH (service registry). Widest surface - ImagePath is command-like.
- T1136.001 (account): IDENTIFIER (account name) almost exclusively ->
  substitution dominant, recoding limited. Narrowest surface.

## Finding this predicts (SQ2)
Persistence-event rules have a NARROWER evasion surface than command-line
process-creation. Substitution and recoding transfer to structured fields and
dominate; insertion, omission, and reordering are command-line-bound and do not
apply to the path/identifier fields most persistence rules match. Account is
narrowest (identifier-only); service widest (command-like ImagePath). The
empirical results test this hypothesis.