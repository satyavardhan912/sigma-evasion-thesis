# Codebook - Evasion Robustness Classification

The same four-way scheme is applied STATICALLY (reading the rule, Phase 2) and
EMPIRICALLY (executing persistence + evasion in the lab, Phase 3). Applying
identical categories to both is what makes the static-vs-empirical comparison
(SQ4) valid.

## What counts as an evasion
A functionally-equivalent modification to the persistence action: the attacker
changes HOW the technique is performed so a rule no longer detects it, while the
persistence still works (survives reboot / runs the payload / creates the
account). Modifications that break the persistence do NOT count.

## Categories

### FULL
A functionally-equivalent modification (or combination) causes the rule not to
fire at all on the malicious action. Complete bypass, persistence still works.

### PARTIAL
The rule cannot be completely bypassed, but at least one modification defeats
part of its detection logic - the attacker reduces coverage (evades one branch
of an OR, or one of several matched specifics) without eliminating detection.
A detection pathway remains that functionally-equivalent changes cannot evade.

### NONE
No functionally-equivalent modification reduces detection. The rule fires on
every functionally-equivalent variant because it matches the invariant core of
the technique (the autostart write, the 7045 service install, the 4720 account
creation) rather than attacker-controllable specifics. Robust (and usually
broad - see Part 3).

### BROKEN
The rule is defective independent of evasion: a logic error, an impossible
condition, a field that does not exist for its log source, or a wrong log
source - so it does not fire on the true-positive action it claims to detect.
Reported separately, excluded from the evadability proportions, fixes
contributed back to SigmaHQ. Empirically, identified by the baseline test: the
rule fails to fire on the UNMODIFIED true-positive action.

## Governing heuristic
Evadability tracks dependence on attacker-controllable specifics vs the
invariant core:
- Matches a specific name / path / value the attacker can change -> evadable
  (FULL or PARTIAL).
- Matches the invariant event of the technique -> robust (NONE).
This is also the axis of the false-positive trade-off in SQ3: robust rules tend
to be broad (noisy); precise rules tend to be evadable.

## Worked examples (from this corpus)
- Registry rule matching `TargetObject|endswith: '\CurrentVersion\Run'` only:
  writing to `\CurrentVersion\RunOnce` instead (also autostarts) is functionally
  equivalent and unmatched -> FULL. If it matched `|contains:
  '\CurrentVersion\Run'`, RunOnce contains that substring and is still caught -
  the modifier alone changes the outcome.
- Service rule matching EID 7045 with a specific ServiceName or ImagePath:
  renaming the service or relocating its binary still installs and runs it ->
  the specific value is evaded -> FULL (or PARTIAL if another matched condition
  still fires).
- Rule matching only EID 4720 with no further constraint: any local account
  creation fires it, no functionally-equivalent change avoids the event -> NONE
  (robust, but broad - high false-positive surface).

## Source alignment (to verify before locking)
These operationalise Uetz et al.'s full / partial / none / broken scheme. Before
locking, reconcile the exact wording against the Uetz paper - the qualitative
comparison (SQ2) depends on using their definitions faithfully.