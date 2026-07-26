"""
sq4_analysis.py - SQ4: how well static classification predicts empirical outcomes.
Confusion matrix + Cohen's kappa on the empirically-testable rules.
Static-only rules (baseline unreproducible) are excluded and reported separately.
"""
import pandas as pd

df = pd.read_csv('data/test_subset.csv')

# --- Split testable vs static-only ---
testable = df[df['empirical_outcome'].isin(['full', 'none'])].copy()
static_only = df[~df['empirical_outcome'].isin(['full', 'none'])].copy()

n_test = len(testable)
n_static = len(static_only)
n_total = len(df)

print("=" * 60)
print("SQ4: STATIC PREDICTION vs EMPIRICAL OUTCOME")
print("=" * 60)
print(f"Total subset rules:      {n_total}")
print(f"Empirically testable:    {n_test}")
print(f"Static-only (excluded):  {n_static}")
print()

# --- Confusion matrix ---
print("CONFUSION MATRIX (rows=predicted, cols=empirical):")
ct = pd.crosstab(testable['predicted_evadability'],
                 testable['empirical_outcome'],
                 margins=True, margins_name='Total')
print(ct.to_string())
print()

# --- Cell counts (binary: evadable vs robust) ---
# Treat 'full' = evadable (positive), 'none' = robust (negative)
def cell(pred, emp):
    return len(testable[(testable['predicted_evadability'] == pred) &
                        (testable['empirical_outcome'] == emp)])

tp = cell('full', 'full')   # predicted evadable, is evadable
tn = cell('none', 'none')   # predicted robust, is robust
fp = cell('full', 'none')   # predicted evadable, actually robust
fn = cell('none', 'full')   # predicted robust, actually evadable (the mismatches)

print("Binary cells (positive = evadable):")
print(f"  True Positive  (pred full / emp full): {tp}")
print(f"  True Negative  (pred none / emp none): {tn}")
print(f"  False Positive (pred full / emp none): {fp}")
print(f"  False Negative (pred none / emp full): {fn}  <-- R25, R27 mismatches")
print()

# --- Overall agreement ---
agree = tp + tn
observed_agreement = agree / n_test
print(f"Observed agreement (accuracy): {agree}/{n_test} = {observed_agreement:.4f} ({observed_agreement*100:.1f}%)")
print()

# --- Cohen's kappa (manual, 2x2) ---
# po = observed agreement
# pe = expected agreement by chance
po = observed_agreement
p_pred_full = (tp + fp) / n_test
p_pred_none = (tn + fn) / n_test
p_emp_full = (tp + fn) / n_test
p_emp_none = (tn + fp) / n_test
pe = (p_pred_full * p_emp_full) + (p_pred_none * p_emp_none)

if (1 - pe) == 0:
    kappa = float('nan')
    print("Cohen's kappa: undefined (pe = 1; no variability in one margin)")
else:
    kappa = (po - pe) / (1 - pe)
    print(f"Expected agreement by chance (pe): {pe:.4f}")
    print(f"Cohen's kappa: {kappa:.4f}")

# --- Kappa interpretation (Landis & Koch 1977) ---
def interpret_kappa(k):
    if k != k:  # nan
        return "undefined"
    if k < 0: return "poor (worse than chance)"
    if k <= 0.20: return "slight"
    if k <= 0.40: return "fair"
    if k <= 0.60: return "moderate"
    if k <= 0.80: return "substantial"
    return "almost perfect"

print(f"Interpretation (Landis & Koch): {interpret_kappa(kappa)}")
print()

# --- The disagreements, named ---
print("DISAGREEMENTS (predicted != empirical):")
disagree = testable[testable['predicted_evadability'] != testable['empirical_outcome']]
for _, r in disagree.iterrows():
    print(f"  - {r['title']}: predicted {r['predicted_evadability']} -> empirical {r['empirical_outcome']}")
print()

# --- Static-only rules, with reasons ---
print("=" * 60)
print(f"STATIC-ONLY RULES (excluded from matrix): {n_static}")
print("=" * 60)
for _, r in static_only.iterrows():
    reason = str(r['empirical_outcome']).replace('not tested (baseline unreproducible', '').replace(')', '').strip(' -')
    if not reason:
        reason = 'structural (PID-0, not locally reproducible)'
    print(f"  - {r['title']}")
    print(f"      predicted: {r['predicted_evadability']} | reason: {reason if reason else 'structural'}")
print()

# --- Per-technique breakdown (testable) ---
print("=" * 60)
print("PER-TECHNIQUE (testable rules):")
print("=" * 60)
for tech in sorted(testable['technique'].unique()):
    sub = testable[testable['technique'] == tech]
    evadable = len(sub[sub['empirical_outcome'] == 'full'])
    total = len(sub)
    print(f"  {tech}: {evadable}/{total} empirically evadable ({evadable/total*100:.0f}%)")