"""
show_sample.py
Print a representative spread for calibrating the classification: a registry
Run-key rule, a startup-folder file rule, a service-install rule, and all
account-creation rules.
"""
from pathlib import Path
import pandas as pd

DATA = Path(__file__).resolve().parent.parent / "data"
df = pd.read_csv(DATA / "classification_sheet.csv").fillna("")


def pick(technique, event_class):
    sub = df[(df["technique"] == technique) & (df["event_class"] == event_class)]
    return sub.iloc[[0]] if len(sub) else df.iloc[0:0]


picks = [
    pick("T1547.001", "registry"),
    pick("T1547.001", "file_event"),
    pick("T1543.003", "service_install"),
    df[df["technique"] == "T1136.001"],   # all account rules
]
sample = pd.concat(picks).drop_duplicates(subset="title")

for _, r in sample.iterrows():
    print("=" * 72)
    print(f"[{r['technique']} | {r['event_class']}] {r['title']}")
    print(f"  DESC : {r['description']}")
    print(f"  LOGIC: {r['detection_summary']}")
    print(f"  FALSEPOS: {r['falsepositives']}")