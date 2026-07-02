"""
show_sample.py
Print rules from the classification sheet for a chosen technique + event class,
in batches, for classification. Usage examples:
    python scripts\\show_sample.py registry
    python scripts\\show_sample.py registry 0 10
    python scripts\\show_sample.py service_install
    python scripts\\show_sample.py security_log
"""
import sys
from pathlib import Path
import pandas as pd

DATA = Path(__file__).resolve().parent.parent / "data"
df = pd.read_csv(DATA / "classification_sheet.csv").fillna("")

event_class = sys.argv[1] if len(sys.argv) > 1 else "registry"
start = int(sys.argv[2]) if len(sys.argv) > 2 else 0
count = int(sys.argv[3]) if len(sys.argv) > 3 else 10

sub = df[df["event_class"] == event_class].reset_index(drop=True)
batch = sub.iloc[start:start + count]

print(f"=== {event_class}: showing {start}-{start + len(batch) - 1} "
      f"of {len(sub)} ===\n")
for i, r in batch.iterrows():
    print("=" * 72)
    print(f"#{i}  [{r['technique']} | {r['event_class']}] {r['title']}")
    print(f"  DESC : {r['description']}")
    print(f"  LOGIC: {r['detection_summary']}")
    print(f"  FALSEPOS: {r['falsepositives']}")