"""
inspect_logsource.py
Show each rule's full log-source signature (category | product | service).
The rules with no 'category' are differentiated by 'service' - these are the
System-log (service creation, EID 7045) and Security-log (account creation,
EID 4720) event rules that form the core novel target.
"""
import pandas as pd
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"
df = pd.read_csv(DATA / "corpus_raw.csv").fillna("(none)")

df["logsource"] = (df["logsource_category"] + " | "
                   + df["logsource_product"] + " | "
                   + df["logsource_service"])

print("--- full log-source signature counts ---")
print(df["logsource"].value_counts().to_string())

print("\n--- technique -> log-source signature -> count ---")
print(df.groupby(["technique", "logsource"]).size().to_string())