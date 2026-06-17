"""
inspect_corpus.py
Show the breakdowns needed for scoping: log-source categories (the
process-creation overlap), rule status, and collection vs technique.
"""
import pandas as pd
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"
df = pd.read_csv(DATA / "corpus_raw.csv").fillna("(none)")

print("Total rules:", len(df))

print("\n--- log-source category counts ---")
print(df["logsource_category"].value_counts().to_string())

print("\n--- technique x log-source category ---")
print(pd.crosstab(df["technique"], df["logsource_category"]).to_string())

print("\n--- rule status counts ---")
print(df["status"].value_counts().to_string())

print("\n--- collection x technique ---")
print(pd.crosstab(df["collection"], df["technique"]).to_string())