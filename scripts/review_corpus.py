"""
review_corpus.py
Print the rules that need a human decision before the corpus is final.
  1. Parent-only tagged rules - candidates to ADD if they're genuinely
     Run-Key / service / account rules that missed the sub-technique tag.
  2. driver_load rules in the novel corpus - confirm each is service/driver
     installation (keep) versus vulnerable-driver abuse (remove).
"""
from pathlib import Path
import pandas as pd

DATA = Path(__file__).resolve().parent.parent / "data"

print("=== 1. PARENT-ONLY TAGGED RULES (candidates to add) ===\n")
parent = pd.read_csv(DATA / "parent_tagged_review.csv").fillna("")
for i, r in parent.iterrows():
    print(f'[{i}] {r["title"]}')
    print(f'    tags: {r["tags"]}')
    print(f'    {r["file_path"]}\n')

print("\n=== 2. DRIVER_LOAD RULES IN NOVEL CORPUS (confirm persistence) ===\n")
novel = pd.read_csv(DATA / "corpus_novel.csv").fillna("")
for _, r in novel[novel["event_class"] == "driver_load"].iterrows():
    print(f'{r["title"]}')
    print(f'    {r["file_path"]}\n')