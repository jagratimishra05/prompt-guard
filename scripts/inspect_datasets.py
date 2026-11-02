
from pathlib import Path
from itertools import combinations
import re
import unicodedata

import pandas as pd


# --------------------------------------------------
# 1. PROJECT PATHS
# --------------------------------------------------

PROJECT_DIR = Path(__file__).resolve().parents[1]
RAW_DIR = PROJECT_DIR / "data" / "raw"
OUTPUT_DIR = PROJECT_DIR / "data" / "processed"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------
# 2. TEXT NORMALIZATION
# --------------------------------------------------

def normalize_text(value):
    if pd.isna(value):
        return ""

    text = unicodedata.normalize("NFKC", str(value))
    text = text.lower().strip()
    text = re.sub(r"\s+", " ", text)

    return text


# --------------------------------------------------
# 3. READ ALL RAW CSV FILES
# --------------------------------------------------

all_records = []

csv_files = sorted(RAW_DIR.rglob("*.csv"))

if not csv_files:
    raise FileNotFoundError(f"No CSV files found in {RAW_DIR}")

for file_path in csv_files:

    df = pd.read_csv(file_path)

    # Identify prompt/text column
    text_column = next(
        (col for col in ["text", "prompt"] if col in df.columns),
        None
    )

    if text_column is None:
        print(f"Skipping {file_path.name}: no text/prompt column")
        continue

    relative_name = str(file_path.relative_to(RAW_DIR))

    for index, row in df.iterrows():

        original_text = row[text_column]
        normalized = normalize_text(original_text)

        if not normalized:
            continue

        all_records.append({
            "file": relative_name,
            "original_index": index,
            "text": original_text,
            "normalized_text": normalized,
            "label": row.get("label", None),
            "group_id": row.get("group_id", None)
        })


if not all_records:
    raise ValueError("No usable prompt records were found.")

data = pd.DataFrame(all_records)

print("\n========== DATASET SUMMARY ==========")
print(f"Total prompts: {len(data)}")
print(f"Dataset files inspected: {data['file'].nunique()}")


# --------------------------------------------------
# 4. DUPLICATE PROMPT REPORT
# --------------------------------------------------

duplicate_groups = data[
    data.duplicated("normalized_text", keep=False)
].copy()

duplicate_groups = duplicate_groups.sort_values(
    ["normalized_text", "file"]
)

duplicate_groups.to_csv(
    OUTPUT_DIR / "duplicate_report.csv",
    index=False
)

unique_duplicated_prompts = duplicate_groups[
    "normalized_text"
].nunique()

print("\n========== DUPLICATE SUMMARY ==========")
print(f"Duplicate prompt rows: {len(duplicate_groups)}")
print(f"Unique duplicated prompts: {unique_duplicated_prompts}")


# --------------------------------------------------
# 5. DUPLICATE SUMMARY BY FILE
# --------------------------------------------------

duplicate_summary = (
    duplicate_groups.groupby("file")
    .agg(
        duplicate_rows=("normalized_text", "size"),
        unique_duplicated_prompts=("normalized_text", "nunique")
    )
    .reset_index()
)

duplicate_summary.to_csv(
    OUTPUT_DIR / "duplicate_summary.csv",
    index=False
)


# --------------------------------------------------
# 6. CONFLICTING LABEL REPORT
# --------------------------------------------------

label_data = data.dropna(subset=["label"]).copy()

label_counts = (
    label_data.groupby("normalized_text")["label"]
    .nunique()
)

conflicting_prompts = label_counts[
    label_counts > 1
].index

label_conflicts = label_data[
    label_data["normalized_text"].isin(conflicting_prompts)
].copy()

label_conflicts.to_csv(
    OUTPUT_DIR / "label_conflicts.csv",
    index=False
)

print("\n========== LABEL CONFLICTS ==========")
print(f"Conflicting-label prompts: {len(conflicting_prompts)}")


# --------------------------------------------------
# 7. GROUP ID OVERLAP REPORT
# --------------------------------------------------

group_data = data.dropna(subset=["group_id"]).copy()

group_data["group_id"] = group_data["group_id"].astype(str)

group_overlap = group_data[
    group_data.duplicated("group_id", keep=False)
].sort_values(["group_id", "file"])

group_overlap.to_csv(
    OUTPUT_DIR / "group_overlap_report.csv",
    index=False
)

print("\n========== GROUP ID SUMMARY ==========")
print(f"Rows with repeated group IDs: {len(group_overlap)}")


# --------------------------------------------------
# 8. ALL-PAIRS DATASET OVERLAP REPORT
# --------------------------------------------------

file_sets = {
    name: set(group["normalized_text"].dropna())
    for name, group in data.groupby("file")
}

overlap_rows = []

for file_a, file_b in combinations(sorted(file_sets), 2):

    shared = file_sets[file_a] & file_sets[file_b]

    overlap_rows.append({
        "file_a": file_a,
        "file_b": file_b,
        "shared_unique_prompts": len(shared),
        "shared_prompts": " || ".join(sorted(shared))
    })

overlap_df = pd.DataFrame(
    overlap_rows,
    columns=[
        "file_a",
        "file_b",
        "shared_unique_prompts",
        "shared_prompts"
    ]
)

overlap_df.to_csv(
    OUTPUT_DIR / "split_overlap_report.csv",
    index=False
)

print("\n========== DATASET OVERLAP SUMMARY ==========")

for row in overlap_rows:

    if row["shared_unique_prompts"] > 0:

        print(
            f"{row['file_a']} vs {row['file_b']}: "
            f"{row['shared_unique_prompts']} shared prompts"
        )


# --------------------------------------------------
# 9. FINAL REPORT LOCATIONS
# --------------------------------------------------

print("\n========== INSPECTION COMPLETED ==========")

print(f"Total prompts inspected: {len(data)}")
print(f"Duplicate prompt rows: {len(duplicate_groups)}")
print(f"Unique duplicated prompts: {unique_duplicated_prompts}")
print(f"Conflicting-label prompts: {len(conflicting_prompts)}")

print("\nReports saved in:")
print(OUTPUT_DIR)
