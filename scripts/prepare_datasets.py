
from pathlib import Path
import re
import unicodedata

import pandas as pd


# --------------------------------------------------
# 1. PATHS AND DATASET SELECTION
# --------------------------------------------------

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
OUTPUT = ROOT / "data" / "processed"

OUTPUT.mkdir(parents=True, exist_ok=True)

TRAIN_FILES = [
    "s_labs_train.csv",
    "wambosec_train.csv",
    "extra_dataset/extra_train.csv",
    "ogma_train.csv",
]

VALIDATION_FILES = [
    "s_labs_validation.csv",
]

TEST_FILES = [
    "wambosec_test.csv",
    "extra_dataset/extra_test.csv",
]


# --------------------------------------------------
# 2. NORMALIZE PROMPTS
# --------------------------------------------------

def normalize_text(value):
    if pd.isna(value):
        return ""

    text = unicodedata.normalize("NFKC", str(value))
    text = text.lower().strip()
    text = re.sub(r"\s+", " ", text)

    return text


# --------------------------------------------------
# 3. LOAD A DATASET
# --------------------------------------------------

def load_dataset(relative_path):

    path = RAW / relative_path

    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")

    df = pd.read_csv(path)

    text_column = next(
        (col for col in ["text", "prompt"] if col in df.columns),
        None
    )

    if text_column is None:
        raise ValueError(f"No text/prompt column in {relative_path}")

    if "label" not in df.columns:
        raise ValueError(f"No label column in {relative_path}")

    df = df.rename(columns={text_column: "text"})

    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df["normalized_text"] = df["text"].apply(normalize_text)

    df["source_file"] = relative_path
    df["source_dataset"] = Path(relative_path).stem

    df = df.dropna(subset=["label"]).copy()
    df = df[df["normalized_text"] != ""].copy()

    return df


# --------------------------------------------------
# 4. LOAD ALL RAW DATASETS FOR CONFLICT CHECKING
# --------------------------------------------------

print("\nLoading raw datasets...")

all_raw = []

for path in sorted(RAW.rglob("*.csv")):
    relative_path = str(path.relative_to(RAW))
    all_raw.append(load_dataset(relative_path))

all_data = pd.concat(all_raw, ignore_index=True)

# Identify prompts that have more than one label
label_counts = (
    all_data.groupby("normalized_text")["label"].nunique()
)

conflict_prompts = set(
    label_counts[label_counts > 1].index
)

print(f"Conflicting prompts identified: {len(conflict_prompts)}")


# --------------------------------------------------
# 5. LOAD SELECTED TRAIN / VALIDATION / TEST FILES
# --------------------------------------------------

train_parts = [load_dataset(f) for f in TRAIN_FILES]
validation_parts = [load_dataset(f) for f in VALIDATION_FILES]
test_parts = [load_dataset(f) for f in TEST_FILES]

train = pd.concat(train_parts, ignore_index=True)
validation = pd.concat(validation_parts, ignore_index=True)
test = pd.concat(test_parts, ignore_index=True)


# --------------------------------------------------
# 6. REMOVE CONFLICTING-LABEL PROMPTS
# --------------------------------------------------

before = len(train)

train = train[
    ~train["normalized_text"].isin(conflict_prompts)
].copy()

conflicts_removed = before - len(train)

# --------------------------------------------------
# 6A. EXCLUDE SUSPECTED MISLABELLED CONTROL EXAMPLES
# --------------------------------------------------

control_mask = (
    (train["source_file"] == "extra_dataset/extra_train.csv")
    & (train["category"] == "control")
    & (train["label"] == 1)
)

control_excluded = train[control_mask].copy()

# Save excluded examples for audit purposes

control_excluded.to_csv(
    OUTPUT / "excluded_control_examples.csv",
    index=False
)

train = train[~control_mask].copy()

print(
    f"Suspected mislabelled control examples excluded: "
    f"{len(control_excluded)}"
)

# --------------------------------------------------
# 7. DEDUPLICATE TEST DATA
# --------------------------------------------------

test_before = len(test)

test = test.drop_duplicates(
    subset="normalized_text",
    keep="first"
).copy()

test_duplicates_removed = test_before - len(test)


# --------------------------------------------------
# 8. KEEP VALIDATION AND TEST SEPARATE
# --------------------------------------------------

validation_before = len(validation)

# Remove prompts already present in test
test_prompts = set(test["normalized_text"])

validation = validation[
    ~validation["normalized_text"].isin(test_prompts)
].copy()

# Remove duplicate prompts within validation
validation = validation.drop_duplicates(
    subset="normalized_text",
    keep="first"
).copy()

validation_removed = validation_before - len(validation)


# --------------------------------------------------
# 9. REMOVE TRAINING OVERLAPS WITH VALIDATION / TEST
# --------------------------------------------------

train_before = len(train)

reserved_prompts = (
    set(validation["normalized_text"])
    | set(test["normalized_text"])
)

train = train[
    ~train["normalized_text"].isin(reserved_prompts)
].copy()

overlap_removed = train_before - len(train)


# --------------------------------------------------
# 10. REMOVE DUPLICATES WITHIN TRAINING DATA
# --------------------------------------------------

train_before_dedup = len(train)

train = train.drop_duplicates(
    subset="normalized_text",
    keep="first"
).copy()

train_duplicates_removed = train_before_dedup - len(train)


# --------------------------------------------------
# 11. SAVE CLEAN DATASETS
# --------------------------------------------------

train.to_csv(
    OUTPUT / "clean_train.csv",
    index=False
)

validation.to_csv(
    OUTPUT / "clean_validation.csv",
    index=False
)

test.to_csv(
    OUTPUT / "clean_test.csv",
    index=False
)


# --------------------------------------------------
# 12. SAVE CLEANING SUMMARY
# --------------------------------------------------

summary = pd.DataFrame([
    {
    "dataset": "train",
    "final_rows": len(train),
    "conflicts_removed": conflicts_removed,
    "control_examples_excluded": control_excluded.shape[0],
    "overlap_removed": overlap_removed,
    "duplicates_removed": train_duplicates_removed
    },
    {
        "dataset": "validation",
        "final_rows": len(validation),
        "conflicts_removed": 0,
        "control_examples_excluded": 0,
        "overlap_removed": validation_removed,
        "duplicates_removed": 0
    },
    {
        "dataset": "test",
        "final_rows": len(test),
        "conflicts_removed": 0,
        "control_examples_excluded": 0,
        "overlap_removed": 0,
        "duplicates_removed": test_duplicates_removed
    }
])

summary.to_csv(
    OUTPUT / "cleaning_summary.csv",
    index=False
)


# --------------------------------------------------
# 13. FINAL RESULTS
# --------------------------------------------------

print("\n========== CLEANING COMPLETED ==========")

print(f"Training examples: {len(train)}")
print(f"Validation examples: {len(validation)}")
print(f"Testing examples: {len(test)}")

print("\nTraining label distribution:")
print(train["label"].value_counts().sort_index())

print("\nValidation label distribution:")
print(validation["label"].value_counts().sort_index())

print("\nTesting label distribution:")
print(test["label"].value_counts().sort_index())

print("\nFiles saved in:", OUTPUT)
print(" - clean_train.csv")
print(" - clean_validation.csv")
print(" - clean_test.csv")
print(" - cleaning_summary.csv")
