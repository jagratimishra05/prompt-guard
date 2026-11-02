
from datasets import load_dataset
from pathlib import Path

output_dir = Path("data/raw/extra_dataset")
output_dir.mkdir(parents=True, exist_ok=True)

print("Downloading additional prompt injection dataset...")

dataset = load_dataset(
    "cyberec/Prompt-injection-dataset",
    "core"
)

print("\nAvailable splits:", list(dataset.keys()))

for split_name, split_data in dataset.items():
    df = split_data.to_pandas()

    print(f"\nSplit: {split_name}")
    print("Rows:", len(df))
    print("Columns:", df.columns.tolist())

    if "label" in df.columns:
        print("\nLabel distribution:")
        print(df["label"].value_counts(dropna=False))

    if "category" in df.columns:
        print("\nCategories:")
        print(df["category"].value_counts().head(15))

    filename = output_dir / f"extra_{split_name}.csv"
    df.to_csv(filename, index=False)

    print("\nSaved:", filename)

print("\nDownload completed!")
