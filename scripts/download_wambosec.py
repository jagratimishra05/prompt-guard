
from datasets import load_dataset
from pathlib import Path

output_dir = Path("data/raw")
output_dir.mkdir(parents=True, exist_ok=True)

print("Downloading Wambosec dataset...")

dataset = load_dataset("wambosec/prompt-injections")

print("\nAvailable splits:", list(dataset.keys()))

for split_name, split_data in dataset.items():

    print(f"\nSplit: {split_name}")
    print("Number of rows:", len(split_data))
    print("Columns:", split_data.column_names)

    df = split_data.to_pandas()

    filename = output_dir / f"wambosec_{split_name}.csv"

    df.to_csv(filename, index=False)

    print("Saved:", filename)

    if "label" in df.columns:
        print("\nLabel distribution:")
        print(df["label"].value_counts())

print("\nWambosec download completed!")
