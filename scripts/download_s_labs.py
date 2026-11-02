
from datasets import load_dataset
from pathlib import Path

output_dir = Path("data/raw")
output_dir.mkdir(parents=True, exist_ok=True)

print("Downloading S-Labs dataset...")

dataset = load_dataset("S-Labs/prompt-injection-dataset")

print("\nAvailable splits:", list(dataset.keys()))

for split_name, split_data in dataset.items():
    print(f"\nSplit: {split_name}")
    print("Number of rows:", len(split_data))
    print("Columns:", split_data.column_names)

    df = split_data.to_pandas()

    filename = output_dir / f"s_labs_{split_name}.csv"
    df.to_csv(filename, index=False)

    print("Saved:", filename)

print("\nS-Labs download completed!")
