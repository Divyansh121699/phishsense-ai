import sys
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split


RANDOM_STATE = 42

TRAIN_RATIO = 0.70
VALIDATION_RATIO = 0.15
TEST_RATIO = 0.15


def load_dataset(file_path):
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(f"Dataset not found: {file_path}")

    return pd.read_csv(file_path)


def create_splits(df):
    if "email_id" not in df.columns:
        raise ValueError("Missing required column: email_id")

    if "high_level_category" not in df.columns:
        raise ValueError("Missing required column: high_level_category")

    if df["email_id"].duplicated().any():
        raise ValueError(
            "Duplicate email_id values detected. "
            "Resolve them before creating splits."
        )

    train_df, temp_df = train_test_split(
        df,
        test_size=(VALIDATION_RATIO + TEST_RATIO),
        stratify=df["high_level_category"],
        random_state=RANDOM_STATE,
    )

    relative_test_ratio = TEST_RATIO / (
        VALIDATION_RATIO + TEST_RATIO
    )

    validation_df, test_df = train_test_split(
        temp_df,
        test_size=relative_test_ratio,
        stratify=temp_df["high_level_category"],
        random_state=RANDOM_STATE,
    )

    split_map = pd.concat(
        [
            train_df[["email_id"]].assign(split="train"),
            validation_df[["email_id"]].assign(split="validation"),
            test_df[["email_id"]].assign(split="test"),
        ],
        ignore_index=True,
    )

    return split_map


def print_summary(split_map, original_df):
    merged = split_map.merge(
        original_df[
            [
                "email_id",
                "high_level_category",
                "source_dataset",
                "generation_type",
            ]
        ],
        on="email_id",
        how="left",
    )

    print("\nSplit counts:")
    print(split_map["split"].value_counts())

    print("\nSplit percentages:")
    print(
        (
            split_map["split"].value_counts(normalize=True) * 100
        ).round(2)
    )

    print("\nClass distribution by split:")
    print(
        pd.crosstab(
            merged["split"],
            merged["high_level_category"],
            margins=True,
        )
    )

    print("\nSource distribution by split:")
    print(
        pd.crosstab(
            merged["split"],
            merged["source_dataset"],
            margins=True,
        )
    )

    print("\nGeneration type distribution by split:")
    print(
        pd.crosstab(
            merged["split"],
            merged["generation_type"],
            margins=True,
        )
    )


def save_split_map(split_map, output_path):
    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    split_map.to_csv(
        output_path,
        index=False,
    )

    print(f"\nSaved split mapping to:")
    print(output_path)


def main():
    if len(sys.argv) != 3:
        print(
            "Usage:\n"
            "python create_splits.py "
            "<dataset.csv> "
            "<output_split.csv>"
        )
        sys.exit(1)

    dataset_path = sys.argv[1]
    output_path = sys.argv[2]

    df = load_dataset(dataset_path)

    split_map = create_splits(df)

    print_summary(
        split_map,
        df,
    )

    save_split_map(
        split_map,
        output_path,
    )


if __name__ == "__main__":
    main()