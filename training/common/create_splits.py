import sys
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.model_selection import (
    StratifiedGroupKFold,
    train_test_split,
)


# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------

RANDOM_STATE = 42

TARGET_RECORDS = 3000

TRAIN_RATIO = 0.70
VALIDATION_RATIO = 0.15
TEST_RATIO = 0.15

# 20 folds lets us represent:
#
# 14 folds = 70%
# 3 folds  = 15%
# 3 folds  = 15%
#
N_SPLIT_FOLDS = 20


# -------------------------------------------------------------------
# Data loading
# -------------------------------------------------------------------

def load_dataset(file_path):

    file_path = Path(
        file_path
    )

    if not file_path.exists():

        raise FileNotFoundError(
            f"Dataset not found: "
            f"{file_path}"
        )

    return pd.read_csv(
        file_path
    )


# -------------------------------------------------------------------
# Body normalization
# -------------------------------------------------------------------

def normalize_body_text(series):

    return (
        series
        .fillna("")
        .astype(str)
        .str.lower()
        .str.strip()
        .str.replace(
            r"\s+",
            " ",
            regex=True,
        )
    )


# -------------------------------------------------------------------
# Quality-aware selection
# -------------------------------------------------------------------

def select_quality_records(
    df,
    target_records=TARGET_RECORDS,
):

    print(
        "\n"
        + "=" * 70
    )

    print(
        "QUALITY-AWARE RECORD SELECTION"
    )

    print(
        "=" * 70
    )

    original_count = len(
        df
    )

    print(
        f"\nOriginal records: "
        f"{original_count}"
    )

    # --------------------------------------------------------
    # Required columns
    # --------------------------------------------------------

    required_columns = [
        "email_id",
        "source_dataset",
        "high_level_category",
        "body_text",
    ]

    missing_columns = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing_columns:

        raise ValueError(
            "Dataset missing required "
            f"columns: {missing_columns}"
        )

    # --------------------------------------------------------
    # Step 1:
    # Remove duplicate email_id copies.
    # --------------------------------------------------------

    duplicate_id_count = int(
        df["email_id"]
        .duplicated(
            keep="first"
        )
        .sum()
    )

    df = (
        df
        .drop_duplicates(
            subset=[
                "email_id"
            ],
            keep="first",
        )
        .copy()
    )

    print(
        "Duplicate email-ID copies removed: "
        f"{duplicate_id_count}"
    )

    print(
        "Records after email-ID deduplication: "
        f"{len(df)}"
    )

    if len(df) < target_records:

        raise ValueError(
            f"Only {len(df)} records remain "
            "after email-ID deduplication, "
            f"but {target_records} were requested."
        )

    # --------------------------------------------------------
    # Step 2:
    # Normalize email body text.
    # --------------------------------------------------------

    df[
        "_normalized_body"
    ] = normalize_body_text(
        df["body_text"]
    )

    # --------------------------------------------------------
    # Step 3:
    # Verify identical email bodies do not have
    # conflicting phishing/benign labels.
    # --------------------------------------------------------

    non_empty = (
        df[
            df["_normalized_body"]
            != ""
        ]
    )

    body_label_counts = (
        non_empty
        .groupby(
            "_normalized_body"
        )[
            "high_level_category"
        ]
        .nunique()
    )

    conflicting_bodies = (
        body_label_counts[
            body_label_counts > 1
        ]
    )

    if not conflicting_bodies.empty:

        raise ValueError(
            f"{len(conflicting_bodies)} "
            "identical email-body group(s) "
            "contain conflicting labels."
        )

    # --------------------------------------------------------
    # Step 4:
    # Identify only EXTRA repeated-body copies.
    #
    # rank = 0:
    # first copy, always protected
    #
    # rank > 0:
    # removable duplicate copy
    # --------------------------------------------------------

    df[
        "_body_duplicate_rank"
    ] = 0

    valid_body_mask = (
        df["_normalized_body"]
        != ""
    )

    df.loc[
        valid_body_mask,
        "_body_duplicate_rank",
    ] = (
        df.loc[
            valid_body_mask
        ]
        .groupby(
            "_normalized_body"
        )
        .cumcount()
    )

    duplicate_candidates = (
        df[
            df[
                "_body_duplicate_rank"
            ] > 0
        ]
        .copy()
    )

    print(
        "Extra repeated-body copies available: "
        f"{len(duplicate_candidates)}"
    )

    records_to_remove = (
        len(df)
        - target_records
    )

    print(
        "Records that need to be removed "
        f"to reach {target_records}: "
        f"{records_to_remove}"
    )

    # --------------------------------------------------------
    # Step 5:
    # Preferentially remove duplicate-body copies.
    # --------------------------------------------------------

    if records_to_remove > 0:

        if (
            len(duplicate_candidates)
            >= records_to_remove
        ):

            duplicate_candidates[
                "_selection_stratum"
            ] = (
                duplicate_candidates[
                    "source_dataset"
                ]
                .astype(str)
                .str.strip()
                + "__"
                + duplicate_candidates[
                    "high_level_category"
                ]
                .astype(str)
                .str.strip()
                .str.lower()
            )

            stratum_counts = (
                duplicate_candidates[
                    "_selection_stratum"
                ]
                .value_counts()
            )

            can_stratify = (
                len(stratum_counts) > 1
                and stratum_counts.min() >= 2
                and records_to_remove
                >= len(stratum_counts)
                and (
                    len(duplicate_candidates)
                    - records_to_remove
                )
                >= len(stratum_counts)
            )

            if can_stratify:

                (
                    remove_indices,
                    _,
                ) = train_test_split(
                    duplicate_candidates.index,
                    train_size=(
                        records_to_remove
                    ),
                    stratify=(
                        duplicate_candidates[
                            "_selection_stratum"
                        ]
                    ),
                    random_state=(
                        RANDOM_STATE
                    ),
                )

            else:

                print(
                    "\nNOTE: Source/class-stratified "
                    "duplicate removal was not "
                    "possible."
                )

                print(
                    "Using reproducible random "
                    "removal from duplicate copies."
                )

                remove_indices = (
                    duplicate_candidates
                    .sample(
                        n=records_to_remove,
                        random_state=(
                            RANDOM_STATE
                        ),
                    )
                    .index
                )

            df = df.drop(
                index=remove_indices
            )

        else:

            # ------------------------------------------------
            # Remove every duplicate-body copy first.
            # ------------------------------------------------

            df = df.drop(
                index=(
                    duplicate_candidates.index
                )
            )

            remaining_to_remove = (
                len(df)
                - target_records
            )

            # ------------------------------------------------
            # If more records still need to be removed,
            # select remaining records using source + class
            # stratification.
            # ------------------------------------------------

            if remaining_to_remove > 0:

                df[
                    "_selection_stratum"
                ] = (
                    df[
                        "source_dataset"
                    ]
                    .astype(str)
                    .str.strip()
                    + "__"
                    + df[
                        "high_level_category"
                    ]
                    .astype(str)
                    .str.strip()
                    .str.lower()
                )

                keep_count = (
                    len(df)
                    - remaining_to_remove
                )

                (
                    kept_indices,
                    _,
                ) = train_test_split(
                    df.index,
                    train_size=keep_count,
                    stratify=(
                        df[
                            "_selection_stratum"
                        ]
                    ),
                    random_state=(
                        RANDOM_STATE
                    ),
                )

                df = (
                    df.loc[
                        kept_indices
                    ]
                    .copy()
                )

    # --------------------------------------------------------
    # Step 6:
    # Remove helper columns.
    # --------------------------------------------------------

    helper_columns = [
        "_normalized_body",
        "_body_duplicate_rank",
        "_selection_stratum",
    ]

    df = df.drop(
        columns=[
            column
            for column in helper_columns
            if column in df.columns
        ]
    )

    # --------------------------------------------------------
    # Step 7:
    # Reproducible shuffle.
    # --------------------------------------------------------

    df = (
        df
        .sample(
            frac=1,
            random_state=RANDOM_STATE,
        )
        .reset_index(
            drop=True
        )
    )

    # --------------------------------------------------------
    # Final checks
    # --------------------------------------------------------

    if len(df) != target_records:

        raise ValueError(
            f"Expected {target_records} records "
            f"but selected {len(df)}."
        )

    if (
        df["email_id"]
        .duplicated()
        .any()
    ):

        raise ValueError(
            "Duplicate email IDs remain "
            "after selection."
        )

    print(
        f"\nFinal selected records: "
        f"{len(df)}"
    )

    print(
        "\nFinal class distribution:"
    )

    print(
        df[
            "high_level_category"
        ]
        .value_counts()
        .to_string()
    )

    print(
        "\nFinal source distribution:"
    )

    print(
        df[
            "source_dataset"
        ]
        .value_counts()
        .to_string()
    )

    print(
        "\nFinal source x class distribution:"
    )

    print(
        pd.crosstab(
            df[
                "source_dataset"
            ],
            df[
                "high_level_category"
            ],
            margins=True,
        )
        .to_string()
    )

    return df


# -------------------------------------------------------------------
# Leakage-safe splitting
# -------------------------------------------------------------------

def create_splits(df):

    if "email_id" not in df.columns:

        raise ValueError(
            "Missing required column: "
            "email_id"
        )

    if (
        "high_level_category"
        not in df.columns
    ):

        raise ValueError(
            "Missing required column: "
            "high_level_category"
        )

    if (
        "source_dataset"
        not in df.columns
    ):

        raise ValueError(
            "Missing required column: "
            "source_dataset"
        )

    if (
        "body_text"
        not in df.columns
    ):

        raise ValueError(
            "Missing required column: "
            "body_text"
        )

    if (
        df["email_id"]
        .duplicated()
        .any()
    ):

        raise ValueError(
            "Duplicate email_id values detected. "
            "Resolve them before creating splits."
        )

    work = df.copy()

    # --------------------------------------------------------
    # Normalize body text.
    # Identical bodies receive the same group key.
    # --------------------------------------------------------

    work[
        "_normalized_body"
    ] = normalize_body_text(
        work["body_text"]
    )

    work[
        "_group_key"
    ] = np.where(
        work[
            "_normalized_body"
        ] != "",
        work[
            "_normalized_body"
        ],
        (
            "EMAIL_ID::"
            + work[
                "email_id"
            ]
            .astype(str)
        ),
    )

    # --------------------------------------------------------
    # Build source + class stratification target.
    # --------------------------------------------------------

    work[
        "_split_stratum"
    ] = (
        work[
            "source_dataset"
        ]
        .astype(str)
        .str.strip()
        + "__"
        + work[
            "high_level_category"
        ]
        .astype(str)
        .str.strip()
        .str.lower()
    )

    # --------------------------------------------------------
    # Check source/class group sizes.
    # --------------------------------------------------------

    group_counts = (
        work
        .groupby(
            "_split_stratum"
        )[
            "_group_key"
        ]
        .nunique()
    )

    if (
        group_counts.min()
        >= N_SPLIT_FOLDS
    ):

        stratification_target = (
            work[
                "_split_stratum"
            ]
        )

        print(
            "\nUsing source + class "
            "group-aware stratification."
        )

    else:

        stratification_target = (
            work[
                "high_level_category"
            ]
        )

        print(
            "\nNOTE: Some source/class groups "
            "are too small for 20-fold "
            "stratification."
        )

        print(
            "Using class-only group-aware "
            "stratification."
        )

    # --------------------------------------------------------
    # Create 20 group-aware folds.
    # --------------------------------------------------------

    splitter = (
        StratifiedGroupKFold(
            n_splits=(
                N_SPLIT_FOLDS
            ),
            shuffle=True,
            random_state=(
                RANDOM_STATE
            ),
        )
    )

    fold_assignments = (
        np.full(
            len(work),
            -1,
            dtype=int,
        )
    )

    for (
        fold_number,
        (
            _,
            fold_indices,
        ),
    ) in enumerate(
        splitter.split(
            X=work,
            y=(
                stratification_target
            ),
            groups=(
                work[
                    "_group_key"
                ]
            ),
        )
    ):

        fold_assignments[
            fold_indices
        ] = fold_number

    work[
        "_fold"
    ] = fold_assignments

    if (
        work[
            "_fold"
        ] < 0
    ).any():

        raise RuntimeError(
            "Some records were not assigned "
            "to a split fold."
        )

    # --------------------------------------------------------
    # Fold assignment:
    #
    # 0-13  -> train       70%
    # 14-16 -> validation  15%
    # 17-19 -> test        15%
    # --------------------------------------------------------

    work[
        "split"
    ] = "test"

    work.loc[
        work[
            "_fold"
        ].between(
            0,
            13,
        ),
        "split",
    ] = "train"

    work.loc[
        work[
            "_fold"
        ].between(
            14,
            16,
        ),
        "split",
    ] = "validation"

    work.loc[
        work[
            "_fold"
        ].between(
            17,
            19,
        ),
        "split",
    ] = "test"

    # --------------------------------------------------------
    # Critical leakage check:
    # No identical normalized body may occur
    # in multiple splits.
    # --------------------------------------------------------

    group_split_counts = (
        work
        .groupby(
            "_group_key"
        )[
            "split"
        ]
        .nunique()
    )

    crossing_groups = (
        group_split_counts[
            group_split_counts > 1
        ]
    )

    if not crossing_groups.empty:

        raise RuntimeError(
            f"{len(crossing_groups)} "
            "email-body group(s) crossed "
            "split boundaries."
        )

    print(
        "\nPASS: Body groups crossing "
        "train/validation/test splits: 0"
    )

    split_map = (
        work[
            [
                "email_id",
                "split",
            ]
        ]
        .copy()
        .reset_index(
            drop=True
        )
    )

    return split_map


# -------------------------------------------------------------------
# Split summary
# -------------------------------------------------------------------

def print_summary(
    split_map,
    original_df,
):

    merged = (
        split_map.merge(
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
    )

    print(
        "\nSplit counts:"
    )

    print(
        split_map[
            "split"
        ]
        .value_counts()
    )

    print(
        "\nSplit percentages:"
    )

    print(
        (
            split_map[
                "split"
            ]
            .value_counts(
                normalize=True
            )
            * 100
        ).round(2)
    )

    print(
        "\nClass distribution by split:"
    )

    print(
        pd.crosstab(
            merged[
                "split"
            ],
            merged[
                "high_level_category"
            ],
            margins=True,
        )
    )

    print(
        "\nSource distribution by split:"
    )

    print(
        pd.crosstab(
            merged[
                "split"
            ],
            merged[
                "source_dataset"
            ],
            margins=True,
        )
    )

    print(
        "\nGeneration type distribution "
        "by split:"
    )

    print(
        pd.crosstab(
            merged[
                "split"
            ],
            merged[
                "generation_type"
            ],
            margins=True,
        )
    )


# -------------------------------------------------------------------
# Save selected dataset
# -------------------------------------------------------------------

def save_selected_dataset(
    df,
    output_path,
):

    output_path = Path(
        output_path
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    df.to_csv(
        output_path,
        index=False,
    )

    print(
        "\nSaved selected analysis dataset to:"
    )

    print(
        output_path
    )


# -------------------------------------------------------------------
# Save split mapping
# -------------------------------------------------------------------

def save_split_map(
    split_map,
    output_path,
):

    output_path = Path(
        output_path
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    split_map.to_csv(
        output_path,
        index=False,
    )

    print(
        "\nSaved split mapping to:"
    )

    print(
        output_path
    )


# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------

def main():

    if len(sys.argv) != 4:

        print(
            "Usage:\n"
            "python create_splits.py "
            "<dataset.csv> "
            "<selected_dataset.csv> "
            "<output_split.csv>"
        )

        sys.exit(1)

    dataset_path = (
        sys.argv[1]
    )

    selected_dataset_path = (
        sys.argv[2]
    )

    output_split_path = (
        sys.argv[3]
    )

    # --------------------------------------------------------
    # Load original dataset.
    # --------------------------------------------------------

    df = load_dataset(
        dataset_path
    )

    # --------------------------------------------------------
    # Select exactly 3,000 quality-controlled records.
    # --------------------------------------------------------

    selected_df = (
        select_quality_records(
            df,
            target_records=(
                TARGET_RECORDS
            ),
        )
    )

    # --------------------------------------------------------
    # Save exact selected dataset.
    # --------------------------------------------------------

    save_selected_dataset(
        selected_df,
        selected_dataset_path,
    )

    # --------------------------------------------------------
    # Create common leakage-safe split.
    # --------------------------------------------------------

    split_map = (
        create_splits(
            selected_df
        )
    )

    # --------------------------------------------------------
    # Print split summary.
    # --------------------------------------------------------

    print_summary(
        split_map,
        selected_df,
    )

    # --------------------------------------------------------
    # Save split mapping.
    # --------------------------------------------------------

    save_split_map(
        split_map,
        output_split_path,
    )


# -------------------------------------------------------------------
# Command-line execution
# -------------------------------------------------------------------

if __name__ == "__main__":
    main()