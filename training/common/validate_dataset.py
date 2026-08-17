import sys
from pathlib import Path

import pandas as pd


# -------------------------------------------------------------------
# Fixed PhishSenseAI dataset schema
# -------------------------------------------------------------------

REQUIRED_COLUMNS = [
    "email_id",
    "source_dataset",
    "source_file",
    "high_level_category",
    "subcategory",
    "sender",
    "receiver",
    "subject",
    "date",
    "body_text",
    "body_html",
    "urls",
    "url_count",
    "has_url",
    "has_attachment",
    "attachment_count",
    "has_image",
    "image_count",
    "received_headers",
    "authentication_results",
    "generation_type",
    "is_html",
    "is_plain_text",
    "dataset_source",
    "message_id",
    "Shuffle",
]

VALID_HIGH_LEVEL_LABELS = {
    "phishing",
    "benign",
}


# -------------------------------------------------------------------
# Helper functions
# -------------------------------------------------------------------

def print_section(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def load_dataset(file_path):
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(f"Dataset not found: {file_path}")

    if file_path.suffix.lower() != ".csv":
        raise ValueError("Dataset must be a CSV file.")

    return pd.read_csv(file_path)


def validate_columns(df):
    missing_columns = [
        column for column in REQUIRED_COLUMNS
        if column not in df.columns
    ]

    extra_columns = [
        column for column in df.columns
        if column not in REQUIRED_COLUMNS
    ]

    print_section("1. SCHEMA VALIDATION")

    if missing_columns:
        print("FAIL: Missing required columns:")
        for column in missing_columns:
            print(f"  - {column}")
    else:
        print("PASS: All required columns are present.")

    if extra_columns:
        print("\nAdditional columns detected:")
        for column in extra_columns:
            print(f"  - {column}")
    else:
        print("PASS: No unexpected columns detected.")

    return len(missing_columns) == 0


def validate_email_ids(df):
    print_section("2. EMAIL ID VALIDATION")

    missing_ids = df["email_id"].isna().sum()

    duplicate_mask = df["email_id"].duplicated(keep=False)
    duplicate_rows = df.loc[
        duplicate_mask,
        ["email_id", "source_dataset", "source_file"]
    ]

    print(f"Missing email_id values: {missing_ids}")
    print(f"Unique email_id values: {df['email_id'].nunique(dropna=True)}")
    print(f"Total rows: {len(df)}")

    if missing_ids == 0:
        print("PASS: No missing email IDs.")
    else:
        print("WARNING: Missing email IDs detected.")

    if duplicate_rows.empty:
        print("PASS: All email IDs are unique.")
    else:
        print(
            f"WARNING: {duplicate_rows['email_id'].nunique()} "
            "duplicated email ID(s) detected."
        )

        print("\nDuplicate email ID records:")
        print(duplicate_rows.to_string(index=False))


def validate_labels(df):
    print_section("3. LABEL VALIDATION")

    labels = (
        df["high_level_category"]
        .dropna()
        .astype(str)
        .str.strip()
        .str.lower()
    )

    invalid_labels = sorted(
        set(labels.unique()) - VALID_HIGH_LEVEL_LABELS
    )

    missing_labels = df["high_level_category"].isna().sum()

    print(f"Missing high-level labels: {missing_labels}")

    print("\nHigh-level category distribution:")
    print(
        df["high_level_category"]
        .value_counts(dropna=False)
        .to_string()
    )

    if invalid_labels:
        print("\nWARNING: Unexpected high-level labels detected:")
        for label in invalid_labels:
            print(f"  - {label}")
    else:
        print("\nPASS: High-level labels are valid.")


def check_body_text(df):
    print_section("4. BODY TEXT VALIDATION")

    missing_body = df["body_text"].isna().sum()

    empty_body = (
        df["body_text"]
        .fillna("")
        .astype(str)
        .str.strip()
        .eq("")
        .sum()
    )

    print(f"Missing body_text values: {missing_body}")
    print(f"Empty body_text values: {empty_body}")

    if missing_body == 0 and empty_body == 0:
        print("PASS: Every record contains body text.")
    else:
        print(
            "WARNING: Some records do not contain usable body text."
        )


def check_missing_values(df):
    print_section("5. MISSING VALUE SUMMARY")

    missing = df.isna().sum()
    missing_percent = (missing / len(df) * 100).round(2)

    missing_table = pd.DataFrame(
        {
            "missing_count": missing,
            "missing_percent": missing_percent,
        }
    )

    missing_table = missing_table[
        missing_table["missing_count"] > 0
    ].sort_values(
        "missing_percent",
        ascending=False
    )

    if missing_table.empty:
        print("PASS: No missing values detected.")
    else:
        print(missing_table.to_string())


def check_duplicates(df):
    print_section("6. DUPLICATE CONTENT CHECK")

    normalized_body = (
        df["body_text"]
        .fillna("")
        .astype(str)
        .str.lower()
        .str.strip()
        .str.replace(r"\s+", " ", regex=True)
    )

    duplicate_body_mask = normalized_body.duplicated(
        keep=False
    ) & normalized_body.ne("")

    duplicate_body_count = duplicate_body_mask.sum()

    duplicate_groups = (
        normalized_body[duplicate_body_mask]
        .value_counts()
    )

    print(
        f"Rows participating in duplicate body-text groups: "
        f"{duplicate_body_count}"
    )

    print(
        f"Number of duplicate body-text groups: "
        f"{len(duplicate_groups)}"
    )

    if duplicate_body_count == 0:
        print("PASS: No duplicate body text detected.")
    else:
        print(
            "WARNING: Duplicate body text exists. "
            "Review before creating train/validation/test splits."
        )


def check_label_conflicts(df):
    print_section("7. DUPLICATE LABEL CONFLICT CHECK")

    temp = df[
        ["body_text", "high_level_category"]
    ].copy()

    temp["normalized_body"] = (
        temp["body_text"]
        .fillna("")
        .astype(str)
        .str.lower()
        .str.strip()
        .str.replace(r"\s+", " ", regex=True)
    )

    temp = temp[temp["normalized_body"] != ""]

    conflict_counts = (
        temp.groupby("normalized_body")[
            "high_level_category"
        ]
        .nunique()
    )

    conflicts = conflict_counts[conflict_counts > 1]

    if conflicts.empty:
        print(
            "PASS: No identical body text appears with "
            "conflicting high-level labels."
        )
    else:
        print(
            f"WARNING: {len(conflicts)} duplicate body-text "
            "group(s) contain conflicting labels."
        )


def check_source_distribution(df):
    print_section("8. SOURCE AND CLASS DISTRIBUTION")

    source_column = None

    if "source_dataset" in df.columns:
        source_column = "source_dataset"
    elif "dataset_source" in df.columns:
        source_column = "dataset_source"

    if source_column is None:
        print("Source field not available.")
        return

    print(f"Using source field: {source_column}")

    distribution = pd.crosstab(
        df[source_column],
        df["high_level_category"],
        margins=True,
    )

    print("\nSource x high-level category:")
    print(distribution.to_string())


def check_generation_distribution(df):
    print_section("9. GENERATION TYPE DISTRIBUTION")

    if "generation_type" not in df.columns:
        print("generation_type column not available.")
        return

    print(
        df["generation_type"]
        .value_counts(dropna=False)
        .to_string()
    )


def check_numeric_fields(df):
    print_section("10. NUMERIC FEATURE VALIDATION")

    numeric_columns = [
        "url_count",
        "attachment_count",
        "image_count",
    ]

    for column in numeric_columns:
        numeric_values = pd.to_numeric(
            df[column],
            errors="coerce",
        )

        invalid = (
            numeric_values.isna()
            & df[column].notna()
        ).sum()

        negative = (numeric_values < 0).sum()

        print(
            f"{column}: "
            f"invalid={invalid}, "
            f"negative={negative}"
        )


def check_boolean_fields(df):
    print_section("11. BOOLEAN FEATURE VALIDATION")

    boolean_columns = [
        "has_url",
        "has_attachment",
        "has_image",
        "is_html",
        "is_plain_text",
    ]

    allowed_values = {
        "true",
        "false",
        "1",
        "0",
        "yes",
        "no",
    }

    for column in boolean_columns:

        values = (
            df[column]
            .dropna()
            .astype(str)
            .str.strip()
            .str.lower()
        )

        invalid_values = sorted(
            set(values.unique()) - allowed_values
        )

        if invalid_values:
            print(
                f"{column}: WARNING unexpected values "
                f"{invalid_values}"
            )
        else:
            print(f"{column}: PASS")


def dataset_summary(df):
    print_section("12. DATASET SUMMARY")

    total = len(df)

    print(f"Total records: {total}")
    print(f"Total columns: {len(df.columns)}")

    if "high_level_category" in df.columns:
        print("\nClass distribution:")

        counts = df[
            "high_level_category"
        ].value_counts(dropna=False)

        for label, count in counts.items():
            percent = (
                count / total * 100
                if total
                else 0
            )

            print(
                f"  {label}: "
                f"{count} ({percent:.2f}%)"
            )

    if "body_text" in df.columns:
        words = (
            df["body_text"]
            .fillna("")
            .astype(str)
            .str.split()
            .str.len()
        )

        print("\nBody-text word statistics:")
        print(f"  Mean: {words.mean():.2f}")
        print(f"  Median: {words.median():.2f}")
        print(f"  Minimum: {words.min()}")
        print(f"  Maximum: {words.max()}")


def validate_dataset(file_path):
    print("\nPhishSenseAI Dataset Validator")
    print(f"Dataset: {file_path}")

    df = load_dataset(file_path)

    schema_valid = validate_columns(df)

    if not schema_valid:
        print_section("VALIDATION STOPPED")
        print(
            "Dataset does not match the fixed "
            "PhishSenseAI schema."
        )
        return False

    validate_email_ids(df)
    validate_labels(df)
    check_body_text(df)
    check_missing_values(df)
    check_duplicates(df)
    check_label_conflicts(df)
    check_source_distribution(df)
    check_generation_distribution(df)
    check_numeric_fields(df)
    check_boolean_fields(df)
    dataset_summary(df)

    print_section("VALIDATION COMPLETE")

    print(
        "The dataset has been checked against the fixed "
        "PhishSenseAI schema."
    )

    print(
        "Warnings should be reviewed before creating the "
        "common train/validation/test split."
    )

    return True


# -------------------------------------------------------------------
# Command-line execution
# -------------------------------------------------------------------

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print(
            "Usage:\n"
            "python validate_dataset.py "
            "<path_to_dataset.csv>"
        )
        sys.exit(1)

    dataset_path = sys.argv[1]

    try:
        success = validate_dataset(dataset_path)

        if not success:
            sys.exit(1)

    except Exception as error:
        print(f"\nERROR: {error}")
        sys.exit(1)