import argparse
import json
import re
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from scipy.sparse import csr_matrix, hstack

from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GridSearchCV


RANDOM_STATE = 42

LABEL_MAP = {
    "benign": 0,
    "phishing": 1,
}


# ---------------------------------------------------------------------
# Text preprocessing
# Paper-guided adaptation:
# - clean body text
# - lowercase
# - normalize whitespace
# - retain useful textual content for TF-IDF
# ---------------------------------------------------------------------

def clean_text(text):
    if pd.isna(text):
        return ""

    text = str(text).lower()

    # Remove HTML tags if any remain in body_text
    text = re.sub(r"<[^>]+>", " ", text)

    # Normalize line breaks / tabs
    text = re.sub(r"[\r\n\t]+", " ", text)

    # Collapse repeated whitespace
    text = re.sub(r"\s+", " ", text)

    return text.strip()


# ---------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------

def safe_text(value):
    if pd.isna(value):
        return ""
    return str(value)


def safe_numeric(value):
    try:
        if pd.isna(value):
            return 0
        return float(value)
    except (TypeError, ValueError):
        return 0


def safe_bool(value):
    if pd.isna(value):
        return 0

    value = str(value).strip().lower()

    if value in {"1", "true", "yes"}:
        return 1

    return 0


# ---------------------------------------------------------------------
# Static feature extraction
#
# These are derived ONLY from fields already present in the fixed
# PhishSenseAI schema.
# ---------------------------------------------------------------------

def extract_static_features(df):
    features = pd.DataFrame(index=df.index)

    # --------------------------------------------------------------
    # Existing numeric / boolean schema features
    # --------------------------------------------------------------

    features["url_count"] = (
        df["url_count"]
        .apply(safe_numeric)
    )

    features["attachment_count"] = (
        df["attachment_count"]
        .apply(safe_numeric)
    )

    features["image_count"] = (
        df["image_count"]
        .apply(safe_numeric)
    )

    features["has_url"] = (
        df["has_url"]
        .apply(safe_bool)
    )

    features["has_attachment"] = (
        df["has_attachment"]
        .apply(safe_bool)
    )

    features["has_image"] = (
        df["has_image"]
        .apply(safe_bool)
    )

    features["is_html"] = (
        df["is_html"]
        .apply(safe_bool)
    )

    features["is_plain_text"] = (
        df["is_plain_text"]
        .apply(safe_bool)
    )

    # --------------------------------------------------------------
    # Missingness indicators
    #
    # These are intentionally explicit so that missing values are not
    # silently converted into arbitrary numerical values.
    # --------------------------------------------------------------

    fields_for_missingness = [
        "sender",
        "receiver",
        "subject",
        "date",
        "body_html",
        "urls",
        "received_headers",
        "authentication_results",
        "message_id",
    ]

    for column in fields_for_missingness:
        features[f"{column}_missing"] = (
            df[column]
            .isna()
            .astype(int)
        )

    # --------------------------------------------------------------
    # Sender-related features
    # --------------------------------------------------------------

    sender = (
        df["sender"]
        .fillna("")
        .astype(str)
    )

    features["sender_length"] = (
        sender.str.len()
    )

    features["sender_has_at"] = (
        sender.str.contains(
            "@",
            regex=False,
        ).astype(int)
    )

    features["sender_digit_count"] = (
        sender.apply(
            lambda x: sum(char.isdigit() for char in x)
        )
    )

    features["sender_special_char_count"] = (
        sender.apply(
            lambda x: sum(
                not char.isalnum()
                and not char.isspace()
                for char in x
            )
        )
    )

    # --------------------------------------------------------------
    # Receiver-related features
    # --------------------------------------------------------------

    receiver = (
        df["receiver"]
        .fillna("")
        .astype(str)
    )

    features["receiver_length"] = (
        receiver.str.len()
    )

    features["receiver_count_estimate"] = (
        receiver.apply(
            lambda x: (
                len(
                    [
                        item
                        for item in re.split(
                            r"[,;]",
                            x,
                        )
                        if item.strip()
                    ]
                )
                if x.strip()
                else 0
            )
        )
    )

    # --------------------------------------------------------------
    # Subject features
    # --------------------------------------------------------------

    subject = (
        df["subject"]
        .fillna("")
        .astype(str)
    )

    features["subject_length"] = (
        subject.str.len()
    )

    features["subject_word_count"] = (
        subject.apply(
            lambda x: len(x.split())
        )
    )

    features["subject_digit_count"] = (
        subject.apply(
            lambda x: sum(char.isdigit() for char in x)
        )
    )

    features["subject_uppercase_count"] = (
        subject.apply(
            lambda x: sum(char.isupper() for char in x)
        )
    )

    features["subject_exclamation_count"] = (
        subject.str.count("!")
    )

    features["subject_question_count"] = (
        subject.str.count(r"\?")
    )

    # --------------------------------------------------------------
    # Body-text structural features
    # --------------------------------------------------------------

    body = (
        df["body_text"]
        .fillna("")
        .astype(str)
    )

    features["body_character_count"] = (
        body.str.len()
    )

    features["body_word_count"] = (
        body.apply(
            lambda x: len(x.split())
        )
    )

    features["body_line_count"] = (
        body.apply(
            lambda x: (
                len(x.splitlines())
                if x
                else 0
            )
        )
    )

    features["body_digit_count"] = (
        body.apply(
            lambda x: sum(char.isdigit() for char in x)
        )
    )

    features["body_uppercase_count"] = (
        body.apply(
            lambda x: sum(char.isupper() for char in x)
        )
    )

    features["body_exclamation_count"] = (
        body.str.count("!")
    )

    features["body_question_count"] = (
        body.str.count(r"\?")
    )

    features["body_dollar_count"] = (
        body.str.count(r"\$")
    )

    # --------------------------------------------------------------
    # HTML-related features
    # --------------------------------------------------------------

    html = (
        df["body_html"]
        .fillna("")
        .astype(str)
    )

    features["html_length"] = (
        html.str.len()
    )

    features["html_tag_count"] = (
        html.apply(
            lambda x: len(
                re.findall(
                    r"<[^>]+>",
                    x,
                )
            )
        )
    )

    features["html_link_tag_count"] = (
        html.apply(
            lambda x: len(
                re.findall(
                    r"<a\b",
                    x,
                    flags=re.IGNORECASE,
                )
            )
        )
    )

    features["html_form_tag_count"] = (
        html.apply(
            lambda x: len(
                re.findall(
                    r"<form\b",
                    x,
                    flags=re.IGNORECASE,
                )
            )
        )
    )

    features["html_script_tag_count"] = (
        html.apply(
            lambda x: len(
                re.findall(
                    r"<script\b",
                    x,
                    flags=re.IGNORECASE,
                )
            )
        )
    )

    # --------------------------------------------------------------
    # URL-derived features
    # --------------------------------------------------------------

    urls = (
        df["urls"]
        .fillna("")
        .astype(str)
    )

    features["url_text_length"] = (
        urls.str.len()
    )

    features["url_https_count"] = (
        urls.str.count(
            r"https://"
        )
    )

    features["url_http_count"] = (
        urls.str.count(
            r"http://"
        )
    )

    features["url_ip_pattern_count"] = (
        urls.apply(
            lambda x: len(
                re.findall(
                    r"https?://\d{1,3}(?:\.\d{1,3}){3}",
                    x,
                    flags=re.IGNORECASE,
                )
            )
        )
    )

    # --------------------------------------------------------------
    # Header / authentication features
    # --------------------------------------------------------------

    received_headers = (
        df["received_headers"]
        .fillna("")
        .astype(str)
    )

    authentication = (
        df["authentication_results"]
        .fillna("")
        .astype(str)
        .str.lower()
    )

    features["received_header_length"] = (
        received_headers.str.len()
    )

    features["received_header_count"] = (
        received_headers.apply(
            lambda x: (
                len(
                    re.findall(
                        r"received:",
                        x,
                        flags=re.IGNORECASE,
                    )
                )
            )
        )
    )

    features["auth_result_length"] = (
        authentication.str.len()
    )

    features["auth_contains_spf"] = (
        authentication
        .str.contains(
            "spf",
            regex=False,
        )
        .astype(int)
    )

    features["auth_contains_dkim"] = (
        authentication
        .str.contains(
            "dkim",
            regex=False,
        )
        .astype(int)
    )

    features["auth_contains_dmarc"] = (
        authentication
        .str.contains(
            "dmarc",
            regex=False,
        )
        .astype(int)
    )

    features["auth_contains_fail"] = (
        authentication
        .str.contains(
            "fail",
            regex=False,
        )
        .astype(int)
    )

    features["auth_contains_pass"] = (
        authentication
        .str.contains(
            "pass",
            regex=False,
        )
        .astype(int)
    )

    return features.astype(float)


# ---------------------------------------------------------------------
# Load common dataset and split mapping
# ---------------------------------------------------------------------

def load_data(dataset_path, split_path):
    dataset = pd.read_csv(dataset_path)
    splits = pd.read_csv(split_path)

    required_columns = {
        "email_id",
        "high_level_category",
        "body_text",
        "sender",
        "receiver",
        "subject",
        "date",
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
        "is_html",
        "is_plain_text",
        "message_id",
    }

    missing = required_columns - set(dataset.columns)

    if missing:
        raise ValueError(
            f"Dataset missing required columns: {sorted(missing)}"
        )

    if dataset["email_id"].duplicated().any():
        raise ValueError(
            "Duplicate email_id values found in dataset."
        )

    if splits["email_id"].duplicated().any():
        raise ValueError(
            "Duplicate email_id values found in split file."
        )

    data = dataset.merge(
        splits,
        on="email_id",
        how="inner",
        validate="one_to_one",
    )

    if len(data) != len(splits):
        raise ValueError(
            "Some split-file email IDs were not found in dataset."
        )

    data["label"] = (
        data["high_level_category"]
        .astype(str)
        .str.strip()
        .str.lower()
        .map(LABEL_MAP)
    )

    if data["label"].isna().any():
        raise ValueError(
            "Unexpected values found in high_level_category."
        )

    data["clean_text"] = (
        data["body_text"]
        .fillna("")
        .apply(clean_text)
    )

    return data


# ---------------------------------------------------------------------
# Prepare combined static + TF-IDF feature matrices
# ---------------------------------------------------------------------

def prepare_features(
    train_data,
    validation_data,
    test_data,
):
    print("\nExtracting static features...")

    train_static = extract_static_features(
        train_data
    )

    validation_static = extract_static_features(
        validation_data
    )

    test_static = extract_static_features(
        test_data
    )

    static_feature_names = list(
        train_static.columns
    )

    print(
        f"Static features extracted: "
        f"{len(static_feature_names)}"
    )

    # --------------------------------------------------------------
    # TF-IDF
    #
    # Zhang et al. evaluates textual representations including
    # TF-IDF; we use 600 dimensions as a paper-guided configuration.
    # --------------------------------------------------------------

    print("\nGenerating TF-IDF features...")

    tfidf = TfidfVectorizer(
        max_features=600,
    )

    train_tfidf = tfidf.fit_transform(
        train_data["clean_text"]
    )

    validation_tfidf = tfidf.transform(
        validation_data["clean_text"]
    )

    test_tfidf = tfidf.transform(
        test_data["clean_text"]
    )

    print(
        f"TF-IDF dimensions: "
        f"{train_tfidf.shape[1]}"
    )

    train_static_sparse = csr_matrix(
        train_static.values
    )

    validation_static_sparse = csr_matrix(
        validation_static.values
    )

    test_static_sparse = csr_matrix(
        test_static.values
    )

    X_train = hstack(
        [
            train_static_sparse,
            train_tfidf,
        ]
    ).tocsr()

    X_validation = hstack(
        [
            validation_static_sparse,
            validation_tfidf,
        ]
    ).tocsr()

    X_test = hstack(
        [
            test_static_sparse,
            test_tfidf,
        ]
    ).tocsr()

    print(
        f"Combined feature dimensions: "
        f"{X_train.shape[1]}"
    )

    return (
        X_train,
        X_validation,
        X_test,
        tfidf,
        static_feature_names,
    )


# ---------------------------------------------------------------------
# Random Forest model
# ---------------------------------------------------------------------

def build_model():
    model = RandomForestClassifier(
        random_state=RANDOM_STATE,
        n_jobs=-1,
        class_weight="balanced",
    )

    parameter_grid = {
        "n_estimators": [
            100,
            200,
            300,
        ],
        "max_depth": [
            None,
            20,
            40,
        ],
        "min_samples_split": [
            2,
            5,
        ],
    }

    search = GridSearchCV(
        estimator=model,
        param_grid=parameter_grid,
        scoring="f1_macro",
        cv=5,
        n_jobs=-1,
        verbose=1,
        refit=True,
    )

    return search


# ---------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------

def evaluate_model(
    model,
    X,
    y,
):
    predictions = model.predict(X)

    probabilities = model.predict_proba(
        X
    )[:, 1]

    metrics = {
        "accuracy": accuracy_score(
            y,
            predictions,
        ),
        "precision": precision_score(
            y,
            predictions,
            zero_division=0,
        ),
        "recall": recall_score(
            y,
            predictions,
            zero_division=0,
        ),
        "f1": f1_score(
            y,
            predictions,
            zero_division=0,
        ),
        "f1_macro": f1_score(
            y,
            predictions,
            average="macro",
            zero_division=0,
        ),
        "roc_auc": roc_auc_score(
            y,
            probabilities,
        ),
    }

    cm = confusion_matrix(
        y,
        predictions,
    )

    report = classification_report(
        y,
        predictions,
        target_names=[
            "benign",
            "phishing",
        ],
        digits=4,
        zero_division=0,
    )

    return (
        metrics,
        cm,
        report,
        predictions,
        probabilities,
    )


# ---------------------------------------------------------------------
# Save predictions
# ---------------------------------------------------------------------

def save_predictions(
    data,
    predictions,
    probabilities,
    output_path,
):
    result = data[
        [
            "email_id",
            "high_level_category",
        ]
    ].copy()

    result["true_label"] = (
        data["label"].values
    )

    result["predicted_label"] = (
        predictions
    )

    result["predicted_category"] = (
        result["predicted_label"]
        .map(
            {
                0: "benign",
                1: "phishing",
            }
        )
    )

    result["phishing_probability"] = (
        probabilities
    )

    result.to_csv(
        output_path,
        index=False,
    )


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Train the PhishSenseAI paper-guided "
            "Random Forest phishing detector."
        )
    )

    parser.add_argument(
        "--dataset",
        required=True,
    )

    parser.add_argument(
        "--splits",
        required=True,
    )

    parser.add_argument(
        "--output-dir",
        default="training/models/random_forest/output",
    )

    args = parser.parse_args()

    output_dir = Path(
        args.output_dir
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    print("=" * 70)
    print("PhishSenseAI - Random Forest")
    print("Paper-guided implementation")
    print("Static Features + TF-IDF")
    print("=" * 70)

    print("\nLoading dataset...")

    data = load_data(
        args.dataset,
        args.splits,
    )

    train_data = data[
        data["split"] == "train"
    ].copy()

    validation_data = data[
        data["split"] == "validation"
    ].copy()

    test_data = data[
        data["split"] == "test"
    ].copy()

    print("\nDataset split:")
    print(
        f"Train:      {len(train_data)}"
    )
    print(
        f"Validation: {len(validation_data)}"
    )
    print(
        f"Test:       {len(test_data)}"
    )

    (
        X_train,
        X_validation,
        X_test,
        tfidf,
        static_feature_names,
    ) = prepare_features(
        train_data,
        validation_data,
        test_data,
    )

    y_train = train_data["label"]
    y_validation = validation_data["label"]
    y_test = test_data["label"]

    print("\nTraining Random Forest...")
    print(
        "Combined static + TF-IDF features"
    )
    print(
        "Selection metric: macro-F1"
    )

    model = build_model()

    training_start = (
        time.perf_counter()
    )

    model.fit(
        X_train,
        y_train,
    )

    training_time = (
        time.perf_counter()
        - training_start
    )

    print(
        f"\nBest parameters: "
        f"{model.best_params_}"
    )

    print(
        f"Best cross-validation macro-F1: "
        f"{model.best_score_:.4f}"
    )

    print(
        f"Training time: "
        f"{training_time:.2f} seconds"
    )

    # --------------------------------------------------------------
    # Validation
    # --------------------------------------------------------------

    print("\n" + "=" * 70)
    print("VALIDATION RESULTS")
    print("=" * 70)

    (
        validation_metrics,
        validation_cm,
        validation_report,
        validation_predictions,
        validation_probabilities,
    ) = evaluate_model(
        model,
        X_validation,
        y_validation,
    )

    for key, value in (
        validation_metrics.items()
    ):
        print(
            f"{key}: {value:.4f}"
        )

    print("\nConfusion Matrix:")
    print(validation_cm)

    print(
        "\nClassification Report:"
    )
    print(validation_report)

    # --------------------------------------------------------------
    # Test
    # --------------------------------------------------------------

    print("\n" + "=" * 70)
    print("TEST RESULTS")
    print("=" * 70)

    inference_start = (
        time.perf_counter()
    )

    (
        test_metrics,
        test_cm,
        test_report,
        test_predictions,
        test_probabilities,
    ) = evaluate_model(
        model,
        X_test,
        y_test,
    )

    inference_time = (
        time.perf_counter()
        - inference_start
    )

    for key, value in (
        test_metrics.items()
    ):
        print(
            f"{key}: {value:.4f}"
        )

    print("\nConfusion Matrix:")
    print(test_cm)

    print(
        "\nClassification Report:"
    )
    print(test_report)

    print(
        f"\nInference time for test set: "
        f"{inference_time:.4f} seconds"
    )

    if len(test_data) > 0:
        avg_ms = (
            inference_time
            / len(test_data)
            * 1000
        )

        print(
            f"Average inference time per email: "
            f"{avg_ms:.4f} ms"
        )

    # --------------------------------------------------------------
    # Save model package
    # --------------------------------------------------------------

    model_package = {
        "model": model,
        "tfidf": tfidf,
        "static_feature_names": (
            static_feature_names
        ),
    }

    joblib.dump(
        model_package,
        output_dir
        / "random_forest_model.joblib",
    )

    # --------------------------------------------------------------
    # Save feature list
    # --------------------------------------------------------------

    with open(
        output_dir
        / "static_features.json",
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            static_feature_names,
            file,
            indent=4,
        )

    # --------------------------------------------------------------
    # Save predictions
    # --------------------------------------------------------------

    save_predictions(
        validation_data,
        validation_predictions,
        validation_probabilities,
        output_dir
        / "validation_predictions.csv",
    )

    save_predictions(
        test_data,
        test_predictions,
        test_probabilities,
        output_dir
        / "test_predictions.csv",
    )

    # --------------------------------------------------------------
    # Save metrics
    # --------------------------------------------------------------

    results = {
        "model": "Random Forest",
        "reference_method": (
            "Zhang et al. paper-guided "
            "combined static + TF-IDF features"
        ),
        "random_state": (
            RANDOM_STATE
        ),
        "tfidf_max_features": 600,
        "static_feature_count": (
            len(static_feature_names)
        ),
        "combined_feature_count": (
            X_train.shape[1]
        ),
        "best_parameters": (
            model.best_params_
        ),
        "best_cv_macro_f1": (
            model.best_score_
        ),
        "training_records": (
            len(train_data)
        ),
        "validation_records": (
            len(validation_data)
        ),
        "test_records": (
            len(test_data)
        ),
        "training_time_seconds": (
            training_time
        ),
        "test_inference_time_seconds": (
            inference_time
        ),
        "validation_metrics": (
            validation_metrics
        ),
        "test_metrics": (
            test_metrics
        ),
        "validation_confusion_matrix": (
            validation_cm.tolist()
        ),
        "test_confusion_matrix": (
            test_cm.tolist()
        ),
    }

    with open(
        output_dir
        / "metrics.json",
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            results,
            file,
            indent=4,
        )

    with open(
        output_dir
        / "classification_report.txt",
        "w",
        encoding="utf-8",
    ) as file:
        file.write(
            "VALIDATION CLASSIFICATION REPORT\n"
        )

        file.write(
            "=" * 70 + "\n"
        )

        file.write(
            validation_report
        )

        file.write(
            "\n\nTEST CLASSIFICATION REPORT\n"
        )

        file.write(
            "=" * 70 + "\n"
        )

        file.write(
            test_report
        )

    print("\n" + "=" * 70)
    print("TRAINING COMPLETE")
    print("=" * 70)

    print(
        f"\nSaved model and results to:\n"
        f"{output_dir}"
    )


if __name__ == "__main__":
    main()