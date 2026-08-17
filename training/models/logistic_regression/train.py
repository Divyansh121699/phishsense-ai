import argparse
import json
import re
import time
from pathlib import Path

import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
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
from sklearn.pipeline import Pipeline


RANDOM_STATE = 42

LABEL_MAP = {
    "benign": 0,
    "phishing": 1,
}


# ---------------------------------------------------------------------
# Text preprocessing
# Paper-guided:
# - lowercase
# - remove special characters
# - remove non-alphabetic values
# - normalize whitespace
# ---------------------------------------------------------------------

def clean_text(text):
    if pd.isna(text):
        return ""

    text = str(text).lower()

    # Keep alphabetic text and spaces only.
    text = re.sub(r"[^a-z\s]", " ", text)

    # Collapse repeated whitespace.
    text = re.sub(r"\s+", " ", text)

    return text.strip()


# ---------------------------------------------------------------------
# Load common PhishSenseAI dataset + split map
# ---------------------------------------------------------------------

def load_data(dataset_path, split_path):
    dataset = pd.read_csv(dataset_path)
    splits = pd.read_csv(split_path)

    required_dataset_columns = {
        "email_id",
        "body_text",
        "high_level_category",
    }

    required_split_columns = {
        "email_id",
        "split",
    }

    missing_dataset = required_dataset_columns - set(dataset.columns)
    missing_split = required_split_columns - set(splits.columns)

    if missing_dataset:
        raise ValueError(
            f"Dataset is missing required columns: {sorted(missing_dataset)}"
        )

    if missing_split:
        raise ValueError(
            f"Split file is missing required columns: {sorted(missing_split)}"
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
            "Some email IDs in the split file were not found in the dataset."
        )

    data["label"] = (
        data["high_level_category"]
        .astype(str)
        .str.strip()
        .str.lower()
        .map(LABEL_MAP)
    )

    if data["label"].isna().any():
        invalid_labels = (
            data.loc[
                data["label"].isna(),
                "high_level_category",
            ]
            .unique()
            .tolist()
        )

        raise ValueError(
            f"Unexpected high-level labels: {invalid_labels}"
        )

    data["clean_text"] = (
        data["body_text"]
        .fillna("")
        .apply(clean_text)
    )

    empty_count = data["clean_text"].eq("").sum()

    if empty_count > 0:
        print(
            f"WARNING: {empty_count} record(s) became empty "
            "after text preprocessing."
        )

    return data


# ---------------------------------------------------------------------
# Build the paper-guided model
# ---------------------------------------------------------------------

def build_model():
    pipeline = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=1000,
                    random_state=RANDOM_STATE,
                ),
            ),
        ]
    )

    # Meléndez et al. parameter search
    parameter_grid = {
        "classifier__C": [0.1, 1, 10],
    }

    search = GridSearchCV(
        estimator=pipeline,
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

def evaluate_model(model, X, y):
    predictions = model.predict(X)

    probabilities = None

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(X)[:, 1]

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
    }

    if probabilities is not None:
        metrics["roc_auc"] = roc_auc_score(
            y,
            probabilities,
        )

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

    return metrics, cm, report, predictions, probabilities


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

    result["true_label"] = data["label"].values
    result["predicted_label"] = predictions

    result["predicted_category"] = result[
        "predicted_label"
    ].map(
        {
            0: "benign",
            1: "phishing",
        }
    )

    if probabilities is not None:
        result["phishing_probability"] = probabilities

    result.to_csv(
        output_path,
        index=False,
    )


# ---------------------------------------------------------------------
# Main training process
# ---------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Train the PhishSenseAI paper-guided "
            "Logistic Regression phishing detector."
        )
    )

    parser.add_argument(
        "--dataset",
        required=True,
        help="Path to common PhishSenseAI CSV dataset.",
    )

    parser.add_argument(
        "--splits",
        required=True,
        help="Path to common email_id/split CSV.",
    )

    parser.add_argument(
        "--output-dir",
        default="training/models/logistic_regression/output",
        help="Directory for model and evaluation outputs.",
    )

    args = parser.parse_args()

    output_dir = Path(args.output_dir)

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    print("=" * 70)
    print("PhishSenseAI - Logistic Regression")
    print("Paper-guided implementation")
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
    print(f"Train:      {len(train_data)}")
    print(f"Validation: {len(validation_data)}")
    print(f"Test:       {len(test_data)}")

    X_train = train_data["clean_text"]
    y_train = train_data["label"]

    X_validation = validation_data["clean_text"]
    y_validation = validation_data["label"]

    X_test = test_data["clean_text"]
    y_test = test_data["label"]

    print("\nTraining Logistic Regression...")
    print("TF-IDF + GridSearchCV")
    print("C values: [0.1, 1, 10]")
    print("Selection metric: macro-F1")

    model = build_model()

    start_time = time.perf_counter()

    model.fit(
        X_train,
        y_train,
    )

    training_time = (
        time.perf_counter() - start_time
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
    # Validation evaluation
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

    for metric, value in validation_metrics.items():
        print(
            f"{metric}: {value:.4f}"
        )

    print("\nConfusion Matrix:")
    print(validation_cm)

    print("\nClassification Report:")
    print(validation_report)

    # --------------------------------------------------------------
    # Final held-out test evaluation
    # --------------------------------------------------------------

    print("\n" + "=" * 70)
    print("TEST RESULTS")
    print("=" * 70)

    test_start = time.perf_counter()

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
        time.perf_counter() - test_start
    )

    for metric, value in test_metrics.items():
        print(
            f"{metric}: {value:.4f}"
        )

    print("\nConfusion Matrix:")
    print(test_cm)

    print("\nClassification Report:")
    print(test_report)

    print(
        f"\nInference time for test set: "
        f"{inference_time:.4f} seconds"
    )

    if len(test_data) > 0:
        print(
            "Average inference time per email: "
            f"{(inference_time / len(test_data)) * 1000:.4f} ms"
        )

    # --------------------------------------------------------------
    # Save model
    # --------------------------------------------------------------

    model_path = (
        output_dir
        / "logistic_regression_model.joblib"
    )

    joblib.dump(
        model,
        model_path,
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
        "model": "Logistic Regression",
        "reference_method": (
            "Melendez et al. paper-guided "
            "TF-IDF + Logistic Regression"
        ),
        "random_state": RANDOM_STATE,
        "best_parameters": model.best_params_,
        "best_cv_macro_f1": model.best_score_,
        "training_records": len(train_data),
        "validation_records": len(validation_data),
        "test_records": len(test_data),
        "training_time_seconds": training_time,
        "test_inference_time_seconds": inference_time,
        "validation_metrics": validation_metrics,
        "test_metrics": test_metrics,
        "validation_confusion_matrix": (
            validation_cm.tolist()
        ),
        "test_confusion_matrix": (
            test_cm.tolist()
        ),
    }

    with open(
        output_dir / "metrics.json",
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            results,
            file,
            indent=4,
        )

    with open(
        output_dir / "classification_report.txt",
        "w",
        encoding="utf-8",
    ) as file:
        file.write(
            "VALIDATION CLASSIFICATION REPORT\n"
        )
        file.write(
            "=" * 70 + "\n"
        )
        file.write(validation_report)

        file.write(
            "\n\nTEST CLASSIFICATION REPORT\n"
        )
        file.write(
            "=" * 70 + "\n"
        )
        file.write(test_report)

    print("\n" + "=" * 70)
    print("TRAINING COMPLETE")
    print("=" * 70)

    print(
        f"\nSaved model and results to:\n"
        f"{output_dir}"
    )


if __name__ == "__main__":
    main()