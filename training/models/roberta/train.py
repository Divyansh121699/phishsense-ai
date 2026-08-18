import argparse
import json
import random
import re
import time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from torch.utils.data import DataLoader, Dataset

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
)


# ============================================================
# CONFIGURATION
# ============================================================

RANDOM_STATE = 42

MODEL_NAME = "roberta-base"

MAX_LENGTH = 512

LEARNING_RATE = 2e-5

EPOCHS = 5

# Hopper 10 GB A100 MIG adaptation:
# physical batch 4 x accumulation 8 = effective batch 32
TRAIN_BATCH_SIZE = 4
GRADIENT_ACCUMULATION_STEPS = 8

EVAL_BATCH_SIZE = 16

LABEL_MAP = {
    "benign": 0,
    "phishing": 1,
}


# ============================================================
# REPRODUCIBILITY
# ============================================================

def set_seed(seed):
    random.seed(seed)
    np.random.seed(seed)

    torch.manual_seed(seed)

    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


# ============================================================
# PAPER-GUIDED TEXT CLEANING
#
# Uddin et al.:
# - lowercase
# - remove HTML
# - normalize repeated whitespace
# - remove carriage returns
# - trim whitespace
# ============================================================

def combine_email_text(subject, body):
    subject = "" if pd.isna(subject) else str(subject)
    body = "" if pd.isna(body) else str(body)

    return f"{subject} {body}".strip()


def clean_text(text):
    if pd.isna(text):
        return ""

    text = str(text).lower()

    # Remove HTML tags
    text = re.sub(
        r"<[^>]+>",
        " ",
        text,
    )

    # Remove carriage returns / line formatting
    text = text.replace(
        "\r",
        " ",
    )

    text = text.replace(
        "\n",
        " ",
    )

    # Collapse repeated whitespace
    text = re.sub(
        r"\s+",
        " ",
        text,
    )

    return text.strip()


# ============================================================
# DATA LOADING
# ============================================================

def load_data(
    dataset_path,
    split_path,
):
    dataset = pd.read_csv(
        dataset_path
    )

    splits = pd.read_csv(
        split_path
    )

    required_dataset_columns = {
        "email_id",
        "subject",
        "body_text",
        "high_level_category",
    }

    required_split_columns = {
        "email_id",
        "split",
    }

    missing_dataset = (
        required_dataset_columns
        - set(dataset.columns)
    )

    missing_splits = (
        required_split_columns
        - set(splits.columns)
    )

    if missing_dataset:
        raise ValueError(
            "Dataset missing required columns: "
            f"{sorted(missing_dataset)}"
        )

    if missing_splits:
        raise ValueError(
            "Split file missing required columns: "
            f"{sorted(missing_splits)}"
        )

    if dataset[
        "email_id"
    ].duplicated().any():
        raise ValueError(
            "Duplicate email_id values "
            "detected in dataset."
        )

    if splits[
        "email_id"
    ].duplicated().any():
        raise ValueError(
            "Duplicate email_id values "
            "detected in split file."
        )

    data = dataset.merge(
        splits,
        on="email_id",
        how="inner",
        validate="one_to_one",
    )

    if len(data) != len(splits):
        raise ValueError(
            "Some email IDs in the split file "
            "were not found in the dataset."
        )

    data["label"] = (
        data["high_level_category"]
        .astype(str)
        .str.strip()
        .str.lower()
        .map(LABEL_MAP)
    )

    if data[
        "label"
    ].isna().any():

        invalid = (
            data.loc[
                data["label"].isna(),
                "high_level_category",
            ]
            .unique()
            .tolist()
        )

        raise ValueError(
            "Unexpected labels found: "
            f"{invalid}"
        )

    data["combined_text"] = (
        data.apply(
            lambda row:
                combine_email_text(
                    row["subject"],
                    row["body_text"],
                ),
            axis=1,
        )
    )

    data["clean_text"] = (
        data["combined_text"]
        .apply(clean_text)
    )

    return data


# ============================================================
# TRAINING-ONLY CLASS BALANCING
#
# Uddin et al. use synonym replacement on phishing emails.
#
# We perform augmentation ONLY when meaningful imbalance
# exists. This keeps validation/test completely untouched.
#
# The development_800 dataset is almost exactly balanced,
# so augmentation will not be needed for that test.
# ============================================================

def get_wordnet_synonyms(word):
    try:
        from nltk.corpus import wordnet

    except ImportError:
        raise RuntimeError(
            "NLTK is required for synonym augmentation. "
            "Install nltk before using augmentation."
        )

    synonyms = set()

    try:
        synsets = wordnet.synsets(
            word
        )

    except LookupError:
        raise RuntimeError(
            "NLTK WordNet data is not installed. "
            "Run nltk.download('wordnet') before "
            "training an imbalanced dataset."
        )

    for synset in synsets:

        for lemma in synset.lemmas():

            synonym = (
                lemma.name()
                .replace(
                    "_",
                    " ",
                )
                .lower()
                .strip()
            )

            if (
                synonym
                and synonym != word
            ):
                synonyms.add(
                    synonym
                )

    return list(
        synonyms
    )


def synonym_replace(
    text,
    replacement_ratio=0.20,
):
    words = text.split()

    if not words:
        return text

    candidate_indices = [
        index
        for index, word
        in enumerate(words)
        if (
            word.isalpha()
            and len(word) > 3
        )
    ]

    if not candidate_indices:
        return text

    replacements_needed = max(
        1,
        int(
            len(words)
            * replacement_ratio
        ),
    )

    replacements_needed = min(
        replacements_needed,
        len(candidate_indices),
    )

    random.shuffle(
        candidate_indices
    )

    replacements = 0

    new_words = words.copy()

    for index in candidate_indices:

        synonyms = get_wordnet_synonyms(
            words[index]
        )

        if not synonyms:
            continue

        new_words[index] = (
            random.choice(
                synonyms
            )
        )

        replacements += 1

        if (
            replacements
            >= replacements_needed
        ):
            break

    return " ".join(
        new_words
    )


def balance_training_data(
    train_data,
):
    counts = (
        train_data[
            "high_level_category"
        ]
        .value_counts()
    )

    print(
        "\nOriginal training "
        "class distribution:"
    )

    print(
        counts.to_string()
    )

    if len(counts) != 2:
        raise ValueError(
            "Expected exactly two classes."
        )

    majority_count = (
        counts.max()
    )

    minority_count = (
        counts.min()
    )

    ratio = (
        majority_count
        / minority_count
    )

    # Nearly balanced -> no augmentation
    if ratio < 1.10:

        print(
            "\nTraining augmentation: "
            "not required"
        )

        return train_data.copy()

    minority_label = (
        counts.idxmin()
    )

    minority_rows = (
        train_data[
            train_data[
                "high_level_category"
            ]
            == minority_label
        ]
        .copy()
    )

    required = (
        majority_count
        - minority_count
    )

    print(
        "\nTraining augmentation enabled."
    )

    print(
        f"Minority class: "
        f"{minority_label}"
    )

    print(
        f"Synthetic training emails "
        f"required: {required}"
    )

    augmented_rows = []

    for i in range(
        required
    ):

        source_row = (
            minority_rows.sample(
                n=1,
                replace=True,
                random_state=(
                    RANDOM_STATE + i
                ),
            )
            .iloc[0]
            .copy()
        )

        source_row[
            "clean_text"
        ] = synonym_replace(
            source_row[
                "clean_text"
            ],
            replacement_ratio=0.20,
        )

        source_row[
            "email_id"
        ] = (
            f"{source_row['email_id']}"
            f"_aug_{i}"
        )

        augmented_rows.append(
            source_row
        )

    augmented_df = (
        pd.DataFrame(
            augmented_rows
        )
    )

    balanced = pd.concat(
        [
            train_data,
            augmented_df,
        ],
        ignore_index=True,
    )

    balanced = (
        balanced.sample(
            frac=1,
            random_state=RANDOM_STATE,
        )
        .reset_index(
            drop=True
        )
    )

    print(
        "\nBalanced training "
        "class distribution:"
    )

    print(
        balanced[
            "high_level_category"
        ]
        .value_counts()
        .to_string()
    )

    return balanced


# ============================================================
# TORCH DATASET
# ============================================================

class RoBERTaEmailDataset(
    Dataset
):

    def __init__(
        self,
        dataframe,
        tokenizer,
    ):
        self.data = (
            dataframe
            .reset_index(
                drop=True
            )
        )

        self.tokenizer = (
            tokenizer
        )

    def __len__(self):
        return len(
            self.data
        )

    def __getitem__(
        self,
        index,
    ):
        row = (
            self.data
            .iloc[index]
        )

        encoded = (
            self.tokenizer(
                row[
                    "clean_text"
                ],
                max_length=MAX_LENGTH,
                padding="max_length",
                truncation=True,
                return_tensors="pt",
            )
        )

        item = {
            "input_ids":
                encoded[
                    "input_ids"
                ].squeeze(0),

            "attention_mask":
                encoded[
                    "attention_mask"
                ].squeeze(0),

            "labels":
                torch.tensor(
                    int(
                        row[
                            "label"
                        ]
                    ),
                    dtype=torch.long,
                ),
        }

        return item


# ============================================================
# TRAINING
# ============================================================

def train_one_epoch(
    model,
    loader,
    optimizer,
    device,
):
    model.train()

    optimizer.zero_grad()

    total_loss = 0.0

    for step, batch in enumerate(
        loader,
        start=1,
    ):

        input_ids = (
            batch[
                "input_ids"
            ]
            .to(device)
        )

        attention_mask = (
            batch[
                "attention_mask"
            ]
            .to(device)
        )

        labels = (
            batch[
                "labels"
            ]
            .to(device)
        )

        outputs = model(
            input_ids=input_ids,
            attention_mask=(
                attention_mask
            ),
            labels=labels,
        )

        loss = (
            outputs.loss
            / GRADIENT_ACCUMULATION_STEPS
        )

        loss.backward()

        total_loss += (
            outputs.loss.item()
            * len(labels)
        )

        if (
            step
            % GRADIENT_ACCUMULATION_STEPS
            == 0
            or step == len(loader)
        ):

            torch.nn.utils.clip_grad_norm_(
                model.parameters(),
                max_norm=1.0,
            )

            optimizer.step()

            optimizer.zero_grad()

    return (
        total_loss
        / len(loader.dataset)
    )


# ============================================================
# PREDICTION / EVALUATION
# ============================================================

def predict_model(
    model,
    loader,
    device,
):
    model.eval()

    all_labels = []
    all_predictions = []
    all_probabilities = []

    total_loss = 0.0

    with torch.no_grad():

        for batch in loader:

            input_ids = (
                batch[
                    "input_ids"
                ]
                .to(device)
            )

            attention_mask = (
                batch[
                    "attention_mask"
                ]
                .to(device)
            )

            labels = (
                batch[
                    "labels"
                ]
                .to(device)
            )

            outputs = model(
                input_ids=input_ids,
                attention_mask=(
                    attention_mask
                ),
                labels=labels,
            )

            total_loss += (
                outputs.loss.item()
                * len(labels)
            )

            probabilities = (
                torch.softmax(
                    outputs.logits,
                    dim=1,
                )[:, 1]
            )

            predictions = (
                torch.argmax(
                    outputs.logits,
                    dim=1,
                )
            )

            all_labels.extend(
                labels
                .cpu()
                .numpy()
                .tolist()
            )

            all_predictions.extend(
                predictions
                .cpu()
                .numpy()
                .tolist()
            )

            all_probabilities.extend(
                probabilities
                .cpu()
                .numpy()
                .tolist()
            )

    average_loss = (
        total_loss
        / len(loader.dataset)
    )

    return (
        np.asarray(
            all_labels
        ),
        np.asarray(
            all_predictions
        ),
        np.asarray(
            all_probabilities
        ),
        average_loss,
    )


def calculate_metrics(
    y_true,
    predictions,
    probabilities,
):
    metrics = {
        "accuracy":
            accuracy_score(
                y_true,
                predictions,
            ),

        "precision":
            precision_score(
                y_true,
                predictions,
                zero_division=0,
            ),

        "recall":
            recall_score(
                y_true,
                predictions,
                zero_division=0,
            ),

        "f1":
            f1_score(
                y_true,
                predictions,
                zero_division=0,
            ),

        "f1_macro":
            f1_score(
                y_true,
                predictions,
                average="macro",
                zero_division=0,
            ),

        "roc_auc":
            roc_auc_score(
                y_true,
                probabilities,
            ),
    }

    matrix = confusion_matrix(
        y_true,
        predictions,
    )

    report = classification_report(
        y_true,
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
        matrix,
        report,
    )


# ============================================================
# SAVE PREDICTIONS
# ============================================================

def save_predictions(
    dataframe,
    predictions,
    probabilities,
    output_path,
):
    result = (
        dataframe[
            [
                "email_id",
                "high_level_category",
            ]
        ]
        .reset_index(
            drop=True
        )
        .copy()
    )

    result[
        "true_label"
    ] = (
        dataframe[
            "label"
        ]
        .reset_index(
            drop=True
        )
        .values
    )

    result[
        "predicted_label"
    ] = predictions

    result[
        "predicted_category"
    ] = (
        result[
            "predicted_label"
        ]
        .map(
            {
                0: "benign",
                1: "phishing",
            }
        )
    )

    result[
        "phishing_probability"
    ] = probabilities

    result.to_csv(
        output_path,
        index=False,
    )


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "PhishSenseAI Uddin et al. "
            "paper-guided RoBERTa classifier."
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
        default=(
            "training/models/"
            "roberta/output"
        ),
    )

    args = parser.parse_args()

    set_seed(
        RANDOM_STATE
    )

    output_dir = Path(
        args.output_dir
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    # ========================================================
    # GPU CHECK
    # ========================================================

    device = torch.device(
        "cuda"
        if torch.cuda.is_available()
        else "cpu"
    )

    print("=" * 70)

    print(
        "PhishSenseAI - RoBERTa"
    )

    print(
        "Uddin et al. (2026) "
        "paper-guided implementation"
    )

    print("=" * 70)

    print(
        f"\nDevice: {device}"
    )

    if (
        device.type
        != "cuda"
    ):
        raise RuntimeError(
            "CUDA GPU is not available. "
            "Run RoBERTa from a Hopper "
            "GPU allocation."
        )

    print(
        "GPU: "
        + torch.cuda.get_device_name(
            0
        )
    )

    print(
        f"CUDA version: "
        f"{torch.version.cuda}"
    )

    # ========================================================
    # DATA
    # ========================================================

    print(
        "\nLoading dataset..."
    )

    data = load_data(
        args.dataset,
        args.splits,
    )

    train_data = (
        data[
            data["split"]
            == "train"
        ]
        .copy()
    )

    validation_data = (
        data[
            data["split"]
            == "validation"
        ]
        .copy()
    )

    test_data = (
        data[
            data["split"]
            == "test"
        ]
        .copy()
    )

    print(
        "\nDataset split:"
    )

    print(
        f"Train:      "
        f"{len(train_data)}"
    )

    print(
        f"Validation: "
        f"{len(validation_data)}"
    )

    print(
        f"Test:       "
        f"{len(test_data)}"
    )

    # ========================================================
    # TRAINING-ONLY BALANCING
    # ========================================================

    train_data = (
        balance_training_data(
            train_data
        )
    )

    # ========================================================
    # TOKENIZER / MODEL
    # ========================================================

    print(
        f"\nLoading tokenizer: "
        f"{MODEL_NAME}"
    )

    tokenizer = (
        AutoTokenizer
        .from_pretrained(
            MODEL_NAME
        )
    )

    print(
        f"Loading model: "
        f"{MODEL_NAME}"
    )

    model = (
        AutoModelForSequenceClassification
        .from_pretrained(
            MODEL_NAME,
            num_labels=2,
        )
        .to(device)
    )

    total_parameters = sum(
        parameter.numel()
        for parameter
        in model.parameters()
    )

    trainable_parameters = sum(
        parameter.numel()
        for parameter
        in model.parameters()
        if parameter.requires_grad
    )

    print(
        f"\nTotal parameters: "
        f"{total_parameters:,}"
    )

    print(
        f"Trainable parameters: "
        f"{trainable_parameters:,}"
    )

    # ========================================================
    # DATASETS / LOADERS
    # ========================================================

    train_dataset = (
        RoBERTaEmailDataset(
            train_data,
            tokenizer,
        )
    )

    validation_dataset = (
        RoBERTaEmailDataset(
            validation_data,
            tokenizer,
        )
    )

    test_dataset = (
        RoBERTaEmailDataset(
            test_data,
            tokenizer,
        )
    )

    train_loader = (
        DataLoader(
            train_dataset,
            batch_size=(
                TRAIN_BATCH_SIZE
            ),
            shuffle=True,
            num_workers=0,
        )
    )

    validation_loader = (
        DataLoader(
            validation_dataset,
            batch_size=(
                EVAL_BATCH_SIZE
            ),
            shuffle=False,
            num_workers=0,
        )
    )

    test_loader = (
        DataLoader(
            test_dataset,
            batch_size=(
                EVAL_BATCH_SIZE
            ),
            shuffle=False,
            num_workers=0,
        )
    )

    # ========================================================
    # OPTIMIZER
    # ========================================================

    optimizer = (
        torch.optim.AdamW(
            model.parameters(),
            lr=LEARNING_RATE,
        )
    )

    print(
        "\nTraining configuration:"
    )

    print(
        f"Model: {MODEL_NAME}"
    )

    print(
        f"Max sequence length: "
        f"{MAX_LENGTH}"
    )

    print(
        f"Learning rate: "
        f"{LEARNING_RATE}"
    )

    print(
        f"Epochs: {EPOCHS}"
    )

    print(
        f"Physical train batch: "
        f"{TRAIN_BATCH_SIZE}"
    )

    print(
        "Gradient accumulation: "
        f"{GRADIENT_ACCUMULATION_STEPS}"
    )

    print(
        "Effective train batch: "
        f"{TRAIN_BATCH_SIZE * GRADIENT_ACCUMULATION_STEPS}"
    )

    # ========================================================
    # TRAINING
    # ========================================================

    best_validation_f1 = -1

    best_model_path = (
        output_dir
        / "best_model.pt"
    )

    training_history = []

    training_start = (
        time.perf_counter()
    )

    for epoch in range(
        1,
        EPOCHS + 1,
    ):

        epoch_start = (
            time.perf_counter()
        )

        train_loss = (
            train_one_epoch(
                model,
                train_loader,
                optimizer,
                device,
            )
        )

        (
            validation_true,
            validation_predictions,
            validation_probabilities,
            validation_loss,
        ) = predict_model(
            model,
            validation_loader,
            device,
        )

        validation_f1 = (
            f1_score(
                validation_true,
                validation_predictions,
                zero_division=0,
            )
        )

        epoch_time = (
            time.perf_counter()
            - epoch_start
        )

        print(
            f"\nEpoch {epoch}/{EPOCHS}"
        )

        print(
            f"Train loss: "
            f"{train_loss:.4f}"
        )

        print(
            f"Validation loss: "
            f"{validation_loss:.4f}"
        )

        print(
            f"Validation F1: "
            f"{validation_f1:.4f}"
        )

        print(
            f"Epoch time: "
            f"{epoch_time:.2f} sec"
        )

        training_history.append(
            {
                "epoch":
                    epoch,

                "train_loss":
                    train_loss,

                "validation_loss":
                    validation_loss,

                "validation_f1":
                    validation_f1,

                "epoch_time_seconds":
                    epoch_time,
            }
        )

        if (
            validation_f1
            > best_validation_f1
        ):

            best_validation_f1 = (
                validation_f1
            )

            torch.save(
                model.state_dict(),
                best_model_path,
            )

            print(
                "Best model updated."
            )

    training_time = (
        time.perf_counter()
        - training_start
    )

    print(
        f"\nTotal training time: "
        f"{training_time:.2f} seconds"
    )

    # ========================================================
    # LOAD BEST MODEL
    # ========================================================

    model.load_state_dict(
        torch.load(
            best_model_path,
            map_location=device,
        )
    )

    # ========================================================
    # VALIDATION RESULTS
    # ========================================================

    (
        validation_true,
        validation_predictions,
        validation_probabilities,
        validation_loss,
    ) = predict_model(
        model,
        validation_loader,
        device,
    )

    (
        validation_metrics,
        validation_cm,
        validation_report,
    ) = calculate_metrics(
        validation_true,
        validation_predictions,
        validation_probabilities,
    )

    print(
        "\n"
        + "=" * 70
    )

    print(
        "VALIDATION RESULTS"
    )

    print(
        "=" * 70
    )

    for (
        metric,
        value
    ) in validation_metrics.items():

        print(
            f"{metric}: "
            f"{value:.4f}"
        )

    print(
        "\nConfusion Matrix:"
    )

    print(
        validation_cm
    )

    print(
        "\nClassification Report:"
    )

    print(
        validation_report
    )

    # ========================================================
    # HELD-OUT TEST
    # ========================================================

    inference_start = (
        time.perf_counter()
    )

    (
        test_true,
        test_predictions,
        test_probabilities,
        test_loss,
    ) = predict_model(
        model,
        test_loader,
        device,
    )

    inference_time = (
        time.perf_counter()
        - inference_start
    )

    (
        test_metrics,
        test_cm,
        test_report,
    ) = calculate_metrics(
        test_true,
        test_predictions,
        test_probabilities,
    )

    print(
        "\n"
        + "=" * 70
    )

    print(
        "TEST RESULTS"
    )

    print(
        "=" * 70
    )

    for (
        metric,
        value
    ) in test_metrics.items():

        print(
            f"{metric}: "
            f"{value:.4f}"
        )

    print(
        "\nConfusion Matrix:"
    )

    print(
        test_cm
    )

    print(
        "\nClassification Report:"
    )

    print(
        test_report
    )

    print(
        f"\nInference time: "
        f"{inference_time:.4f} seconds"
    )

    if len(
        test_data
    ) > 0:

        average_ms = (
            inference_time
            / len(test_data)
            * 1000
        )

        print(
            "Average inference time "
            f"per email: "
            f"{average_ms:.4f} ms"
        )

    # ========================================================
    # SAVE MODEL + TOKENIZER
    # ========================================================

    final_model_dir = (
        output_dir
        / "model"
    )

    model.save_pretrained(
        final_model_dir
    )

    tokenizer.save_pretrained(
        final_model_dir
    )

    # Remove temporary checkpoint after saving
    # the final reusable Hugging Face model.
    if best_model_path.exists():
        best_model_path.unlink()

        print(
            "\nTemporary best_model.pt "
            "checkpoint removed."
        )

    # ========================================================
    # SAVE PREDICTIONS
    # ========================================================

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

    # ========================================================
    # TRAINING HISTORY
    # ========================================================

    pd.DataFrame(
        training_history
    ).to_csv(
        output_dir
        / "training_history.csv",
        index=False,
    )

    # ========================================================
    # METRICS
    # ========================================================

    results = {
        "model":
            "RoBERTa-base",

        "reference_method": (
            "Uddin, Mahiuddin & Sarker "
            "(2026) paper-guided "
            "RoBERTa phishing detection"
        ),

        "model_name":
            MODEL_NAME,

        "device":
            str(device),

        "gpu_name":
            torch.cuda.get_device_name(
                0
            ),

        "random_state":
            RANDOM_STATE,

        "max_sequence_length":
            MAX_LENGTH,

        "learning_rate":
            LEARNING_RATE,

        "epochs":
            EPOCHS,

        "physical_train_batch_size":
            TRAIN_BATCH_SIZE,

        "gradient_accumulation_steps":
            GRADIENT_ACCUMULATION_STEPS,

        "effective_train_batch_size":
            (
                TRAIN_BATCH_SIZE
                * GRADIENT_ACCUMULATION_STEPS
            ),

        "evaluation_batch_size":
            EVAL_BATCH_SIZE,

        "total_parameters":
            total_parameters,

        "trainable_parameters":
            trainable_parameters,

        "training_records":
            len(train_data),

        "validation_records":
            len(validation_data),

        "test_records":
            len(test_data),

        "training_time_seconds":
            training_time,

        "test_inference_time_seconds":
            inference_time,

        "best_validation_f1":
            best_validation_f1,

        "validation_metrics":
            validation_metrics,

        "test_metrics":
            test_metrics,

        "validation_confusion_matrix":
            validation_cm.tolist(),

        "test_confusion_matrix":
            test_cm.tolist(),
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

    # ========================================================
    # REPORT
    # ========================================================

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
            "=" * 70
            + "\n"
        )

        file.write(
            validation_report
        )

        file.write(
            "\n\nTEST CLASSIFICATION REPORT\n"
        )

        file.write(
            "=" * 70
            + "\n"
        )

        file.write(
            test_report
        )

    print(
        "\n"
        + "=" * 70
    )

    print(
        "TRAINING COMPLETE"
    )

    print(
        "=" * 70
    )

    print(
        "\nSaved model and "
        "results to:"
    )

    print(
        output_dir
    )


if __name__ == "__main__":
    main()