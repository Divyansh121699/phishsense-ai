import argparse
import json
import random
import re
import time
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from torch.utils.data import (
    DataLoader,
    Dataset,
    WeightedRandomSampler,
)


# ============================================================
# CONFIGURATION
# ============================================================

RANDOM_STATE = 42

LABEL_MAP = {
    "benign": 0,
    "phishing": 1,
}

PAD_TOKEN = "<PAD>"
UNK_TOKEN = "<UNK>"

EMBEDDING_DIM = 100

BATCH_SIZE = 32

LEARNING_RATE = 0.001

MAX_EPOCHS = 100

EARLY_STOPPING_PATIENCE = 2

LEAKY_RELU_SLOPE = 0.01

DEFAULT_MAX_SEQUENCE_LENGTH = 1000


# ============================================================
# REPRODUCIBILITY
# ============================================================

def set_seed(seed):
    random.seed(seed)
    np.random.seed(seed)

    torch.manual_seed(seed)

    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)

    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False


# ============================================================
# PAPER-GUIDED TEXT PREPROCESSING
#
# Altwaijry et al.:
# - use subject + body
# - remove HTML
# - remove punctuation
# - remove images/encoded content
# - remove IP addresses
# - remove email addresses
# - remove stopwords
# - replace URLs beginning with http with [http]
# - tokenize
# - retain common vocabulary
#
# We reproduce the central cleaning behavior without modifying
# the fixed PhishSenseAI schema itself.
# ============================================================

STOPWORDS = {
    "a", "an", "the", "and", "or", "but",
    "if", "while", "with", "of", "at",
    "by", "for", "to", "from", "in", "on",
    "is", "are", "was", "were", "be", "been",
    "being", "this", "that", "these", "those",
    "it", "its", "as", "so", "than", "then",
}


def combine_text(subject, body):
    subject = "" if pd.isna(subject) else str(subject)
    body = "" if pd.isna(body) else str(body)

    return f"{subject} {body}".strip()


def clean_text(text):
    if pd.isna(text):
        return ""

    text = str(text).lower()

    # Replace URLs with paper-style placeholder.
    text = re.sub(
        r"https?://\S+",
        " http ",
        text,
    )

    # Remove HTML.
    text = re.sub(
        r"<[^>]+>",
        " ",
        text,
    )

    # Remove email addresses.
    text = re.sub(
        r"\b[A-Za-z0-9._%+-]+"
        r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        " ",
        text,
    )

    # Remove IPv4 addresses.
    text = re.sub(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        " ",
        text,
    )

    # Remove long base64-like encoded sequences.
    text = re.sub(
        r"\b[A-Za-z0-9+/]{40,}={0,2}\b",
        " ",
        text,
    )

    # Remove punctuation / non-word symbols.
    text = re.sub(
        r"[^a-z\s]",
        " ",
        text,
    )

    # Normalize whitespace.
    text = re.sub(
        r"\s+",
        " ",
        text,
    )

    words = [
        word
        for word in text.split()
        if word not in STOPWORDS
    ]

    return " ".join(words)


# ============================================================
# DATA LOADING
# ============================================================

def load_data(dataset_path, split_path):
    dataset = pd.read_csv(dataset_path)
    splits = pd.read_csv(split_path)

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
            f"Missing dataset columns: "
            f"{sorted(missing_dataset)}"
        )

    if missing_splits:
        raise ValueError(
            f"Missing split columns: "
            f"{sorted(missing_splits)}"
        )

    if dataset["email_id"].duplicated().any():
        raise ValueError(
            "Duplicate email_id values found "
            "in the dataset."
        )

    if splits["email_id"].duplicated().any():
        raise ValueError(
            "Duplicate email_id values found "
            "in the split file."
        )

    data = dataset.merge(
        splits,
        on="email_id",
        how="inner",
        validate="one_to_one",
    )

    if len(data) != len(splits):
        raise ValueError(
            "Some split IDs were not found "
            "in the dataset."
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
            "Unexpected high_level_category values."
        )

    data["combined_text"] = data.apply(
        lambda row: combine_text(
            row["subject"],
            row["body_text"],
        ),
        axis=1,
    )

    data["clean_text"] = (
        data["combined_text"]
        .apply(clean_text)
    )

    return data


# ============================================================
# VOCABULARY
#
# Paper keeps words appearing three times or more.
# Vocabulary is built from TRAINING DATA ONLY to avoid leakage.
# ============================================================

def build_vocabulary(train_texts):
    counter = Counter()

    for text in train_texts:
        counter.update(
            text.split()
        )

    vocabulary = {
        PAD_TOKEN: 0,
        UNK_TOKEN: 1,
    }

    for word, count in counter.items():
        if count >= 3:
            vocabulary[word] = len(
                vocabulary
            )

    return vocabulary


# ============================================================
# GLOVE EMBEDDINGS
# ============================================================

def load_glove_embeddings(
    glove_path,
    vocabulary,
):
    glove_path = Path(glove_path)

    if not glove_path.exists():
        raise FileNotFoundError(
            f"GloVe file not found: {glove_path}"
        )

    embedding_matrix = np.random.normal(
        loc=0.0,
        scale=0.05,
        size=(
            len(vocabulary),
            EMBEDDING_DIM,
        ),
    ).astype(
        np.float32
    )

    embedding_matrix[
        vocabulary[PAD_TOKEN]
    ] = np.zeros(
        EMBEDDING_DIM,
        dtype=np.float32,
    )

    found = 0

    with open(
        glove_path,
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as file:

        for line in file:
            parts = line.rstrip().split()

            if len(parts) != (
                EMBEDDING_DIM + 1
            ):
                continue

            word = parts[0]

            if word not in vocabulary:
                continue

            try:
                vector = np.asarray(
                    parts[1:],
                    dtype=np.float32,
                )

            except ValueError:
                continue

            embedding_matrix[
                vocabulary[word]
            ] = vector

            found += 1

    print(
        f"GloVe vectors matched: "
        f"{found:,}/{len(vocabulary):,}"
    )

    return embedding_matrix


# ============================================================
# SEQUENCE ENCODING
# ============================================================

def encode_text(
    text,
    vocabulary,
    max_length,
):
    tokens = text.split()

    ids = [
        vocabulary.get(
            token,
            vocabulary[UNK_TOKEN],
        )
        for token in tokens
    ]

    ids = ids[:max_length]

    if len(ids) < max_length:
        ids += [
            vocabulary[PAD_TOKEN]
        ] * (
            max_length - len(ids)
        )

    return ids


# ============================================================
# PYTORCH DATASET
# ============================================================

class EmailDataset(Dataset):

    def __init__(
        self,
        dataframe,
        vocabulary,
        max_length,
    ):
        self.data = dataframe.reset_index(
            drop=True
        )

        self.vocabulary = vocabulary
        self.max_length = max_length

    def __len__(self):
        return len(
            self.data
        )

    def __getitem__(self, index):
        row = self.data.iloc[
            index
        ]

        sequence = encode_text(
            row["clean_text"],
            self.vocabulary,
            self.max_length,
        )

        label = int(
            row["label"]
        )

        return (
            torch.tensor(
                sequence,
                dtype=torch.long,
            ),
            torch.tensor(
                label,
                dtype=torch.float32,
            ),
        )


# ============================================================
# PAPER-GUIDED 1D-CNN + BiLSTM MODEL
#
# Core architecture:
#
# pretrained 100-D GloVe
# -> Conv1D
# -> BatchNorm
# -> MaxPool
# -> LeakyReLU
# -> Dropout
# -> BiLSTM
# -> sigmoid binary classification
# ============================================================

class CNNBiLSTM(nn.Module):

    def __init__(
        self,
        embedding_matrix,
        num_filters=300,
        kernel_size=5,
        lstm_hidden_size=128,
        dropout=0.5,
    ):
        super().__init__()

        embedding_tensor = torch.tensor(
            embedding_matrix,
            dtype=torch.float32,
        )

        self.embedding = (
            nn.Embedding.from_pretrained(
                embedding_tensor,
                freeze=False,
                padding_idx=0,
            )
        )

        self.conv = nn.Conv1d(
            in_channels=EMBEDDING_DIM,
            out_channels=num_filters,
            kernel_size=kernel_size,
            padding=kernel_size // 2,
        )

        self.batch_norm = nn.BatchNorm1d(
            num_filters
        )

        self.pool = nn.MaxPool1d(
            kernel_size=2
        )

        self.activation = nn.LeakyReLU(
            negative_slope=LEAKY_RELU_SLOPE
        )

        self.dropout = nn.Dropout(
            dropout
        )

        self.bilstm = nn.LSTM(
            input_size=num_filters,
            hidden_size=lstm_hidden_size,
            batch_first=True,
            bidirectional=True,
        )

        self.output = nn.Linear(
            lstm_hidden_size * 2,
            1,
        )

    def forward(self, x):
        # [batch, sequence]
        x = self.embedding(x)

        # [batch, sequence, embedding]
        x = x.transpose(
            1,
            2,
        )

        # [batch, filters, sequence]
        x = self.conv(x)

        x = self.batch_norm(x)

        x = self.pool(x)

        x = self.activation(x)

        x = self.dropout(x)

        # LSTM expects:
        # [batch, sequence, features]
        x = x.transpose(
            1,
            2,
        )

        _, (
            hidden,
            _
        ) = self.bilstm(x)

        # hidden:
        # forward final state
        # backward final state
        forward_hidden = hidden[-2]

        backward_hidden = hidden[-1]

        combined = torch.cat(
            (
                forward_hidden,
                backward_hidden,
            ),
            dim=1,
        )

        logits = self.output(
            combined
        ).squeeze(1)

        return logits


# ============================================================
# TRAINING
# ============================================================

def train_one_epoch(
    model,
    loader,
    optimizer,
    loss_function,
    device,
):
    model.train()

    total_loss = 0.0

    for sequences, labels in loader:
        sequences = sequences.to(
            device
        )

        labels = labels.to(
            device
        )

        optimizer.zero_grad()

        logits = model(
            sequences
        )

        loss = loss_function(
            logits,
            labels,
        )

        loss.backward()

        optimizer.step()

        total_loss += (
            loss.item()
            * len(labels)
        )

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

    probabilities = []
    labels_all = []

    with torch.no_grad():

        for sequences, labels in loader:
            sequences = sequences.to(
                device
            )

            logits = model(
                sequences
            )

            probs = torch.sigmoid(
                logits
            )

            probabilities.extend(
                probs.cpu()
                .numpy()
                .tolist()
            )

            labels_all.extend(
                labels.numpy()
                .astype(int)
                .tolist()
            )

    probabilities = np.asarray(
        probabilities
    )

    labels_all = np.asarray(
        labels_all
    )

    predictions = (
        probabilities >= 0.5
    ).astype(
        int
    )

    return (
        labels_all,
        predictions,
        probabilities,
    )


def evaluate_predictions(
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
# TRAINING BALANCE
#
# The paper uses Borderline-SMOTE.
#
# For this PyTorch/text adaptation, we preserve the paper's
# balancing objective but do NOT synthesize fractional token
# sequences with SMOTE. Instead, minority-class examples are
# oversampled in the TRAINING loader only.
#
# Validation and test sets are untouched.
# ============================================================

def build_training_sampler(
    labels,
):
    labels = np.asarray(
        labels,
        dtype=int,
    )

    class_counts = np.bincount(
        labels,
        minlength=2,
    )

    if (
        class_counts[0] == 0
        or class_counts[1] == 0
    ):
        return None

    ratio = (
        max(class_counts)
        / min(class_counts)
    )

    # For nearly balanced datasets such as development_800,
    # ordinary shuffling is sufficient.
    if ratio < 1.10:
        return None

    class_weights = (
        1.0
        / class_counts
    )

    sample_weights = (
        class_weights[
            labels
        ]
    )

    return WeightedRandomSampler(
        weights=torch.tensor(
            sample_weights,
            dtype=torch.double,
        ),
        num_samples=len(
            sample_weights
        ),
        replacement=True,
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
    results = dataframe[
        [
            "email_id",
            "high_level_category",
        ]
    ].reset_index(
        drop=True
    ).copy()

    results[
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

    results[
        "predicted_label"
    ] = predictions

    results[
        "predicted_category"
    ] = results[
        "predicted_label"
    ].map(
        {
            0: "benign",
            1: "phishing",
        }
    )

    results[
        "phishing_probability"
    ] = probabilities

    results.to_csv(
        output_path,
        index=False,
    )


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "PhishSenseAI paper-guided "
            "1D-CNN + BiLSTM classifier."
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
        "--glove",
        required=True,
        help=(
            "Path to pretrained "
            "100-dimensional GloVe file."
        ),
    )

    parser.add_argument(
        "--output-dir",
        default=(
            "training/models/"
            "bilstm/output"
        ),
    )

    parser.add_argument(
        "--max-length",
        type=int,
        default=(
            DEFAULT_MAX_SEQUENCE_LENGTH
        ),
    )

    parser.add_argument(
        "--num-filters",
        type=int,
        default=300,
    )

    parser.add_argument(
        "--kernel-size",
        type=int,
        default=5,
    )

    parser.add_argument(
        "--hidden-size",
        type=int,
        default=128,
    )

    parser.add_argument(
        "--dropout",
        type=float,
        default=0.5,
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
        "PhishSenseAI - "
        "1D-CNN + BiLSTM"
    )

    print(
        "Altwaijry et al. "
        "paper-guided implementation"
    )

    print("=" * 70)

    print(
        f"\nDevice: {device}"
    )

    if device.type == "cuda":
        print(
            "GPU: "
            + torch.cuda.get_device_name(
                0
            )
        )

    else:
        raise RuntimeError(
            "CUDA GPU is not available. "
            "Run this model from a Hopper "
            "GPU allocation."
        )

    # ========================================================
    # LOAD DATA
    # ========================================================

    print(
        "\nLoading dataset..."
    )

    data = load_data(
        args.dataset,
        args.splits,
    )

    train_data = data[
        data["split"]
        == "train"
    ].copy()

    validation_data = data[
        data["split"]
        == "validation"
    ].copy()

    test_data = data[
        data["split"]
        == "test"
    ].copy()

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
    # VOCABULARY
    # ========================================================

    vocabulary = build_vocabulary(
        train_data[
            "clean_text"
        ]
    )

    print(
        f"\nVocabulary size: "
        f"{len(vocabulary):,}"
    )

    print(
        f"Max sequence length: "
        f"{args.max_length}"
    )

    # ========================================================
    # GLOVE
    # ========================================================

    print(
        "\nLoading 100-D "
        "GloVe embeddings..."
    )

    embedding_matrix = (
        load_glove_embeddings(
            args.glove,
            vocabulary,
        )
    )

    # ========================================================
    # DATASETS
    # ========================================================

    train_dataset = EmailDataset(
        train_data,
        vocabulary,
        args.max_length,
    )

    validation_dataset = (
        EmailDataset(
            validation_data,
            vocabulary,
            args.max_length,
        )
    )

    test_dataset = EmailDataset(
        test_data,
        vocabulary,
        args.max_length,
    )

    sampler = (
        build_training_sampler(
            train_data[
                "label"
            ].values
        )
    )

    if sampler is None:
        print(
            "\nTraining balancing: "
            "not required"
        )

        train_loader = DataLoader(
            train_dataset,
            batch_size=BATCH_SIZE,
            shuffle=True,
            num_workers=0,
        )

    else:
        print(
            "\nTraining balancing: "
            "minority oversampling enabled"
        )

        train_loader = DataLoader(
            train_dataset,
            batch_size=BATCH_SIZE,
            sampler=sampler,
            num_workers=0,
        )

    validation_loader = DataLoader(
        validation_dataset,
        batch_size=BATCH_SIZE,
        shuffle=False,
        num_workers=0,
    )

    test_loader = DataLoader(
        test_dataset,
        batch_size=BATCH_SIZE,
        shuffle=False,
        num_workers=0,
    )

    # ========================================================
    # MODEL
    # ========================================================

    model = CNNBiLSTM(
        embedding_matrix=(
            embedding_matrix
        ),
        num_filters=(
            args.num_filters
        ),
        kernel_size=(
            args.kernel_size
        ),
        lstm_hidden_size=(
            args.hidden_size
        ),
        dropout=(
            args.dropout
        ),
    ).to(
        device
    )

    parameter_count = sum(
        parameter.numel()
        for parameter
        in model.parameters()
    )

    trainable_count = sum(
        parameter.numel()
        for parameter
        in model.parameters()
        if parameter.requires_grad
    )

    print(
        f"\nTotal parameters: "
        f"{parameter_count:,}"
    )

    print(
        f"Trainable parameters: "
        f"{trainable_count:,}"
    )

    loss_function = (
        nn.BCEWithLogitsLoss()
    )

    optimizer = torch.optim.Adam(
        model.parameters(),
        lr=LEARNING_RATE,
    )

    # ========================================================
    # TRAINING WITH EARLY STOPPING
    # ========================================================

    best_validation_loss = (
        float("inf")
    )

    patience_counter = 0

    best_model_path = (
        output_dir
        / "best_model.pt"
    )

    training_history = []

    print(
        "\nTraining..."
    )

    training_start = (
        time.perf_counter()
    )

    for epoch in range(
        1,
        MAX_EPOCHS + 1,
    ):

        train_loss = (
            train_one_epoch(
                model,
                train_loader,
                optimizer,
                loss_function,
                device,
            )
        )

        model.eval()

        validation_loss = 0.0

        with torch.no_grad():

            for (
                sequences,
                labels
            ) in validation_loader:

                sequences = sequences.to(
                    device
                )

                labels = labels.to(
                    device
                )

                logits = model(
                    sequences
                )

                loss = loss_function(
                    logits,
                    labels,
                )

                validation_loss += (
                    loss.item()
                    * len(labels)
                )

        validation_loss /= len(
            validation_dataset
        )

        (
            validation_true,
            validation_pred,
            validation_prob,
        ) = predict_model(
            model,
            validation_loader,
            device,
        )

        validation_f1 = f1_score(
            validation_true,
            validation_pred,
            zero_division=0,
        )

        print(
            f"Epoch {epoch:03d} | "
            f"train_loss={train_loss:.4f} | "
            f"val_loss={validation_loss:.4f} | "
            f"val_f1={validation_f1:.4f}"
        )

        training_history.append(
            {
                "epoch": epoch,
                "train_loss": (
                    train_loss
                ),
                "validation_loss": (
                    validation_loss
                ),
                "validation_f1": (
                    validation_f1
                ),
            }
        )

        if (
            validation_loss
            < best_validation_loss
        ):

            best_validation_loss = (
                validation_loss
            )

            patience_counter = 0

            torch.save(
                model.state_dict(),
                best_model_path,
            )

        else:
            patience_counter += 1

            if (
                patience_counter
                >= EARLY_STOPPING_PATIENCE
            ):

                print(
                    "\nEarly stopping triggered."
                )

                break

    training_time = (
        time.perf_counter()
        - training_start
    )

    print(
        f"\nTraining time: "
        f"{training_time:.2f} seconds"
    )

    # Load best validation-loss model.
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
    ) = predict_model(
        model,
        validation_loader,
        device,
    )

    (
        validation_metrics,
        validation_cm,
        validation_report,
    ) = evaluate_predictions(
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
    # TEST RESULTS
    # ========================================================

    inference_start = (
        time.perf_counter()
    )

    (
        test_true,
        test_predictions,
        test_probabilities,
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
    ) = evaluate_predictions(
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
        f"\nInference time for "
        f"test set: "
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
    # SAVE VOCABULARY
    # ========================================================

    with open(
        output_dir
        / "vocabulary.json",
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            vocabulary,
            file,
            indent=2,
        )

    # ========================================================
    # SAVE TRAINING HISTORY
    # ========================================================

    pd.DataFrame(
        training_history
    ).to_csv(
        output_dir
        / "training_history.csv",
        index=False,
    )

    # ========================================================
    # SAVE METRICS
    # ========================================================

    results = {
        "model": (
            "1D-CNN + BiLSTM"
        ),

        "reference_method": (
            "Altwaijry et al. (2024) "
            "paper-guided Advanced "
            "1D-CNNPD BiLSTM"
        ),

        "device": str(
            device
        ),

        "gpu_name": (
            torch.cuda.get_device_name(
                0
            )
            if device.type == "cuda"
            else None
        ),

        "random_state":
            RANDOM_STATE,

        "embedding":
            "GloVe 100-dimensional",

        "max_sequence_length":
            args.max_length,

        "num_filters":
            args.num_filters,

        "kernel_size":
            args.kernel_size,

        "lstm_hidden_size":
            args.hidden_size,

        "dropout":
            args.dropout,

        "batch_size":
            BATCH_SIZE,

        "learning_rate":
            LEARNING_RATE,

        "max_epochs":
            MAX_EPOCHS,

        "early_stopping_patience":
            EARLY_STOPPING_PATIENCE,

        "vocabulary_size":
            len(vocabulary),

        "total_parameters":
            parameter_count,

        "trainable_parameters":
            trainable_count,

        "training_records":
            len(train_data),

        "validation_records":
            len(validation_data),

        "test_records":
            len(test_data),

        "epochs_completed":
            len(training_history),

        "training_time_seconds":
            training_time,

        "test_inference_time_seconds":
            inference_time,

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
    # SAVE REPORT
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