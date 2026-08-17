import argparse
import json
import math
import re
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import StandardScaler

from xgboost import XGBClassifier


RANDOM_STATE = 42

LABEL_MAP = {
    "benign": 0,
    "phishing": 1,
}


# ============================================================
# PAPER-GUIDED WORD LISTS
# ============================================================

PRONOUNS = {
    "i", "me", "my", "mine", "we", "us", "our", "ours",
    "you", "your", "yours",
    "he", "him", "his", "she", "her", "hers",
    "they", "them", "their", "theirs",
    "it", "its",
}

FIRST_PERSON_PRONOUNS = {
    "i", "me", "my", "mine",
    "we", "us", "our", "ours",
}

SECOND_PERSON_PRONOUNS = {
    "you", "your", "yours", "yourself", "yourselves",
}

THIRD_PERSON_PRONOUNS = {
    "he", "him", "his",
    "she", "her", "hers",
    "they", "them", "their", "theirs",
    "it", "its",
}

CONJUNCTIONS = {
    "and", "but", "or", "nor", "for", "yet", "so",
    "although", "because", "since", "unless", "while",
    "whereas", "if",
}

PREPOSITIONS = {
    "in", "on", "at", "by", "for", "with", "from", "to",
    "of", "about", "against", "between", "into", "through",
    "during", "before", "after", "above", "below", "under",
    "over", "within", "without",
}

# Opara et al. explicitly mentions examples:
# click, verify, submit, download, update
IMPERATIVE_VERBS = {
    "click", "verify", "submit", "download", "update",
    "confirm", "login", "log", "open", "reply",
    "send", "provide", "enter", "reset", "pay",
    "activate", "review", "check", "visit", "follow",
}

TECHNICAL_JARGON = {
    "server", "database", "account", "security", "network",
    "authentication", "password", "credential", "system",
    "software", "firewall", "login", "domain", "administrator",
    "verification",
}

PROMOTIONAL_WORDS = {
    "free", "offer", "discount", "deal", "promotion",
    "winner", "prize", "bonus", "reward", "exclusive",
    "limited", "sale",
}

FINANCIAL_WORDS = {
    "bank", "payment", "invoice", "money", "refund",
    "transaction", "credit", "debit", "wire", "transfer",
    "dollar", "cash", "financial", "billing",
}

CREDENTIAL_WORDS = {
    "password", "username", "credential", "login",
    "account", "pin", "ssn", "identity", "authentication",
    "verification",
}

ACTION_WORDS = {
    "click", "open", "download", "verify", "confirm",
    "reply", "submit", "send", "update", "login",
    "visit", "pay",
}

MODAL_WORDS = {
    "can", "could", "may", "might", "must",
    "shall", "should", "will", "would",
}

POLITENESS_MARKERS = {
    "please", "thank", "thanks", "appreciate",
}

# Paper-specific examples
AGGRESSIVENESS_MARKERS = {
    "must", "now", "immediately",
}

URGENCY_MARKERS = {
    "urgent", "asap", "immediately",
}

CONDITIONAL_MARKERS = {
    "if", "unless",
}

PERSONALISATION_MARKERS = {
    "you", "your",
}

CLAUSE_MARKERS = {
    "and", "but", "or", "because", "although",
    "while", "if", "unless", "when", "where",
    "which", "that", "since",
}


# ============================================================
# BASIC TEXT PROCESSING
# ============================================================

def combine_email_text(subject, body):
    subject = "" if pd.isna(subject) else str(subject)
    body = "" if pd.isna(body) else str(body)

    return f"{subject} {body}".strip()


def get_words(text):
    return re.findall(
        r"\b[A-Za-z']+\b",
        text.lower(),
    )


def get_sentences(text):
    sentences = re.split(
        r"[.!?]+",
        text,
    )

    return [
        sentence.strip()
        for sentence in sentences
        if sentence.strip()
    ]


def count_terms(words, vocabulary):
    return sum(
        1
        for word in words
        if word in vocabulary
    )


def safe_divide(a, b):
    if b == 0:
        return 0.0

    return a / b


# ============================================================
# SYLLABLE / READABILITY HELPERS
# ============================================================

def count_syllables(word):
    word = word.lower()

    word = re.sub(
        r"[^a-z]",
        "",
        word,
    )

    if not word:
        return 0

    vowels = "aeiouy"

    count = 0
    previous_was_vowel = False

    for char in word:
        is_vowel = char in vowels

        if is_vowel and not previous_was_vowel:
            count += 1

        previous_was_vowel = is_vowel

    if (
        word.endswith("e")
        and count > 1
        and not word.endswith(("le", "ye"))
    ):
        count -= 1

    return max(count, 1)


def readability_features(
    words,
    sentences,
):
    word_count = len(words)
    sentence_count = max(
        len(sentences),
        1,
    )

    character_count = sum(
        len(word)
        for word in words
    )

    syllable_count = sum(
        count_syllables(word)
        for word in words
    )

    complex_words = [
        word
        for word in words
        if count_syllables(word) >= 3
    ]

    complex_word_count = len(
        complex_words
    )

    if word_count == 0:
        return {
            "flesch_reading_ease": 0.0,
            "flesch_kincaid_grade": 0.0,
            "gunning_fog": 0.0,
            "smog_index": 0.0,
            "coleman_liau_index": 0.0,
            "automated_readability_index": 0.0,
            "avg_syllables_per_word": 0.0,
            "complex_word_count": 0.0,
            "complex_word_ratio": 0.0,
            "avg_chars_per_sentence": 0.0,
        }

    words_per_sentence = (
        word_count / sentence_count
    )

    syllables_per_word = (
        syllable_count / word_count
    )

    flesch = (
        206.835
        - 1.015 * words_per_sentence
        - 84.6 * syllables_per_word
    )

    fk_grade = (
        0.39 * words_per_sentence
        + 11.8 * syllables_per_word
        - 15.59
    )

    complex_ratio = (
        complex_word_count
        / word_count
    )

    gunning_fog = (
        0.4
        * (
            words_per_sentence
            + 100 * complex_ratio
        )
    )

    if complex_word_count > 0:
        smog = (
            1.043
            * math.sqrt(
                complex_word_count
                * (30 / sentence_count)
            )
            + 3.1291
        )
    else:
        smog = 0.0

    letters_per_100_words = (
        character_count
        / word_count
        * 100
    )

    sentences_per_100_words = (
        sentence_count
        / word_count
        * 100
    )

    coleman_liau = (
        0.0588
        * letters_per_100_words
        - 0.296
        * sentences_per_100_words
        - 15.8
    )

    ari = (
        4.71
        * (character_count / word_count)
        + 0.5
        * words_per_sentence
        - 21.43
    )

    return {
        "flesch_reading_ease": flesch,
        "flesch_kincaid_grade": fk_grade,
        "gunning_fog": gunning_fog,
        "smog_index": smog,
        "coleman_liau_index": coleman_liau,
        "automated_readability_index": ari,
        "avg_syllables_per_word": syllables_per_word,
        "complex_word_count": complex_word_count,
        "complex_word_ratio": complex_ratio,
        "avg_chars_per_sentence": (
            character_count
            / sentence_count
        ),
    }


# ============================================================
# 60 PAPER-GUIDED STYLOMETRIC FEATURES
# ============================================================

def extract_features(text):
    words = get_words(text)
    sentences = get_sentences(text)

    word_count = len(words)
    character_count = len(text)

    unique_words = set(words)

    word_lengths = [
        len(word)
        for word in words
    ]

    sentence_lengths = [
        len(get_words(sentence))
        for sentence in sentences
    ]

    # --------------------------------------------------------
    # 1. LEXICAL FEATURES — 10
    # --------------------------------------------------------

    features = {
        "word_count": word_count,

        "character_count": character_count,

        "average_word_length": (
            np.mean(word_lengths)
            if word_lengths
            else 0
        ),

        "unique_word_count": len(
            unique_words
        ),

        "lexical_diversity": safe_divide(
            len(unique_words),
            word_count,
        ),

        "long_word_count": sum(
            length >= 7
            for length in word_lengths
        ),

        "short_word_count": sum(
            length <= 3
            for length in word_lengths
        ),

        "average_sentence_length": (
            np.mean(sentence_lengths)
            if sentence_lengths
            else 0
        ),

        "maximum_word_length": (
            max(word_lengths)
            if word_lengths
            else 0
        ),

        "minimum_word_length": (
            min(word_lengths)
            if word_lengths
            else 0
        ),
    }

    # --------------------------------------------------------
    # 2. SYNTACTIC FEATURES — 11
    # --------------------------------------------------------

    clause_count = count_terms(
        words,
        CLAUSE_MARKERS,
    )

    pronoun_count = count_terms(
        words,
        PRONOUNS,
    )

    features.update(
        {
            "sentence_count": len(
                sentences
            ),

            "clause_count": clause_count,

            "clause_density": safe_divide(
                clause_count,
                max(len(sentences), 1),
            ),

            "pronoun_count": (
                pronoun_count
            ),

            "pronoun_density": safe_divide(
                pronoun_count,
                word_count,
            ),

            "first_person_pronoun_count":
                count_terms(
                    words,
                    FIRST_PERSON_PRONOUNS,
                ),

            "second_person_pronoun_count":
                count_terms(
                    words,
                    SECOND_PERSON_PRONOUNS,
                ),

            "third_person_pronoun_count":
                count_terms(
                    words,
                    THIRD_PERSON_PRONOUNS,
                ),

            "conjunction_count":
                count_terms(
                    words,
                    CONJUNCTIONS,
                ),

            "preposition_count":
                count_terms(
                    words,
                    PREPOSITIONS,
                ),

            "average_clause_length":
                safe_divide(
                    word_count,
                    max(clause_count, 1),
                ),
        }
    )

    # --------------------------------------------------------
    # 3. PUNCTUATION FEATURES — 10
    # --------------------------------------------------------

    features.update(
        {
            "period_count":
                text.count("."),

            "comma_count":
                text.count(","),

            "exclamation_count":
                text.count("!"),

            "question_mark_count":
                text.count("?"),

            "colon_count":
                text.count(":"),

            "semicolon_count":
                text.count(";"),

            "hyphen_count":
                text.count("-"),

            "quotation_mark_count":
                text.count('"')
                + text.count("'"),

            "parenthesis_count":
                text.count("(")
                + text.count(")"),

            "slash_count":
                text.count("/"),
        }
    )

    # --------------------------------------------------------
    # 4. READABILITY FEATURES — 10
    # --------------------------------------------------------

    features.update(
        readability_features(
            words,
            sentences,
        )
    )

    # --------------------------------------------------------
    # 5. WORD CATEGORY FEATURES — 7
    # --------------------------------------------------------

    features.update(
        {
            "imperative_verb_count":
                count_terms(
                    words,
                    IMPERATIVE_VERBS,
                ),

            "technical_jargon_count":
                count_terms(
                    words,
                    TECHNICAL_JARGON,
                ),

            "promotional_word_count":
                count_terms(
                    words,
                    PROMOTIONAL_WORDS,
                ),

            "financial_word_count":
                count_terms(
                    words,
                    FINANCIAL_WORDS,
                ),

            "credential_word_count":
                count_terms(
                    words,
                    CREDENTIAL_WORDS,
                ),

            "action_word_count":
                count_terms(
                    words,
                    ACTION_WORDS,
                ),

            "modal_word_count":
                count_terms(
                    words,
                    MODAL_WORDS,
                ),
        }
    )

    # --------------------------------------------------------
    # 6. EMAIL-SPECIFIC FEATURES — 4
    # --------------------------------------------------------

    url_matches = re.findall(
        r"https?://\S+|www\.\S+",
        text,
        flags=re.IGNORECASE,
    )

    email_matches = re.findall(
        r"\b[A-Za-z0-9._%+-]+"
        r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        text,
    )

    attachment_mentions = len(
        re.findall(
            r"\b(?:attachment|attached|file|document)\b",
            text,
            flags=re.IGNORECASE,
        )
    )

    features.update(
        {
            "at_symbol_count":
                text.count("@"),

            "url_count":
                len(url_matches),

            "attachment_mentions":
                attachment_mentions,

            "email_address_count":
                len(email_matches),
        }
    )

    # --------------------------------------------------------
    # 7. COMPLEXITY FEATURES — 3
    # --------------------------------------------------------

    bigrams = list(
        zip(
            words,
            words[1:],
        )
    )

    trigrams = list(
        zip(
            words,
            words[1:],
            words[2:],
        )
    )

    features.update(
        {
            "bigram_count":
                len(bigrams),

            "trigram_count":
                len(trigrams),

            "word_length_variation":
                (
                    float(
                        np.std(
                            word_lengths
                        )
                    )
                    if word_lengths
                    else 0.0
                ),
        }
    )

    # --------------------------------------------------------
    # 8. STYLISTIC FEATURES — 5
    # --------------------------------------------------------

    features.update(
        {
            "politeness_markers_count":
                count_terms(
                    words,
                    POLITENESS_MARKERS,
                ),

            "aggressiveness_markers_count":
                count_terms(
                    words,
                    AGGRESSIVENESS_MARKERS,
                ),

            "urgency_markers_count":
                count_terms(
                    words,
                    URGENCY_MARKERS,
                ),

            "conditional_phrases_count":
                count_terms(
                    words,
                    CONDITIONAL_MARKERS,
                ),

            "personalisation_markers_count":
                count_terms(
                    words,
                    PERSONALISATION_MARKERS,
                ),
        }
    )

    if len(features) != 60:
        raise RuntimeError(
            f"Expected 60 stylometric features, "
            f"but generated {len(features)}."
        )

    return features


# ============================================================
# FEATURE MATRIX
# ============================================================

def create_feature_matrix(data):
    rows = []

    for _, row in data.iterrows():
        text = combine_email_text(
            row["subject"],
            row["body_text"],
        )

        rows.append(
            extract_features(text)
        )

    return pd.DataFrame(
        rows,
        index=data.index,
    )


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

    required_columns = {
        "email_id",
        "subject",
        "body_text",
        "high_level_category",
    }

    missing = (
        required_columns
        - set(dataset.columns)
    )

    if missing:
        raise ValueError(
            f"Missing dataset columns: "
            f"{sorted(missing)}"
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
            "Some IDs from the split file "
            "were not found in the dataset."
        )

    data["label"] = (
        data[
            "high_level_category"
        ]
        .astype(str)
        .str.strip()
        .str.lower()
        .map(LABEL_MAP)
    )

    if data[
        "label"
    ].isna().any():
        raise ValueError(
            "Unexpected high_level_category "
            "values detected."
        )

    return data


# ============================================================
# EVALUATION
# ============================================================

def evaluate_model(
    model,
    X,
    y,
):
    predictions = model.predict(
        X
    )

    probabilities = (
        model.predict_proba(
            X
        )[:, 1]
    )

    metrics = {
        "accuracy":
            accuracy_score(
                y,
                predictions,
            ),

        "precision":
            precision_score(
                y,
                predictions,
                zero_division=0,
            ),

        "recall":
            recall_score(
                y,
                predictions,
                zero_division=0,
            ),

        "f1":
            f1_score(
                y,
                predictions,
                zero_division=0,
            ),

        "f1_macro":
            f1_score(
                y,
                predictions,
                average="macro",
                zero_division=0,
            ),

        "roc_auc":
            roc_auc_score(
                y,
                probabilities,
            ),
    }

    cm = confusion_matrix(
        y,
        predictions,
    )

    report = (
        classification_report(
            y,
            predictions,
            target_names=[
                "benign",
                "phishing",
            ],
            digits=4,
            zero_division=0,
        )
    )

    return (
        metrics,
        cm,
        report,
        predictions,
        probabilities,
    )


# ============================================================
# SAVE PREDICTIONS
# ============================================================

def save_predictions(
    data,
    predictions,
    probabilities,
    output_path,
):
    results = data[
        [
            "email_id",
            "high_level_category",
        ]
    ].copy()

    results[
        "true_label"
    ] = data[
        "label"
    ].values

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
            "XGBoost stylometric classifier."
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
            "xgboost/output"
        ),
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
    print(
        "PhishSenseAI - XGBoost"
    )
    print(
        "Opara et al. paper-guided implementation"
    )
    print(
        "60 Stylometric + Linguistic Features"
    )
    print("=" * 70)

    # --------------------------------------------------------
    # Load
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Feature extraction
    # --------------------------------------------------------

    print(
        "\nExtracting 60 stylometric "
        "features..."
    )

    extraction_start = (
        time.perf_counter()
    )

    X_train_raw = (
        create_feature_matrix(
            train_data
        )
    )

    X_validation_raw = (
        create_feature_matrix(
            validation_data
        )
    )

    X_test_raw = (
        create_feature_matrix(
            test_data
        )
    )

    extraction_time = (
        time.perf_counter()
        - extraction_start
    )

    feature_names = list(
        X_train_raw.columns
    )

    print(
        f"Features extracted: "
        f"{len(feature_names)}"
    )

    print(
        f"Feature extraction time: "
        f"{extraction_time:.2f} seconds"
    )

    # --------------------------------------------------------
    # Standardisation
    #
    # Fit scaler ONLY on training data to prevent leakage.
    # --------------------------------------------------------

    print(
        "\nStandardising features..."
    )

    scaler = StandardScaler()

    X_train = (
        scaler.fit_transform(
            X_train_raw
        )
    )

    X_validation = (
        scaler.transform(
            X_validation_raw
        )
    )

    X_test = (
        scaler.transform(
            X_test_raw
        )
    )

    y_train = (
        train_data["label"]
    )

    y_validation = (
        validation_data["label"]
    )

    y_test = (
        test_data["label"]
    )

    # --------------------------------------------------------
    # XGBoost
    #
    # Paper uses default XGBoost settings.
    # random_state is fixed only for reproducibility.
    # --------------------------------------------------------

    print(
        "\nTraining XGBoost..."
    )

    print(
        "Paper-guided default "
        "XGBoost configuration"
    )

    model = XGBClassifier(
        random_state=RANDOM_STATE,
        eval_metric="logloss",
    )

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
        f"Training time: "
        f"{training_time:.2f} seconds"
    )

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

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
            f"{key}: "
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

    # --------------------------------------------------------
    # Test
    # --------------------------------------------------------

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
            f"{key}: "
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
        f"\nInference time for test set: "
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

    # --------------------------------------------------------
    # Feature importance
    # --------------------------------------------------------

    importance_df = (
        pd.DataFrame(
            {
                "feature":
                    feature_names,

                "importance":
                    model.feature_importances_,
            }
        )
        .sort_values(
            "importance",
            ascending=False,
        )
        .reset_index(
            drop=True
        )
    )

    importance_df.to_csv(
        output_dir
        / "feature_importance.csv",
        index=False,
    )

    print(
        "\nTop 10 Features:"
    )

    print(
        importance_df
        .head(10)
        .to_string(
            index=False
        )
    )

    # --------------------------------------------------------
    # Save model package
    # --------------------------------------------------------

    model_package = {
        "model":
            model,

        "scaler":
            scaler,

        "feature_names":
            feature_names,
    }

    joblib.dump(
        model_package,
        output_dir
        / "xgboost_model.joblib",
    )

    # --------------------------------------------------------
    # Save feature list
    # --------------------------------------------------------

    with open(
        output_dir
        / "stylometric_features.json",
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            feature_names,
            file,
            indent=4,
        )

    # --------------------------------------------------------
    # Predictions
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

    metrics_output = {
        "model":
            "XGBoost",

        "reference_method": (
            "Opara et al. (2025) "
            "paper-guided 60 stylometric "
            "feature approach"
        ),

        "random_state":
            RANDOM_STATE,

        "feature_count":
            len(feature_names),

        "training_records":
            len(train_data),

        "validation_records":
            len(validation_data),

        "test_records":
            len(test_data),

        "feature_extraction_time_seconds":
            extraction_time,

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

        "top_10_features":
            importance_df
            .head(10)
            .to_dict(
                orient="records"
            ),
    }

    with open(
        output_dir
        / "metrics.json",
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            metrics_output,
            file,
            indent=4,
        )

    # --------------------------------------------------------
    # Classification report
    # --------------------------------------------------------

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