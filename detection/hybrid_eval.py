import json
from pathlib import Path

from detection.detection_controller import detect_email

# ==========================
# CONFIGURATION
# ==========================

PHISHING_DIR = Path("phishing_emails")
BENIGN_DIR = Path("benign_emails")

OUTPUT_DIR = Path("detection/output_hybrid")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Detection mode to evaluate
DETECTION_MODE = "full_ensemble"

# Fusion strategy
FUSION_STRATEGY = "weighted"


# ==========================
# EVALUATION
# ==========================

def evaluate_directory(directory, true_label):

    results = []

    files = list(directory.glob("*.json"))

    for file in files:

        result = detect_email(
            file_path=file,
            mode=DETECTION_MODE,
            true_label=true_label,
            fusion_strategy=FUSION_STRATEGY,
        )

        results.append(result)

        print(
            f"{file.name} -> "
            f"{result['prediction']} "
            f"({result['confidence']:.3f})"
        )

    return results


# ==========================
# METRICS
# ==========================

def compute_metrics(results):

    TP = TN = FP = FN = 0

    for r in results:

        pred = r["prediction"]
        actual = r["actual_label"]

        if pred == "phishing" and actual == "phishing":
            TP += 1

        elif pred == "benign" and actual == "benign":
            TN += 1

        elif pred == "phishing" and actual == "benign":
            FP += 1

        elif pred == "benign" and actual == "phishing":
            FN += 1

    total = TP + TN + FP + FN

    return {

        "total_emails": total,

        "true_positives": TP,
        "true_negatives": TN,
        "false_positives": FP,
        "false_negatives": FN,

        "precision":
            round(TP / (TP + FP), 3)
            if TP + FP else 0,

        "recall":
            round(TP / (TP + FN), 3)
            if TP + FN else 0,

        "accuracy":
            round((TP + TN) / total, 3)
            if total else 0,

        "f1_score":
            round(
                2 * TP /
                (2 * TP + FP + FN),
                3,
            )
            if (2 * TP + FP + FN)
            else 0,
    }


# ==========================
# MAIN
# ==========================

if __name__ == "__main__":

    phishing = evaluate_directory(
        PHISHING_DIR,
        "phishing",
    )

    benign = evaluate_directory(
        BENIGN_DIR,
        "benign",
    )

    all_results = phishing + benign

    metrics = compute_metrics(all_results)

    with open(
        OUTPUT_DIR / "evaluation_results.json",
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(all_results, f, indent=4)

    with open(
        OUTPUT_DIR / "evaluation_metrics.json",
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(metrics, f, indent=4)

    print()

    print(json.dumps(metrics, indent=4))