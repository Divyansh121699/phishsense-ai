import json
from pathlib import Path

# ========== CONFIG ==========
RULE_PATH = Path("detection/output_rule/details/summary_detected.json")
LLM_PATH = Path("detection/output_llm/details/llm_scan_results.json")
OUTPUT_DIR = Path("detection/output_hybrid")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ========== LOAD DATA ==========
def load_results():
    with open(RULE_PATH, "r", encoding="utf-8") as f:
        rule_data = json.load(f)
    with open(LLM_PATH, "r", encoding="utf-8") as f:
        llm_data = json.load(f)
    return rule_data, llm_data

# ========== MERGE BY FILENAME ==========
def merge_results(rule_data, llm_data):
    llm_lookup = {d["source_file"]: d for d in llm_data}
    combined = []

    for r in rule_data:
        fname = r["source_file"]
        if fname not in llm_lookup:
            continue
        l = llm_lookup[fname]
        combined.append({
            "filename": fname,
            "true_label": r["actual_label"],
            "rule_label": r["predicted_label"],
            "llm_label": l["llm_label"],
            "rule_score": r["score"],
            "llm_explanation": l.get("explanation", "")
        })
    return combined

# ========== METRICS ==========
def evaluate(predictions):
    TP = TN = FP = FN = 0
    for p in predictions:
        pred = p["hybrid_label"]
        true = p["true_label"]
        if pred == "phishing" and true == "phishing":
            TP += 1
        elif pred == "benign" and true == "benign":
            TN += 1
        elif pred == "phishing" and true == "benign":
            FP += 1
        elif pred == "benign" and true == "phishing":
            FN += 1

    precision = round(TP / (TP + FP), 3) if (TP + FP) > 0 else 0
    recall = round(TP / (TP + FN), 3) if (TP + FN) > 0 else 0
    accuracy = round((TP + TN) / (TP + TN + FP + FN), 3)
    f1 = round(2 * TP / (2 * TP + FP + FN), 3) if (2 * TP + FP + FN) > 0 else 0

    return {
        "total_emails": TP + TN + FP + FN,
        "true_positives": TP,
        "true_negatives": TN,
        "false_positives": FP,
        "false_negatives": FN,
        "precision": precision,
        "recall": recall,
        "accuracy": accuracy,
        "f1_score": f1
    }

# ========== STRATEGY EXECUTION ==========
def run_strategy(data, strategy):
    predictions = []
    for d in data:
        r = d["rule_label"]
        l = d["llm_label"]

        if strategy == "union":
            pred = "phishing" if "phishing" in (r, l) else "benign"
        elif strategy == "intersection":
            pred = "phishing" if r == "phishing" and l == "phishing" else "benign"
        elif strategy == "weighted":
            score = 0
            if r == "phishing":
                score += 1
            if l == "phishing":
                score += 1
            pred = "phishing" if score >= 1 else "benign"
        else:
            raise ValueError("Unknown strategy")

        d["hybrid_label"] = pred
        predictions.append(d)

    metrics = evaluate(predictions)
    print(f"\n📊 Strategy: {strategy.upper()}")
    print(json.dumps(metrics, indent=4))

    # Save results
    with open(OUTPUT_DIR / f"{strategy}_results.json", "w", encoding="utf-8") as f:
        json.dump(predictions, f, indent=4)

    with open(OUTPUT_DIR / f"{strategy}_metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=4)

# ========== MAIN ==========
if __name__ == "__main__":
    rule_data, llm_data = load_results()
    combined_data = merge_results(rule_data, llm_data)

    for strategy in ["union", "intersection", "weighted"]:
        run_strategy(combined_data, strategy)
