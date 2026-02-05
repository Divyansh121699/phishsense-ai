import json
import re
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1]))
from detection.rule_based import analyze_email_dict
from detection.llm_based import get_llm_prediction

def run_combined_detection(email_text: str, email_meta: dict):
    rule_result = analyze_email_dict(email_meta, true_label="unknown")
    llm_label, llm_explanation = get_llm_prediction(email_text)

    # Strategy: Union (predict phishing if either says so)
    hybrid_label = (
        rule_result["is_phishing"] or llm_label == "phishing"
    )

    return {
        "rule_result": rule_result,
        "llm_label": llm_label,
        "llm_explanation": llm_explanation,
        "hybrid_label": "phishing" if hybrid_label else "benign"
    }
