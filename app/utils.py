import re
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
from detection.rule_based import analyze_email_dict
from detection.llm_based import get_llm_prediction
from detection.schema_utils import normalize_email_record


def _extract_llm_confidence(llm_explanation: str, llm_label: str) -> float:
    """Extract an LLM confidence value if the prompt response contains one.

    Falls back to conservative defaults so the hybrid module still works with
    older responses containing only Label and Explanation.
    """
    text = llm_explanation or ""
    patterns = [
        r"confidence\s*[:=]\s*(0\.\d+|1(?:\.0+)?)",
        r"confidence\s*[:=]\s*(\d{1,3})\s*%",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            value = float(match.group(1))
            if value > 1:
                value = value / 100
            return max(0.0, min(value, 1.0))

    # Conservative defaults: the LLM is helpful, but not treated as certainty.
    return 0.85 if llm_label == "phishing" else 0.80


def _risk_level(score: float) -> str:
    if score >= 0.70:
        return "High"
    if score >= 0.40:
        return "Medium"
    return "Low"


def _top_indicators(rule_result: dict, limit: int = 5):
    indicators = rule_result.get("indicators", []) or []
    positive = [i for i in indicators if i.get("weight", 0) > 0]
    return sorted(positive, key=lambda i: i.get("weight", 0), reverse=True)[:limit]


def run_combined_detection(email_text: str, email_meta: dict):
    normalized = normalize_email_record(email_meta)
    email_text = normalized.get("email_text", email_text)

    # 4A. Heuristic engine
    rule_result = analyze_email_dict(normalized, true_label="unknown")
    rule_confidence = float(rule_result.get("rule_confidence", rule_result.get("score", 0) / 100))

    # 4B. LLM semantic reasoning
    llm_result = get_llm_prediction(email_text, normalized)
    llm_label = llm_result.get("label", "benign")
    llm_confidence = float(llm_result.get("confidence", 0.80))
    llm_explanation = llm_result.get("explanation", "")
    llm_confidence = _extract_llm_confidence(llm_explanation, llm_label)
    llm_phishing_probability = llm_confidence if llm_label == "phishing" else 1 - llm_confidence

    # 5. Hybrid decision fusion
    # Weighted fusion makes the architecture explicit: heuristic evidence + LLM semantic confidence.
    hybrid_probability = (0.35 * rule_confidence) + (0.65 * llm_phishing_probability)
    hybrid_score = round(hybrid_probability * 100, 2)
    risk_level = _risk_level(hybrid_probability)

    # Final label remains binary for evaluation, while risk_level captures uncertainty.
   # Final label uses three classes: benign, suspicious, phishing.
# Suspicious now requires either medium hybrid confidence or stronger rule evidence.
    if hybrid_probability >= 0.70:
        hybrid_label = "phishing"
    elif hybrid_probability >= 0.40:
        hybrid_label = "suspicious"
    elif rule_result.get("score", 0) >= 50 and llm_label == "benign":
        hybrid_label = "suspicious"
    else:
        hybrid_label = "benign"

    # Keep risk level consistent with the final hybrid label.
    if hybrid_label == "phishing":
        risk_level = "High"
    elif hybrid_label == "suspicious":
        risk_level = "Medium"
    else:
        risk_level = "Low"

    if hybrid_label == "phishing":
        decision_reason = (
            f"Hybrid score {hybrid_score}% exceeded phishing threshold. "
            f"Rule confidence={round(rule_confidence,2)}, "
            f"LLM predicted phishing."
        )

    elif hybrid_label == "suspicious":
        decision_reason = (
            f"Moderate hybrid score ({hybrid_score}%). "
            f"Conflicting heuristic and semantic evidence detected."
        )

    else:
        decision_reason = (
            f"Low hybrid score ({hybrid_score}%). "
            f"No strong phishing indicators identified."
        )

    top_indicators = _top_indicators(rule_result)

    return {
        "normalized_email": normalized,
        "rule_result": rule_result,
        "llm_label": llm_label,
        "llm_confidence": round(llm_confidence, 3),
        "llm_explanation": llm_explanation,
        "hybrid_label": hybrid_label,
        "hybrid_score": hybrid_score,
        "risk_level": risk_level,
        "top_indicators": top_indicators,
        "analysis_report": {
            "decision_reason": decision_reason,
            "heuristic_confidence": round(rule_confidence, 3),
            "llm_phishing_probability": round(llm_phishing_probability, 3),
            "fusion_formula": "0.35 * heuristic_confidence + 0.65 * llm_phishing_probability",
            "top_indicators": top_indicators,
        },
        "llm_intent": llm_result.get("intent", ""),
        "llm_sender_trust": llm_result.get("sender_trust", ""),
        "llm_url_risk": llm_result.get("url_risk", ""),
        "llm_social_engineering_risk": llm_result.get("social_engineering_risk", ""),
        "llm_explanation": llm_explanation,
    }
