from typing import Any


DEFAULT_PHISHING_THRESHOLD = 0.50

DEFAULT_WEIGHTS = {
    "weighted_heuristic": 0.30,
    "rule_association": 0.30,
    "llm": 0.40,
}


def normalize_prediction(prediction: Any) -> str:
    """
    Normalize a detector prediction to phishing or benign.
    """

    normalized = str(prediction).strip().lower()

    if normalized in {
        "phishing",
        "spam",
        "malicious",
        "fraud",
        "scam",
    }:
        return "phishing"

    if normalized in {
        "benign",
        "legitimate",
        "safe",
        "ham",
    }:
        return "benign"

    return "unknown"


def normalize_confidence(confidence: Any) -> float:
    """
    Normalize confidence to the range 0.0 to 1.0.
    """

    try:
        normalized = float(confidence)
    except (TypeError, ValueError):
        return 0.0

    if normalized > 1:
        normalized = normalized / 100

    return round(
        max(0.0, min(normalized, 1.0)),
        3,
    )


def get_detector_method(
    result: dict[str, Any],
) -> str:
    """
    Return a standardized detector method name.
    """

    method = str(
        result.get("method", "")
    ).strip().lower()

    method_aliases = {
        "heuristic": "weighted_heuristic",
        "rule_based": "weighted_heuristic",
        "weighted_rule": "weighted_heuristic",
        "association": "rule_association",
        "association_rule": "rule_association",
        "gpt": "llm",
        "gpt_5": "llm",
        "gpt-5": "llm",
    }

    return method_aliases.get(method, method)


def calculate_phishing_score(
    result: dict[str, Any],
) -> float:
    """
    Convert a detector result into a phishing probability.

    Examples:
    phishing with confidence 0.90 -> 0.90
    benign with confidence 0.90 -> 0.10
    """

    prediction = normalize_prediction(
        result.get(
            "prediction",
            result.get(
                "predicted_label",
                result.get(
                    "llm_label",
                    result.get("label", "unknown"),
                ),
            ),
        )
    )

    confidence = normalize_confidence(
        result.get("confidence", 0.0)
    )

    if prediction == "phishing":
        return confidence

    if prediction == "benign":
        return round(1.0 - confidence, 3)

    return 0.5


def normalize_weights(
    weights: dict[str, float],
    available_methods: list[str],
) -> dict[str, float]:
    """
    Normalize weights across detectors that are actually present.
    """

    active_weights = {
        method: float(weights.get(method, 0.0))
        for method in available_methods
        if float(weights.get(method, 0.0)) > 0
    }

    total_weight = sum(active_weights.values())

    if total_weight <= 0:
        equal_weight = (
            1.0 / len(available_methods)
            if available_methods
            else 0.0
        )

        return {
            method: equal_weight
            for method in available_methods
        }

    return {
        method: round(weight / total_weight, 6)
        for method, weight in active_weights.items()
    }


def normalize_actual_label(
    actual_label: Any,
) -> tuple[str, str | None]:
    """
    Normalize ground truth for evaluation.

    Spam is treated as malicious/phishing.
    """

    if actual_label is None:
        return "unknown", None

    normalized = str(actual_label).strip().lower()

    if normalized == "spam":
        expected_prediction = "phishing"
    elif normalized in {"phishing", "benign"}:
        expected_prediction = normalized
    else:
        expected_prediction = None

    return normalized, expected_prediction


def weighted_fusion(
    detector_results: list[dict[str, Any]],
    weights: dict[str, float] | None = None,
    threshold: float = DEFAULT_PHISHING_THRESHOLD,
    actual_label: str | None = None,
) -> dict[str, Any]:
    """
    Fuse detector results using a weighted phishing score.
    """

    if not detector_results:
        raise ValueError(
            "At least one detector result is required."
        )

    if weights is None:
        weights = DEFAULT_WEIGHTS.copy()

    normalized_results = []
    seen_methods = set()

    for result in detector_results:
        if not isinstance(result, dict):
            continue

        method = get_detector_method(result)

        if not method:
            continue

        if method in seen_methods:
            raise ValueError(
                f"Duplicate detector result received for method: {method}"
            )

        seen_methods.add(method)

        prediction = normalize_prediction(
            result.get(
                "prediction",
                result.get(
                    "predicted_label",
                    result.get(
                        "llm_label",
                        result.get("label", "unknown"),
                    ),
                ),
            )
        )

        confidence = normalize_confidence(
            result.get("confidence", 0.0)
        )

        phishing_score = calculate_phishing_score(
            result
        )

        normalized_results.append(
            {
                "method": method,
                "prediction": prediction,
                "confidence": confidence,
                "phishing_score": phishing_score,
                "original_result": result,
            }
        )

    if not normalized_results:
        raise ValueError(
            "No valid detector results were provided."
        )

    available_methods = [
        result["method"]
        for result in normalized_results
    ]

    normalized_weights = normalize_weights(
        weights,
        available_methods,
    )

    weighted_components = []

    final_phishing_score = 0.0

    for result in normalized_results:
        method = result["method"]
        method_weight = normalized_weights.get(
            method,
            0.0,
        )

        weighted_score = (
            result["phishing_score"]
            * method_weight
        )

        final_phishing_score += weighted_score

        weighted_components.append(
            {
                "method": method,
                "prediction": result["prediction"],
                "confidence": result["confidence"],
                "phishing_score": result[
                    "phishing_score"
                ],
                "weight": round(
                    method_weight,
                    3,
                ),
                "weighted_score": round(
                    weighted_score,
                    3,
                ),
            }
        )

    final_phishing_score = round(
        final_phishing_score,
        3,
    )

    prediction = (
        "phishing"
        if final_phishing_score >= threshold
        else "benign"
    )

    confidence = (
        final_phishing_score
        if prediction == "phishing"
        else 1.0 - final_phishing_score
    )

    confidence = round(confidence, 3)

    if actual_label is None:
        for result in normalized_results:
            result_actual_label = (
                result["original_result"].get(
                    "actual_label"
                )
            )

            if result_actual_label not in {
                None,
                "",
                "unknown",
            }:
                actual_label = result_actual_label
                break

    normalized_actual_label, expected_prediction = (
        normalize_actual_label(actual_label)
    )

    correct = (
        prediction == expected_prediction
        if expected_prediction is not None
        else None
    )

    votes = {
        "phishing": sum(
            result["prediction"] == "phishing"
            for result in normalized_results
        ),
        "benign": sum(
            result["prediction"] == "benign"
            for result in normalized_results
        ),
        "unknown": sum(
            result["prediction"] == "unknown"
            for result in normalized_results
        ),
    }

    return {
        "method": "weighted_fusion",
        "prediction": prediction,
        "confidence": confidence,
        "is_phishing": prediction == "phishing",

        "phishing_score": final_phishing_score,
        "threshold": threshold,

        "actual_label": normalized_actual_label,
        "correct": correct,

        "weights": normalized_weights,
        "votes": votes,

        "detector_count": len(normalized_results),
        "detectors_used": available_methods,

        "weighted_components": weighted_components,

        "detector_results": {
            result["method"]: result["original_result"]
            for result in normalized_results
        },
    }


def majority_vote_fusion(
    detector_results: list[dict[str, Any]],
    actual_label: str | None = None,
    tie_breaker: str = "highest_confidence",
) -> dict[str, Any]:
    """
    Fuse detector results using majority voting.
    """

    if not detector_results:
        raise ValueError(
            "At least one detector result is required."
        )

    normalized_results = []

    for result in detector_results:
        method = get_detector_method(result)

        if not method:
            continue

        prediction = normalize_prediction(
            result.get(
                "prediction",
                result.get(
                    "predicted_label",
                    result.get(
                        "llm_label",
                        result.get("label", "unknown"),
                    ),
                ),
            )
        )

        confidence = normalize_confidence(
            result.get("confidence", 0.0)
        )

        normalized_results.append(
            {
                "method": method,
                "prediction": prediction,
                "confidence": confidence,
                "original_result": result,
            }
        )

    phishing_results = [
        result
        for result in normalized_results
        if result["prediction"] == "phishing"
    ]

    benign_results = [
        result
        for result in normalized_results
        if result["prediction"] == "benign"
    ]

    phishing_votes = len(phishing_results)
    benign_votes = len(benign_results)

    if phishing_votes > benign_votes:
        prediction = "phishing"
        winning_results = phishing_results

    elif benign_votes > phishing_votes:
        prediction = "benign"
        winning_results = benign_results

    else:
        normalized_tie_breaker = (
            tie_breaker.strip().lower()
        )

        if normalized_tie_breaker == "phishing":
            prediction = "phishing"
            winning_results = phishing_results

        elif normalized_tie_breaker == "benign":
            prediction = "benign"
            winning_results = benign_results

        elif normalized_tie_breaker == "highest_confidence":
            valid_results = [
                result
                for result in normalized_results
                if result["prediction"] in {
                    "phishing",
                    "benign",
                }
            ]

            if valid_results:
                strongest_result = max(
                    valid_results,
                    key=lambda result: result[
                        "confidence"
                    ],
                )

                prediction = strongest_result[
                    "prediction"
                ]

                winning_results = [
                    strongest_result
                ]
            else:
                prediction = "benign"
                winning_results = []

        else:
            raise ValueError(
                "Unsupported tie breaker. Use "
                "'highest_confidence', 'phishing', "
                "or 'benign'."
            )

    if winning_results:
        confidence = round(
            sum(
                result["confidence"]
                for result in winning_results
            )
            / len(winning_results),
            3,
        )
    else:
        confidence = 0.5

    if actual_label is None:
        for result in normalized_results:
            candidate = result[
                "original_result"
            ].get("actual_label")

            if candidate not in {
                None,
                "",
                "unknown",
            }:
                actual_label = candidate
                break

    normalized_actual_label, expected_prediction = (
        normalize_actual_label(actual_label)
    )

    correct = (
        prediction == expected_prediction
        if expected_prediction is not None
        else None
    )

    return {
        "method": "majority_vote_fusion",
        "prediction": prediction,
        "confidence": confidence,
        "is_phishing": prediction == "phishing",

        "actual_label": normalized_actual_label,
        "correct": correct,

        "tie_breaker": tie_breaker,

        "votes": {
            "phishing": phishing_votes,
            "benign": benign_votes,
            "unknown": sum(
                result["prediction"] == "unknown"
                for result in normalized_results
            ),
        },

        "detector_count": len(normalized_results),
        "detectors_used": [
            result["method"]
            for result in normalized_results
        ],

        "detector_results": {
            result["method"]: result["original_result"]
            for result in normalized_results
        },
    }


def fuse_detector_results(
    detector_results: list[dict[str, Any]],
    strategy: str = "weighted",
    weights: dict[str, float] | None = None,
    threshold: float = DEFAULT_PHISHING_THRESHOLD,
    actual_label: str | None = None,
    tie_breaker: str = "highest_confidence",
) -> dict[str, Any]:
    """
    Public fusion function.

    Supported strategies:
    - weighted
    - majority_vote
    """

    normalized_strategy = (
        strategy.strip().lower()
    )

    if normalized_strategy in {
        "weighted",
        "weighted_fusion",
    }:
        return weighted_fusion(
            detector_results=detector_results,
            weights=weights,
            threshold=threshold,
            actual_label=actual_label,
        )

    if normalized_strategy in {
        "majority",
        "majority_vote",
        "majority-vote",
    }:
        return majority_vote_fusion(
            detector_results=detector_results,
            actual_label=actual_label,
            tie_breaker=tie_breaker,
        )

    raise ValueError(
        "Unsupported fusion strategy. "
        "Use 'weighted' or 'majority_vote'."
    )


if __name__ == "__main__":
    sample_results = [
        {
            "method": "weighted_heuristic",
            "prediction": "phishing",
            "confidence": 0.75,
            "actual_label": "phishing",
        },
        {
            "method": "rule_association",
            "prediction": "phishing",
            "confidence": 0.85,
            "actual_label": "phishing",
        },
        {
            "method": "llm",
            "prediction": "benign",
            "confidence": 0.70,
            "actual_label": "phishing",
        },
    ]

    result = fuse_detector_results(
        detector_results=sample_results,
        strategy="weighted",
    )

    print(result)