import json
from pathlib import Path
from typing import Any

try:
    from detection.rule_based import analyze_email, analyze_email_dict
except ImportError:
    from rule_based import analyze_email, analyze_email_dict


# ========== CONFIG ==========
PROJECT_ROOT = Path(__file__).resolve().parent.parent
PATTERN_FILE = PROJECT_ROOT / "rules" / "association_patterns.json"

DEFAULT_PATTERN_THRESHOLD = 0.70


# ========== PATTERN LOADING ==========
def load_patterns(pattern_file: Path = PATTERN_FILE) -> list[dict[str, Any]]:
    """
    Load enabled rule-association patterns from the JSON configuration file.
    """

    if not pattern_file.exists():
        raise FileNotFoundError(
            f"Association pattern file was not found: {pattern_file}"
        )

    with open(pattern_file, "r", encoding="utf-8") as file:
        patterns = json.load(file)

    if not isinstance(patterns, list):
        raise ValueError(
            "association_patterns.json must contain a JSON list."
        )

    enabled_patterns = [
        pattern
        for pattern in patterns
        if pattern.get("enabled", True)
    ]

    return enabled_patterns


# ========== PATTERN VALIDATION ==========
def validate_pattern(
    pattern: dict[str, Any],
    available_indicators: set[str],
) -> list[str]:
    """
    Return indicator names used by a pattern that do not exist in
    the atomic-indicator output.
    """

    required = pattern.get("required_indicators", [])
    supporting = pattern.get("supporting_indicators", [])

    referenced_indicators = set(required + supporting)

    return sorted(
        referenced_indicators - available_indicators
    )


# ========== PATTERN MATCHING ==========
def match_pattern(
    pattern: dict[str, Any],
    atomic_indicators: dict[str, bool],
) -> dict[str, Any]:
    """
    Check whether one association pattern matches an email.
    """

    required_indicators = pattern.get(
        "required_indicators",
        [],
    )

    supporting_indicators = pattern.get(
        "supporting_indicators",
        [],
    )

    minimum_supporting_matches = int(
        pattern.get(
            "minimum_supporting_matches",
            0,
        )
    )

    matched_required = [
        indicator
        for indicator in required_indicators
        if atomic_indicators.get(indicator, False)
    ]

    missing_required = [
        indicator
        for indicator in required_indicators
        if not atomic_indicators.get(indicator, False)
    ]

    matched_supporting = [
        indicator
        for indicator in supporting_indicators
        if atomic_indicators.get(indicator, False)
    ]

    required_match = (
        len(matched_required)
        == len(required_indicators)
    )

    supporting_match = (
        len(matched_supporting)
        >= minimum_supporting_matches
    )

    matched = required_match and supporting_match

    required_coverage = (
        len(matched_required) / len(required_indicators)
        if required_indicators
        else 1.0
    )

    supporting_coverage = (
        len(matched_supporting) / len(supporting_indicators)
        if supporting_indicators
        else 1.0
    )

    base_confidence = float(
        pattern.get(
            "pilot_confidence",
            0.0,
        )
    )

    if matched:
        confidence = base_confidence
    else:
        confidence = 0.0

    return {
        "pattern_id": pattern.get(
            "pattern_id",
            "",
        ),
        "pattern_name": pattern.get(
            "pattern_name",
            "",
        ),
        "description": pattern.get(
            "description",
            "",
        ),
        "matched": matched,
        "confidence": round(
            confidence,
            3,
        ),
        "pilot_support": float(
            pattern.get(
                "pilot_support",
                0.0,
            )
        ),
        "required_indicators": required_indicators,
        "supporting_indicators": supporting_indicators,
        "matched_required_indicators": matched_required,
        "missing_required_indicators": missing_required,
        "matched_supporting_indicators": matched_supporting,
        "minimum_supporting_matches":
            minimum_supporting_matches,
        "required_coverage": round(
            required_coverage,
            3,
        ),
        "supporting_coverage": round(
            supporting_coverage,
            3,
        ),
    }


def match_patterns(
    atomic_indicators: dict[str, bool],
    patterns: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """
    Match all enabled association patterns against an email.
    """

    if patterns is None:
        patterns = load_patterns()

    return [
        match_pattern(
            pattern,
            atomic_indicators,
        )
        for pattern in patterns
    ]


# ========== CONFIDENCE FUSION ==========
def maximum_pattern_confidence(
    matched_patterns: list[dict[str, Any]],
) -> float:
    """
    Use the confidence of the strongest matched pattern.
    """

    if not matched_patterns:
        return 0.0

    return round(
        max(
            pattern.get("confidence", 0.0)
            for pattern in matched_patterns
        ),
        3,
    )


def average_pattern_confidence(
    matched_patterns: list[dict[str, Any]],
) -> float:
    """
    Average the confidence of all matched patterns.
    """

    if not matched_patterns:
        return 0.0

    confidences = [
        float(pattern.get("confidence", 0.0))
        for pattern in matched_patterns
    ]

    return round(
        sum(confidences) / len(confidences),
        3,
    )


def noisy_or_pattern_confidence(
    matched_patterns: list[dict[str, Any]],
) -> float:
    """
    Combine matched pattern confidence values using Noisy OR.
    """

    if not matched_patterns:
        return 0.0

    probability_none = 1.0

    for pattern in matched_patterns:
        confidence = float(
            pattern.get(
                "confidence",
                0.0,
            )
        )

        confidence = max(
            0.0,
            min(confidence, 1.0),
        )

        probability_none *= 1.0 - confidence

    return round(
        1.0 - probability_none,
        3,
    )


def calculate_pattern_confidence(
    matched_patterns: list[dict[str, Any]],
    strategy: str = "maximum",
) -> float:
    """
    Calculate final rule-association confidence.
    """

    normalized_strategy = strategy.strip().lower()

    if normalized_strategy == "maximum":
        return maximum_pattern_confidence(
            matched_patterns
        )

    if normalized_strategy == "average":
        return average_pattern_confidence(
            matched_patterns
        )

    if normalized_strategy in {
        "noisy_or",
        "noisy-or",
        "noisy or",
    }:
        return noisy_or_pattern_confidence(
            matched_patterns
        )

    raise ValueError(
        "Unsupported pattern confidence strategy. "
        "Use 'maximum', 'average', or 'noisy_or'."
    )


# ========== ASSOCIATION RESULT ==========
def build_association_result(
    heuristic_result: dict[str, Any],
    confidence_strategy: str = "maximum",
    threshold: float = DEFAULT_PATTERN_THRESHOLD,
) -> dict[str, Any]:
    """
    Build a rule-association result from the atomic indicators
    returned by the weighted heuristic.
    """

    atomic_indicators = heuristic_result.get(
        "atomic_indicators",
        {},
    )

    if not atomic_indicators:
        raise ValueError(
            "The heuristic result does not contain "
            "'atomic_indicators'."
        )

    patterns = load_patterns()

    available_indicators = set(
        atomic_indicators.keys()
    )

    pattern_warnings = {}

    for pattern in patterns:
        missing_indicator_names = validate_pattern(
            pattern,
            available_indicators,
        )

        if missing_indicator_names:
            pattern_id = pattern.get(
                "pattern_id",
                "unknown_pattern",
            )

            pattern_warnings[pattern_id] = (
                missing_indicator_names
            )

    pattern_results = match_patterns(
        atomic_indicators=atomic_indicators,
        patterns=patterns,
    )

    matched_patterns = [
        pattern
        for pattern in pattern_results
        if pattern.get("matched")
    ]

    confidence = calculate_pattern_confidence(
        matched_patterns=matched_patterns,
        strategy=confidence_strategy,
    )

    is_phishing = (
        bool(matched_patterns)
        and confidence >= threshold
    )

    prediction = (
        "phishing"
        if is_phishing
        else "benign"
    )

    actual_label = str(
        heuristic_result.get(
            "actual_label",
            "unknown",
        )
    ).strip().lower()

    if actual_label == "spam":
        expected_prediction = "phishing"
    elif actual_label in {
        "phishing",
        "benign",
    }:
        expected_prediction = actual_label
    else:
        expected_prediction = None

    correct = (
        prediction == expected_prediction
        if expected_prediction is not None
        else None
    )

    strongest_pattern = None

    if matched_patterns:
        strongest_pattern = max(
            matched_patterns,
            key=lambda pattern: pattern.get(
                "confidence",
                0.0,
            ),
        )

    return {
        "method": "rule_association",
        "source_file": heuristic_result.get(
            "source_file",
            "",
        ),
        "email_id": heuristic_result.get(
            "email_id",
            "",
        ),
        "source_dataset": heuristic_result.get(
            "source_dataset",
            "",
        ),
        "high_level_category": heuristic_result.get(
            "high_level_category",
            "",
        ),
        "subcategory": heuristic_result.get(
            "subcategory",
            "",
        ),
        "generation_type": heuristic_result.get(
            "generation_type",
            "",
        ),

        "prediction": prediction,
        "confidence": confidence,
        "is_phishing": is_phishing,
        "threshold": threshold,
        "confidence_strategy":
            confidence_strategy,

        "actual_label": actual_label,
        "correct": correct,

        "matched_pattern_count":
            len(matched_patterns),

        "matched_pattern_ids": [
            pattern.get(
                "pattern_id",
                "",
            )
            for pattern in matched_patterns
        ],

        "matched_pattern_names": [
            pattern.get(
                "pattern_name",
                "",
            )
            for pattern in matched_patterns
        ],

        "strongest_pattern": (
            strongest_pattern.get(
                "pattern_name",
                "",
            )
            if strongest_pattern
            else None
        ),

        "strongest_pattern_id": (
            strongest_pattern.get(
                "pattern_id",
                "",
            )
            if strongest_pattern
            else None
        ),

        "matched_patterns":
            matched_patterns,

        "all_pattern_results":
            pattern_results,

        "atomic_indicators":
            atomic_indicators,

        "active_indicators": [
            indicator_name
            for indicator_name, is_active
            in atomic_indicators.items()
            if is_active
        ],

        "pattern_warnings":
            pattern_warnings,
    }


# ========== PUBLIC FUNCTIONS ==========
def analyze_email_association(
    file_path: str | Path,
    true_label: str | None = None,
    confidence_strategy: str = "maximum",
    threshold: float = DEFAULT_PATTERN_THRESHOLD,
) -> dict[str, Any]:
    """
    Analyze an email file using the rule-association method.
    """

    heuristic_result = analyze_email(
        file_path=file_path,
        true_label=true_label,
    )

    return build_association_result(
        heuristic_result=heuristic_result,
        confidence_strategy=confidence_strategy,
        threshold=threshold,
    )


def analyze_email_dict_association(
    email_data: dict[str, Any],
    true_label: str = "unknown",
    filename: str = "uploaded_email.json",
    confidence_strategy: str = "maximum",
    threshold: float = DEFAULT_PATTERN_THRESHOLD,
) -> dict[str, Any]:
    """
    Analyze an email dictionary using the rule-association method.
    This is intended for Streamlit uploads.
    """

    heuristic_result = analyze_email_dict(
        email_data=email_data,
        true_label=true_label,
        filename=filename,
    )

    return build_association_result(
        heuristic_result=heuristic_result,
        confidence_strategy=confidence_strategy,
        threshold=threshold,
    )


# ========== TEST ==========
if __name__ == "__main__":
    patterns = load_patterns()

    print(
        f"Loaded {len(patterns)} enabled "
        f"association patterns."
    )

    for pattern in patterns:
        print(
            f"- {pattern.get('pattern_name')} "
            f"({pattern.get('pattern_id')})"
        )