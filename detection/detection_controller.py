from pathlib import Path
from typing import Any

try:
    from detection.rule_based import (
        analyze_email,
        analyze_email_dict,
    )
    from detection.rule_association import (
        analyze_email_association,
        analyze_email_dict_association,
    )
    from detection.llm_based import (
        analyze_email_llm,
        analyze_email_dict_llm,
    )
    from detection.fusion import fuse_detector_results
except ImportError:
    from rule_based import (
        analyze_email,
        analyze_email_dict,
    )
    from rule_association import (
        analyze_email_association,
        analyze_email_dict_association,
    )
    from llm_based import (
        analyze_email_llm,
        analyze_email_dict_llm,
    )
    from fusion import fuse_detector_results


# ========== DETECTION MODES ==========

MODE_WEIGHTED_HEURISTIC = "weighted_heuristic"
MODE_RULE_ASSOCIATION = "rule_association"
MODE_LLM = "llm"
MODE_WEIGHTED_LLM = "weighted_heuristic_llm"
MODE_ASSOCIATION_LLM = "rule_association_llm"
MODE_FULL_ENSEMBLE = "full_ensemble"


SUPPORTED_MODES = {
    MODE_WEIGHTED_HEURISTIC,
    MODE_RULE_ASSOCIATION,
    MODE_LLM,
    MODE_WEIGHTED_LLM,
    MODE_ASSOCIATION_LLM,
    MODE_FULL_ENSEMBLE,
}


MODE_ALIASES = {
    "heuristic": MODE_WEIGHTED_HEURISTIC,
    "rule_based": MODE_WEIGHTED_HEURISTIC,
    "weighted": MODE_WEIGHTED_HEURISTIC,

    "association": MODE_RULE_ASSOCIATION,
    "association_rule": MODE_RULE_ASSOCIATION,

    "gpt": MODE_LLM,
    "gpt_5": MODE_LLM,
    "gpt-5": MODE_LLM,

    "heuristic_llm": MODE_WEIGHTED_LLM,
    "weighted_gpt": MODE_WEIGHTED_LLM,
    "weighted_heuristic_gpt": MODE_WEIGHTED_LLM,

    "association_gpt": MODE_ASSOCIATION_LLM,
    "rule_association_gpt": MODE_ASSOCIATION_LLM,

    "ensemble": MODE_FULL_ENSEMBLE,
    "all": MODE_FULL_ENSEMBLE,
    "complete": MODE_FULL_ENSEMBLE,
}


# ========== DEFAULT SETTINGS ==========

DEFAULT_FUSION_STRATEGY = "weighted"
DEFAULT_FUSION_THRESHOLD = 0.50
DEFAULT_ASSOCIATION_THRESHOLD = 0.70
DEFAULT_ASSOCIATION_CONFIDENCE_STRATEGY = "maximum"

DEFAULT_FULL_ENSEMBLE_WEIGHTS = {
    "weighted_heuristic": 0.30,
    "rule_association": 0.30,
    "llm": 0.40,
}

DEFAULT_WEIGHTED_LLM_WEIGHTS = {
    "weighted_heuristic": 0.40,
    "llm": 0.60,
}

DEFAULT_ASSOCIATION_LLM_WEIGHTS = {
    "rule_association": 0.40,
    "llm": 0.60,
}


# ========== MODE NORMALIZATION ==========

def normalize_detection_mode(mode: str) -> str:
    """
    Normalize a detection-mode name.
    """

    normalized_mode = str(mode).strip().lower()

    normalized_mode = normalized_mode.replace(
        "-",
        "_",
    ).replace(
        " ",
        "_",
    )

    normalized_mode = MODE_ALIASES.get(
        normalized_mode,
        normalized_mode,
    )

    if normalized_mode not in SUPPORTED_MODES:
        supported = ", ".join(
            sorted(SUPPORTED_MODES)
        )

        raise ValueError(
            f"Unsupported detection mode: {mode}. "
            f"Supported modes are: {supported}"
        )

    return normalized_mode


def get_mode_detectors(mode: str) -> list[str]:
    """
    Return the detectors required for a detection mode.
    """

    normalized_mode = normalize_detection_mode(mode)

    mode_detectors = {
        MODE_WEIGHTED_HEURISTIC: [
            "weighted_heuristic",
        ],
        MODE_RULE_ASSOCIATION: [
            "rule_association",
        ],
        MODE_LLM: [
            "llm",
        ],
        MODE_WEIGHTED_LLM: [
            "weighted_heuristic",
            "llm",
        ],
        MODE_ASSOCIATION_LLM: [
            "rule_association",
            "llm",
        ],
        MODE_FULL_ENSEMBLE: [
            "weighted_heuristic",
            "rule_association",
            "llm",
        ],
    }

    return mode_detectors[normalized_mode]


# ========== WEIGHT SELECTION ==========

def get_default_weights_for_mode(
    mode: str,
) -> dict[str, float] | None:
    """
    Return default fusion weights for a selected mode.
    """

    normalized_mode = normalize_detection_mode(mode)

    if normalized_mode == MODE_WEIGHTED_LLM:
        return DEFAULT_WEIGHTED_LLM_WEIGHTS.copy()

    if normalized_mode == MODE_ASSOCIATION_LLM:
        return DEFAULT_ASSOCIATION_LLM_WEIGHTS.copy()

    if normalized_mode == MODE_FULL_ENSEMBLE:
        return DEFAULT_FULL_ENSEMBLE_WEIGHTS.copy()

    return None


# ========== RESULT METADATA ==========

def build_controller_result(
    mode: str,
    detector_results: list[dict[str, Any]],
    final_result: dict[str, Any],
    fusion_strategy: str | None = None,
) -> dict[str, Any]:
    """
    Build the final standardized controller output.
    """

    normalized_mode = normalize_detection_mode(mode)

    result = {
        "controller": "detection_controller",
        "detection_mode": normalized_mode,
        "detectors_requested": get_mode_detectors(
            normalized_mode
        ),
        "detector_count": len(detector_results),

        "prediction": final_result.get(
            "prediction",
            "unknown",
        ),
        "confidence": final_result.get(
            "confidence",
            0.0,
        ),
        "is_phishing": final_result.get(
            "is_phishing",
            False,
        ),

        "actual_label": final_result.get(
            "actual_label",
            "unknown",
        ),
        "correct": final_result.get(
            "correct"
        ),

        "final_method": final_result.get(
            "method",
            normalized_mode,
        ),

        "fusion_strategy": fusion_strategy,

        "final_result": final_result,

        "detector_results": {
            result.get(
                "method",
                f"detector_{index + 1}",
            ): result
            for index, result in enumerate(
                detector_results
            )
        },
    }

    for detector_result in detector_results:
        for field in [
            "source_file",
            "email_id",
            "source_dataset",
            "high_level_category",
            "subcategory",
            "generation_type",
        ]:
            value = detector_result.get(field)

            if value not in {
                None,
                "",
            }:
                result[field] = value

    return result


# ========== FILE-BASED DETECTION ==========

def detect_email(
    file_path: str | Path,
    mode: str = MODE_FULL_ENSEMBLE,
    true_label: str | None = None,
    fusion_strategy: str = DEFAULT_FUSION_STRATEGY,
    weights: dict[str, float] | None = None,
    fusion_threshold: float = DEFAULT_FUSION_THRESHOLD,
    association_threshold: float = (
        DEFAULT_ASSOCIATION_THRESHOLD
    ),
    association_confidence_strategy: str = (
        DEFAULT_ASSOCIATION_CONFIDENCE_STRATEGY
    ),
    tie_breaker: str = "highest_confidence",
) -> dict[str, Any]:
    """
    Analyze one email JSON file using the selected detection mode.
    """

    file_path = Path(file_path)
    normalized_mode = normalize_detection_mode(mode)

    if not file_path.exists():
        raise FileNotFoundError(
            f"Email file was not found: {file_path}"
        )

    detector_results = []

    heuristic_result = None
    association_result = None
    llm_result = None

    required_detectors = get_mode_detectors(
        normalized_mode
    )

    if "weighted_heuristic" in required_detectors:
        heuristic_result = analyze_email(
            file_path=file_path,
            true_label=true_label,
        )

        detector_results.append(
            heuristic_result
        )

    if "rule_association" in required_detectors:
        association_result = (
            analyze_email_association(
                file_path=file_path,
                true_label=true_label,
                confidence_strategy=(
                    association_confidence_strategy
                ),
                threshold=association_threshold,
            )
        )

        detector_results.append(
            association_result
        )

    if "llm" in required_detectors:
        llm_result = analyze_email_llm(
            file_path=file_path,
            true_label=true_label,
        )

        detector_results.append(
            llm_result
        )

    # Single-detector modes do not require fusion.
    if len(detector_results) == 1:
        final_result = detector_results[0]

        return build_controller_result(
            mode=normalized_mode,
            detector_results=detector_results,
            final_result=final_result,
            fusion_strategy=None,
        )

    if weights is None:
        weights = get_default_weights_for_mode(
            normalized_mode
        )

    final_result = fuse_detector_results(
        detector_results=detector_results,
        strategy=fusion_strategy,
        weights=weights,
        threshold=fusion_threshold,
        actual_label=true_label,
        tie_breaker=tie_breaker,
    )

    return build_controller_result(
        mode=normalized_mode,
        detector_results=detector_results,
        final_result=final_result,
        fusion_strategy=fusion_strategy,
    )


# ========== DICTIONARY-BASED DETECTION ==========

def detect_email_dict(
    email_data: dict[str, Any],
    mode: str = MODE_FULL_ENSEMBLE,
    true_label: str = "unknown",
    filename: str = "uploaded_email.json",
    fusion_strategy: str = DEFAULT_FUSION_STRATEGY,
    weights: dict[str, float] | None = None,
    fusion_threshold: float = DEFAULT_FUSION_THRESHOLD,
    association_threshold: float = (
        DEFAULT_ASSOCIATION_THRESHOLD
    ),
    association_confidence_strategy: str = (
        DEFAULT_ASSOCIATION_CONFIDENCE_STRATEGY
    ),
    tie_breaker: str = "highest_confidence",
) -> dict[str, Any]:
    """
    Analyze an email dictionary using the selected detection mode.

    This function is intended for Streamlit uploads.
    """

    if not isinstance(email_data, dict):
        raise TypeError(
            "email_data must be a dictionary."
        )

    normalized_mode = normalize_detection_mode(mode)

    detector_results = []

    required_detectors = get_mode_detectors(
        normalized_mode
    )

    if "weighted_heuristic" in required_detectors:
        heuristic_result = analyze_email_dict(
            email_data=email_data,
            true_label=true_label,
            filename=filename,
        )

        detector_results.append(
            heuristic_result
        )

    if "rule_association" in required_detectors:
        association_result = (
            analyze_email_dict_association(
                email_data=email_data,
                true_label=true_label,
                filename=filename,
                confidence_strategy=(
                    association_confidence_strategy
                ),
                threshold=association_threshold,
            )
        )

        detector_results.append(
            association_result
        )

    if "llm" in required_detectors:
        llm_result = analyze_email_dict_llm(
            email_data=email_data,
            true_label=true_label,
            filename=filename,
        )

        detector_results.append(
            llm_result
        )

    # Single-detector modes do not require fusion.
    if len(detector_results) == 1:
        final_result = detector_results[0]

        return build_controller_result(
            mode=normalized_mode,
            detector_results=detector_results,
            final_result=final_result,
            fusion_strategy=None,
        )

    if weights is None:
        weights = get_default_weights_for_mode(
            normalized_mode
        )

    final_result = fuse_detector_results(
        detector_results=detector_results,
        strategy=fusion_strategy,
        weights=weights,
        threshold=fusion_threshold,
        actual_label=true_label,
        tie_breaker=tie_breaker,
    )

    return build_controller_result(
        mode=normalized_mode,
        detector_results=detector_results,
        final_result=final_result,
        fusion_strategy=fusion_strategy,
    )


# ========== CONVENIENCE FUNCTIONS ==========

def detect_with_heuristic(
    file_path: str | Path,
    true_label: str | None = None,
) -> dict[str, Any]:
    """
    Run weighted heuristic detection only.
    """

    return detect_email(
        file_path=file_path,
        mode=MODE_WEIGHTED_HEURISTIC,
        true_label=true_label,
    )


def detect_with_association(
    file_path: str | Path,
    true_label: str | None = None,
) -> dict[str, Any]:
    """
    Run rule-association detection only.
    """

    return detect_email(
        file_path=file_path,
        mode=MODE_RULE_ASSOCIATION,
        true_label=true_label,
    )


def detect_with_llm(
    file_path: str | Path,
    true_label: str | None = None,
) -> dict[str, Any]:
    """
    Run LLM detection only.
    """

    return detect_email(
        file_path=file_path,
        mode=MODE_LLM,
        true_label=true_label,
    )


def detect_with_full_ensemble(
    file_path: str | Path,
    true_label: str | None = None,
    fusion_strategy: str = DEFAULT_FUSION_STRATEGY,
) -> dict[str, Any]:
    """
    Run the full three-detector ensemble.
    """

    return detect_email(
        file_path=file_path,
        mode=MODE_FULL_ENSEMBLE,
        true_label=true_label,
        fusion_strategy=fusion_strategy,
    )


# ========== MODE INFORMATION ==========

def get_supported_modes() -> dict[str, list[str]]:
    """
    Return all supported detection modes and their detectors.
    """

    return {
        mode: get_mode_detectors(mode)
        for mode in sorted(SUPPORTED_MODES)
    }


# ========== TEST ==========

if __name__ == "__main__":
    print("Supported detection modes:\n")

    for supported_mode, detectors in (
        get_supported_modes().items()
    ):
        detector_list = ", ".join(detectors)

        print(
            f"- {supported_mode}: "
            f"{detector_list}"
        )