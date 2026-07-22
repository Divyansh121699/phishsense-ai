from detection.detection_controller import detect_email_dict

def run_combined_detection(
    email_text: str,
    email_meta: dict,
    mode: str = "full_ensemble",
    true_label: str = "unknown",
    filename: str = "",
    fusion_strategy: str = "weighted",
) -> dict:
    """
    Backward-compatible wrapper around the modular detection controller.

    New code should preferably call detect_email_dict() directly.
    """

    email_data = dict(email_meta or {})

    if email_text:
        if not email_data.get("email_text"):
            email_data["email_text"] = email_text

        if not email_data.get("body_text"):
            email_data["body_text"] = email_text

    resolved_filename = (
        filename
        or str(email_data.get("source_file", "unknown_email"))
    )

    return detect_email_dict(
        email_data=email_data,
        mode=mode,
        true_label=true_label,
        filename=resolved_filename,
        fusion_strategy=fusion_strategy,
    )