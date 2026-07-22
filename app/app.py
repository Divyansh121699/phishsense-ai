import json
import time
from pathlib import Path
import pandas as pd
import streamlit as st
import sys
from pathlib import Path

# Add the project root directory to Python's import path.
PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st
from detection.detection_controller import detect_email_dict
from detection.llm_based import (
    reset_token_counter,
    get_total_tokens_used,
)


st.set_page_config(page_title="PhishSense AI", layout="wide")
st.markdown("""
<style>
/* Main background */
.stApp {
    background:
        linear-gradient(rgba(5, 12, 28, 0.82), rgba(5, 12, 28, 0.85)),
        url("https://images.unsplash.com/photo-1563986768609-322da13575f3");
    background-size: cover;
    background-position: center;
    background-attachment: fixed;
}

/* Main content container */
.block-container {
    background: rgba(255, 255, 255, 0.88);
    padding: 2.5rem;
    border-radius: 18px;
    margin-top: 1rem;
    margin-bottom: 2rem;
    box-shadow: 0 10px 35px rgba(0, 0, 0, 0.35);
}

/* Text readability */
h1 {
    color: #0f172a !important;
    font-weight: 800 !important;
}

h2, h3, h4, h5, h6 {
    color: #0f172a !important;
    font-weight: 700 !important;
}

p, label {
    color: #111827;
}

/* Captions */
[data-testid="stCaptionContainer"] {
    color: #334155 !important;
}

/* ======================================================
   CYBERSECURITY TABS
   ====================================================== */

.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
    border-bottom: none !important;
}

/* Normal tabs */

.stTabs [data-baseweb="tab"] {
    background: #0f172a !important;
    color: #ffffff !important;
    border: 1px solid #334155 !important;
    border-radius: 10px 10px 0 0;
    padding: 10px 18px;
    font-weight: 600;
}

/* Hover */

.stTabs [data-baseweb="tab"]:hover {
    background: #1e293b !important;
    color: #ffffff !important;
}

/* Active tab */

.stTabs [aria-selected="true"] {
    background: #2563eb !important;
    color: #ffffff !important;
    border-bottom: 3px solid #60a5fa !important;
}

/* Force tab text white */

.stTabs [data-baseweb="tab"] *,
.stTabs [aria-selected="true"] * {
    color: #ffffff !important;
}

/* Buttons */
.stButton > button {
    background: #0f172a;
    color: white;
    border-radius: 10px;
    border: none;
    padding: 0.55rem 1rem;
    font-weight: 700;
}

.stButton > button:hover {
    background: #1d4ed8;
    color: white;
}

/* Download buttons */
.stDownloadButton > button {
    background: #1d4ed8;
    color: white;
    border-radius: 10px;
    border: none;
    font-weight: 700;
}

.stDownloadButton > button:hover {
    background: #0f172a;
    color: white;
}

/* Upload area */
[data-testid="stFileUploader"] {
    background: #f8fafc;
    border: 1px solid #cbd5e1;
    border-radius: 14px;
    padding: 1rem;
}

/* Text area */
textarea {
    background-color: #ffffff !important;
    color: #111827 !important;
    border-radius: 10px !important;
    border: 1px solid #cbd5e1 !important;
}

/* Dataframes */
[data-testid="stDataFrame"] {
    background: white;
    border-radius: 12px;
    border: 1px solid #cbd5e1;
}

/* Metrics */
[data-testid="stMetric"] {
    background: #f8fafc;
    border: 1px solid #cbd5e1;
    padding: 1rem;
    border-radius: 14px;
    box-shadow: 0 3px 12px rgba(15, 23, 42, 0.08);
}

[data-testid="stMetricLabel"] {
    color: #334155 !important;
    font-weight: 700;
}

[data-testid="stMetricValue"] {
    color: #0f172a !important;
    font-weight: 800;
}

/* Info/warning/success boxes */
[data-testid="stAlert"] {
    border-radius: 12px;
}

/* Expander */
.streamlit-expanderHeader {
    font-weight: 700;
    color: #0f172a !important;
}

/* Code/json blocks */
pre, code {
    color: #e5e7eb !important;
    background: #0f172a !important;
    border-radius: 10px !important;
}

/* Tables */
table {
    background: white;
    color: #111827;
}

thead tr th {
    background: #e2e8f0 !important;
    color: #0f172a !important;
}

tbody tr td {
    color: #111827 !important;
}

/* Hide Streamlit default footer */
footer {
    visibility: hidden;
}
            
/* Fix invisible button text */
.stButton > button,
.stButton > button * {
    color: #ffffff !important;
}

.stDownloadButton > button,
.stDownloadButton > button * {
    color: #ffffff !important;
}

/* Fix file uploader upload button */
[data-testid="stFileUploader"] button,
[data-testid="stFileUploader"] button * {
    color: #ffffff !important;
    background-color: #0f172a !important;
}
            
/* ===== File Uploader Text Fix ===== */

/* Drag & Drop text */
[data-testid="stFileUploaderDropzone"] span,
[data-testid="stFileUploaderDropzone"] small,
[data-testid="stFileUploaderDropzone"] p,
[data-testid="stFileUploaderDropzone"] div {
    color: #ffffff !important;
}

/* "Limit 200MB..." text */
[data-testid="stFileUploader"] {
    color: #ffffff !important;
}

/* Uploaded filename */
[data-testid="stFileUploader"] label,
[data-testid="stFileUploader"] span {
    color: #111827 !important;
}

/* Force uploader instructions to white */
section[data-testid="stFileUploaderDropzone"] * {
    color: white !important;
}

/* =======================================================
   CYBER THEME FIXES
   Keep dark background, make text readable
   ======================================================= */

/* ---------- Select boxes ---------- */

[data-baseweb="select"] * {
    color: #ffffff !important;
}

[data-baseweb="select"] svg {
    fill: #ffffff !important;
}

/* Dropdown menu */

[role="listbox"] {
    background: #0f172a !important;
}

[role="option"] {
    background: #0f172a !important;
    color: #ffffff !important;
}

[role="option"]:hover {
    background: #1e293b !important;
}

/* ---------- Code blocks ---------- */

pre,
code,
[data-testid="stCodeBlock"] {
    color: #ffffff !important;
}

/* ---------- JSON ---------- */

[data-testid="stJson"] * {
    color: #ffffff !important;
}

/* ---------- Architecture Formula ---------- */

pre code {
    color: #ffffff !important;
}

/* ---------- Schema text ---------- */

.stCodeBlock span {
    color: #ffffff !important;
}        

/* ======================================================
   DARK TABLES (System Architecture / DataFrames)
   ====================================================== */

/* Entire dataframe/table */
[data-testid="stTable"] table,
[data-testid="stDataFrame"] table {
    background-color: #0f172a !important;
    color: #ffffff !important;
    border: 1px solid #334155 !important;
}

/* Header */
[data-testid="stTable"] thead tr th,
[data-testid="stDataFrame"] thead tr th {
    background-color: #1e293b !important;
    color: #ffffff !important;
    border: 1px solid #334155 !important;
    font-weight: 700 !important;
}

/* Rows */
[data-testid="stTable"] tbody tr td,
[data-testid="stDataFrame"] tbody tr td {
    background-color: #0f172a !important;
    color: #ffffff !important;
    border: 1px solid #334155 !important;
}

/* Alternate row color */
[data-testid="stTable"] tbody tr:nth-child(even) td,
[data-testid="stDataFrame"] tbody tr:nth-child(even) td {
    background-color: #172033 !important;
}

/* Hover */
[data-testid="stTable"] tbody tr:hover td,
[data-testid="stDataFrame"] tbody tr:hover td {
    background-color: #243447 !important;
}

/* Make dataframe text white */
[data-testid="stDataFrame"] * {
    color: #ffffff !important;
}
</style>
""", unsafe_allow_html=True)
st.title("🛡️ PhishSense AI")
st.subheader(
    "Modular Heuristic, Association-Rule, and LLM "
    "Email Phishing Detection System"
)

st.caption(
    "Research prototype supporting weighted heuristic detection, "
    "association-rule detection, LLM semantic reasoning, configurable "
    "fusion strategies, and explainable phishing classification."
)

SCHEMA_COLUMNS = [
    "email_id", "source_dataset", "source_file", "high_level_category", "subcategory",
    "sender", "receiver", "subject", "date", "body_text", "body_html", "urls",
    "url_count", "has_url", "has_attachment", "attachment_count", "has_image",
    "image_count", "received_headers", "authentication_results", "generation_type",
    "is_html", "is_plain_text"
]

IMPORTANT_COLUMNS = [
    "sender", "subject", "body_text", "body_html", "urls", "url_count", "has_url",
    "has_attachment", "attachment_count", "has_image", "image_count",
    "authentication_results", "received_headers", "is_html", "is_plain_text",
    "generation_type", "high_level_category", "subcategory", "source_dataset"
]

ARCHITECTURE_MODULES = [
    {
        "layer": "1. Incoming Emails",
        "implementation": (
            "CSV, JSON, Excel, or pasted raw-text input"
        ),
    },
    {
        "layer": "2. Dataset Normalization",
        "implementation": (
            "schema_utils.normalize_email_record() standardizes "
            "the email schema"
        ),
    },
    {
        "layer": "3. Atomic Indicator Extraction",
        "implementation": (
            "Sender, URL, authentication, attachment, urgency, "
            "credential, payment, and social-engineering indicators"
        ),
    },
    {
        "layer": "4A. Weighted Heuristic",
        "implementation": (
            "Weighted rule scoring and category-level evidence"
        ),
    },
    {
        "layer": "4B. Rule Association",
        "implementation": (
            "Matches combinations of atomic indicators against "
            "association_patterns.json"
        ),
    },
    {
        "layer": "4C. LLM Semantic Reasoning",
        "implementation": (
            "GPT classification, confidence, intent, sender trust, "
            "URL risk, and explanation"
        ),
    },
    {
        "layer": "5. Detection Controller",
        "implementation": (
            "Selects one detector or a configurable detector ensemble"
        ),
    },
    {
        "layer": "6. Decision Fusion",
        "implementation": (
            "Weighted probability fusion or majority voting"
        ),
    },
    {
        "layer": "7. Explainability and Evaluation",
        "implementation": (
            "Detector outputs, matched patterns, indicators, "
            "confidence, actual label, and correctness"
        ),
    },
]

# ======================================================
# OUTPUT DIRECTORY
# ======================================================

OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

DETECTION_MODE_OPTIONS = {
    "Weighted Heuristic": "weighted_heuristic",
    "Rule Association": "rule_association",
    "GPT": "llm",
    "Weighted Heuristic + GPT": "weighted_heuristic_llm",
    "Rule Association + GPT": "rule_association_llm",
    "Full Ensemble": "full_ensemble",
}

FUSION_OPTIONS = {
    "Weighted Fusion": "weighted",
    "Majority Vote": "majority_vote",
}

LLM_MODES = {
    "llm",
    "weighted_heuristic_llm",
    "rule_association_llm",
    "full_ensemble",
}


def load_uploaded_records(uploaded_file):
    """
    Supports:
    - JSON
    - CSV (UTF-8, UTF-8 BOM, Windows, Latin1, ISO-8859-1)
    - Excel (.xlsx/.xls)

    Automatically handles encoding issues and malformed rows.
    """

    file_name = uploaded_file.name.lower()

    try:

        # ---------------- JSON ----------------
        if file_name.endswith(".json"):
            uploaded_file.seek(0)

            payload = json.load(uploaded_file)

            if isinstance(payload, list):
                return payload

            return [payload]

        # ---------------- CSV ----------------
        elif file_name.endswith(".csv"):

            encodings = [
                "utf-8",
                "utf-8-sig",
                "cp1252",
                "latin1",
                "iso-8859-1"
            ]

            for enc in encodings:

                try:
                    uploaded_file.seek(0)

                    df = pd.read_csv(
                        uploaded_file,
                        encoding=enc
                    )

                    return df.fillna("").to_dict(orient="records")

                except UnicodeDecodeError:
                    continue

                except pd.errors.ParserError:

                    try:

                        uploaded_file.seek(0)

                        df = pd.read_csv(
                            uploaded_file,
                            encoding=enc,
                            engine="python",
                            on_bad_lines="skip"
                        )

                        st.warning(
                            "Some malformed CSV rows were skipped."
                        )

                        return df.fillna("").to_dict(orient="records")

                    except Exception:
                        continue

            st.error(
                "Unable to read CSV. Unsupported encoding or corrupted file."
            )

            return []

        # ---------------- Excel ----------------
        elif file_name.endswith((".xlsx", ".xls")):

            uploaded_file.seek(0)

            df = pd.read_excel(uploaded_file)

            return df.fillna("").to_dict(orient="records")

        # ---------------- Unsupported ----------------
        else:

            st.error(
                "Unsupported file type. Please upload CSV, Excel, or JSON."
            )

            return []

    except Exception as e:

        st.error(f"Error reading uploaded file: {e}")

        return []

def normalize_true_label(value):

    """
    Normalize dataset labels for binary evaluation.

    Spam is treated as phishing.
    """

    normalized = str(value or "").strip().lower()

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


def get_record_true_label(record):
    """
    Retrieve ground truth without passing dataset metadata to the LLM.
    """

    candidate_fields = [
        "actual_label",
        "true_label",
        "label",
        "high_level_category",
        "category",
    ]

    for field in candidate_fields:
        normalized = normalize_true_label(
            record.get(field)
        )

        if normalized != "unknown":
            return normalized

    return "unknown"

def prepare_record_for_detection(
    record: dict,
    fallback_id: str,
) -> tuple[dict, str]:
    """
    Prepare an uploaded CSV/JSON row for dictionary-based detection.

    The original source_file may refer to a temporary path that no longer
    exists. Preserve it as metadata, but do not allow the detector to treat
    it as a local file that must be opened.
    """

    prepared_record = {}

    for key, value in dict(record or {}).items():
        try:
            is_missing = pd.isna(value)
        except (TypeError, ValueError):
            is_missing = False

        prepared_record[key] = "" if is_missing else value

    original_source_file = str(
        prepared_record.get("source_file", "") or ""
    )

    record_id = str(
        prepared_record.get("email_id")
        or fallback_id
    )

    # Preserve the original dataset path for research metadata.
    prepared_record["original_source_file"] = (
        original_source_file
    )

    # Use a safe identifier instead of a nonexistent local path.
    prepared_record["source_file"] = record_id

    return prepared_record, record_id

def indicator_dataframe(indicators):
    columns = [
        "category",
        "rule",
        "weight",
        "strength",
        "evidence",
    ]

    if not indicators:
        return pd.DataFrame(columns=columns)

    rows = []

    for item in indicators:
        rows.append(
            {
                "category": item.get("category", ""),
                "rule": item.get(
                    "rule",
                    item.get("indicator", ""),
                ),
                "weight": item.get("weight", 0),
                "strength": item.get("strength", ""),
                "evidence": item.get("evidence", ""),
            }
        )

    dataframe = pd.DataFrame(rows)

    if "weight" in dataframe.columns:
        dataframe = dataframe.sort_values(
            by="weight",
            ascending=False,
        )

    return dataframe


def show_results(results):
    final_result = results.get(
        "final_result",
        results,
    )

    prediction = str(
        results.get("prediction", "unknown")
    ).lower()

    confidence = float(
        results.get("confidence", 0.0) or 0.0
    )

    actual_label = results.get(
        "actual_label",
        "unknown",
    )

    correct = results.get("correct")
    mode = results.get("detection_mode", "")
    final_method = results.get("final_method", "")

    if prediction == "phishing":
        prediction_display = "🔴 PHISHING"
        risk_display = "🔴 HIGH"
    elif prediction == "benign":
        prediction_display = "🟢 BENIGN"

        if confidence >= 0.75:
            risk_display = "🟢 LOW"
        else:
            risk_display = "🟡 REVIEW"
    else:
        prediction_display = "🟡 UNKNOWN"
        risk_display = "🟡 REVIEW"

    if correct is True:
        correctness_display = "✅ CORRECT"
    elif correct is False:
        correctness_display = "❌ INCORRECT"
    else:
        correctness_display = "Not evaluated"

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric(
        "Final Decision",
        prediction_display,
    )
    col2.metric(
        "Confidence",
        f"{confidence * 100:.1f}%",
    )
    col3.metric(
        "Risk",
        risk_display,
    )
    col4.metric(
        "Detection Mode",
        mode.replace("_", " ").title(),
    )
    col5.metric(
        "Evaluation",
        correctness_display,
    )

    if actual_label != "unknown":
        st.caption(
            f"Actual label: {actual_label.upper()} | "
            f"Final method: {final_method}"
        )
    else:
        st.caption(
            f"Final method: {final_method}"
        )

    if "phishing_score" in final_result:
        st.markdown("#### ⚖️ Fusion Result")

        fusion_columns = st.columns(3)

        fusion_columns[0].metric(
            "Phishing Probability",
            (
                f"{float(final_result['phishing_score']) * 100:.1f}%"
            ),
        )

        fusion_columns[1].metric(
            "Fusion Threshold",
            (
                f"{float(final_result.get('threshold', 0.5)) * 100:.1f}%"
            ),
        )

        fusion_columns[2].metric(
            "Detectors Used",
            final_result.get(
                "detector_count",
                len(results.get("detector_results", {})),
            ),
        )

        with st.expander("Fusion Components"):
            components = final_result.get(
                "weighted_components",
                [],
            )

            if components:
                st.dataframe(
                    pd.DataFrame(components),
                    use_container_width=True,
                )
            else:
                st.json(
                    final_result.get("votes", {})
                )

    detector_results = results.get(
        "detector_results",
        {},
    )

    heuristic_result = detector_results.get(
        "weighted_heuristic"
    )

    if heuristic_result:
        st.markdown("#### 🔍 Weighted Heuristic")

        heuristic_columns = st.columns(3)

        heuristic_columns[0].metric(
            "Prediction",
            heuristic_result.get(
                "prediction",
                "unknown",
            ).upper(),
        )

        heuristic_columns[1].metric(
            "Confidence",
            (
                f"{float(heuristic_result.get('confidence', 0)) * 100:.1f}%"
            ),
        )

        heuristic_columns[2].metric(
            "Rule Score",
            heuristic_result.get("score", 0),
        )

        indicators = heuristic_result.get(
            "indicators",
            heuristic_result.get(
                "triggered_indicators",
                [],
            ),
        )

        st.dataframe(
            indicator_dataframe(indicators),
            use_container_width=True,
        )

        with st.expander("Atomic Indicators"):
            st.json(
                heuristic_result.get(
                    "atomic_indicators",
                    {},
                )
            )

        with st.expander("Heuristic Category Scores"):
            st.json(
                heuristic_result.get(
                    "category_scores",
                    {},
                )
            )

    association_result = detector_results.get(
        "rule_association"
    )

    if association_result:
        st.markdown("#### 🧩 Rule Association Analysis")

        association_columns = st.columns(3)

        association_columns[0].metric(
            "Prediction",
            association_result.get(
                "prediction",
                "unknown",
            ).upper(),
        )

        association_columns[1].metric(
            "Confidence",
            (
                f"{float(association_result.get('confidence', 0)) * 100:.1f}%"
            ),
        )

        association_columns[2].metric(
            "Matched Patterns",
            association_result.get(
                "matched_pattern_count",
                0,
            ),
        )

        matched_patterns = association_result.get(
            "matched_patterns",
            [],
        )

        if matched_patterns:
            st.dataframe(
                pd.DataFrame(matched_patterns),
                use_container_width=True,
            )
        else:
            st.info(
                "No enabled association pattern matched this email."
            )

        strongest_pattern = association_result.get(
            "strongest_pattern"
        )

        if strongest_pattern:
            with st.expander("Strongest Association Pattern"):
                st.json(strongest_pattern)

    llm_result = detector_results.get("llm")

    if llm_result:
        st.markdown("#### 💬 LLM Semantic Reasoning")

        llm_columns = st.columns(4)

        llm_columns[0].metric(
            "Prediction",
            llm_result.get(
                "prediction",
                llm_result.get("label", "unknown"),
            ).upper(),
        )

        llm_columns[1].metric(
            "Confidence",
            (
                f"{float(llm_result.get('confidence', 0)) * 100:.1f}%"
            ),
        )

        llm_columns[2].metric(
            "Sender Trust",
            llm_result.get(
                "sender_trust",
                "unknown",
            ),
        )

        llm_columns[3].metric(
            "URL Risk",
            llm_result.get(
                "url_risk",
                "unknown",
            ),
        )

        st.write(
            llm_result.get(
                "explanation",
                "No explanation returned.",
            )
        )

        with st.expander("Complete LLM Result"):
            st.json(llm_result)

    normalized_email = None

    for detector_result in detector_results.values():
        normalized_email = detector_result.get(
            "normalized_email"
        )

        if normalized_email:
            break

    if normalized_email:
        with st.expander("📄 Normalized Email Record"):
            st.json(normalized_email)

    with st.expander("Complete Controller Result"):
        st.json(results)


def build_output_row(results):
    detector_results = results.get(
        "detector_results",
        {},
    )

    final_result = results.get(
        "final_result",
        {},
    )

    heuristic = detector_results.get(
        "weighted_heuristic",
        {},
    )

    association = detector_results.get(
        "rule_association",
        {},
    )

    llm = detector_results.get(
        "llm",
        {},
    )

    return {
        "email_id": results.get("email_id", ""),
        "source_dataset": results.get(
            "source_dataset",
            "",
        ),
        "source_file": results.get(
            "source_file",
            "",
        ),
        "high_level_category": results.get(
            "high_level_category",
            "",
        ),
        "subcategory": results.get(
            "subcategory",
            "",
        ),

        "detection_mode": results.get(
            "detection_mode",
            "",
        ),
        "final_method": results.get(
            "final_method",
            "",
        ),
        "fusion_strategy": results.get(
            "fusion_strategy",
            "",
        ),

        "prediction": results.get(
            "prediction",
            "unknown",
        ),
        "confidence": results.get(
            "confidence",
            0.0,
        ),
        "actual_label": results.get(
            "actual_label",
            "unknown",
        ),
        "correct": results.get("correct"),

        "phishing_score": final_result.get(
            "phishing_score",
            results.get("phishing_score", ""),
        ),
        "fusion_threshold": final_result.get(
            "threshold",
            final_result.get("fusion_threshold", ""),
        ),

        "heuristic_prediction": heuristic.get(
            "prediction",
            "",
        ),
        "heuristic_confidence": heuristic.get(
            "confidence",
            "",
        ),
        "heuristic_score": heuristic.get(
            "score",
            "",
        ),

        "association_prediction": association.get(
            "prediction",
            "",
        ),
        "association_confidence": association.get(
            "confidence",
            "",
        ),
        "matched_pattern_count": association.get(
            "matched_pattern_count",
            "",
        ),
        "strongest_pattern": (
            association.get(
                "strongest_pattern",
                {},
            ).get("pattern_name", "")
            if isinstance(
                association.get("strongest_pattern"),
                dict,
            )
            else association.get(
                "strongest_pattern",
                "",
            )
        ),

        "llm_prediction": llm.get(
            "prediction",
            llm.get("label", ""),
        ),
        "llm_confidence": llm.get(
            "confidence",
            "",
        ),
        "llm_intent": llm.get(
            "intent",
            "",
        ),
        "llm_sender_trust": llm.get(
            "sender_trust",
            "",
        ),
        "llm_url_risk": llm.get(
            "url_risk",
            "",
        ),
        "llm_social_engineering_risk": llm.get(
            "social_engineering_risk",
            "",
        ),
        "llm_explanation": llm.get(
            "explanation",
            "",
        ),
    }

def build_detailed_indicator_rows(results):

    """
    Build one detailed CSV row from the controller output.
    """

    detector_results = results.get(
        "detector_results",
        {},
    )

    heuristic = detector_results.get(
        "weighted_heuristic",
        {},
    )

    association = detector_results.get(
        "rule_association",
        {},
    )

    llm = detector_results.get(
        "llm",
        {},
    )

    indicators = heuristic.get(
        "indicators",
        heuristic.get(
            "triggered_indicators",
            [],
        ),
    ) or []

    atomic_indicators = heuristic.get(
        "atomic_indicators",
        {},
    )

    matched_patterns = association.get(
        "matched_patterns",
        [],
    ) or []

    indicator_categories = [
        str(item.get("category", ""))
        for item in indicators
    ]

    indicator_rules = [
        str(
            item.get(
                "rule",
                item.get("indicator", ""),
            )
        )
        for item in indicators
    ]

    indicator_weights = [
        str(item.get("weight", 0))
        for item in indicators
    ]

    indicator_strengths = [
        str(item.get("strength", ""))
        for item in indicators
    ]

    indicator_evidence = [
        str(item.get("evidence", ""))
        for item in indicators
    ]

    pattern_names = []

    for pattern in matched_patterns:
        if isinstance(pattern, dict):
            pattern_names.append(
                str(
                    pattern.get(
                        "pattern_name",
                        pattern.get(
                            "name",
                            pattern.get("id", ""),
                        ),
                    )
                )
            )
        else:
            pattern_names.append(str(pattern))

    heuristic_prediction = heuristic.get(
        "prediction",
        "",
    )

    association_prediction = association.get(
        "prediction",
        "",
    )

    llm_prediction = llm.get(
        "prediction",
        llm.get("label", ""),
    )

    final_prediction = results.get(
        "prediction",
        "unknown",
    )

    actual_label = results.get(
        "actual_label",
        "unknown",
    )

    detector_predictions = [
        prediction
        for prediction in [
            heuristic_prediction,
            association_prediction,
            llm_prediction,
        ]
        if prediction
    ]

    if len(detector_predictions) == 1:
        agreement_status = "Single Detector"

    elif len(detector_predictions) > 1:
        unique_predictions = set(
            detector_predictions
        )

        agreement_status = (
            "All Detectors Agree"
            if len(unique_predictions) == 1
            else "Detector Disagreement"
        )

    else:
        agreement_status = "No Detector Result"

    final_result = results.get(
    "final_result",
    {},
    )

    strongest_pattern = association.get(
        "strongest_pattern"
    )

    if isinstance(strongest_pattern, dict):
        strongest_pattern_name = strongest_pattern.get(
            "pattern_name",
            strongest_pattern.get("name", ""),
        )
    else:
        strongest_pattern_name = (
            strongest_pattern or ""
        )

    return [
        {
            "email_id": results.get(
                "email_id",
                "",
            ),
            "source_dataset": results.get(
                "source_dataset",
                "",
            ),
            "source_file": results.get(
                "source_file",
                "",
            ),
            "high_level_category": results.get(
                "high_level_category",
                "",
            ),
            "subcategory": results.get(
                "subcategory",
                "",
            ),

            "detection_mode": results.get(
                "detection_mode",
                "",
            ),
            "fusion_strategy": results.get(
                "fusion_strategy",
                "",
            ),
            "final_method": results.get(
                "final_method",
                "",
            ),

            "final_prediction": final_prediction,
            "final_confidence": results.get(
                "confidence",
                0.0,
            ),
            "actual_label": actual_label,
            "final_correct": results.get(
                "correct"
            ),

            "phishing_score": final_result.get(
                "phishing_score",
                "",
            ),
            "fusion_threshold": final_result.get(
                "threshold",
                "",
            ),

            "heuristic_prediction": (
                heuristic_prediction
            ),
            "heuristic_confidence": heuristic.get(
                "confidence",
                "",
            ),
            "heuristic_score": heuristic.get(
                "score",
                "",
            ),
            "heuristic_correct": heuristic.get(
                "correct"
            ),

            "association_prediction": (
                association_prediction
            ),
            "association_confidence": (
                association.get(
                    "confidence",
                    "",
                )
            ),
            "association_correct": association.get(
                "correct"
            ),
            "matched_pattern_count": (
                association.get(
                    "matched_pattern_count",
                    0,
                )
            ),
            "strongest_pattern": (
                strongest_pattern_name
            ),
            "matched_patterns": " | ".join(
                pattern_names
            ),

            "llm_prediction": llm_prediction,
            "llm_confidence": llm.get(
                "confidence",
                "",
            ),
            "llm_correct": llm.get(
                "correct"
            ),
            "llm_intent": llm.get(
                "intent",
                "",
            ),
            "llm_sender_trust": llm.get(
                "sender_trust",
                "",
            ),
            "llm_url_risk": llm.get(
                "url_risk",
                "",
            ),
            "llm_social_engineering_risk": (
                llm.get(
                    "social_engineering_risk",
                    "",
                )
            ),
            "llm_explanation": llm.get(
                "explanation",
                "",
            ),

            "agreement_status": agreement_status,

            "active_atomic_indicators": (
                " | ".join(
                    key
                    for key, value
                    in atomic_indicators.items()
                    if value
                )
                if isinstance(atomic_indicators, dict)
                else " | ".join(
                    str(item)
                    for item in atomic_indicators
                )
                if isinstance(atomic_indicators, list)
                else ""
            ),

            "indicator_categories": " | ".join(
                indicator_categories
            ),
            "indicator_rules": " | ".join(
                indicator_rules
            ),
            "indicator_weights": " | ".join(
                indicator_weights
            ),
            "indicator_strengths": " | ".join(
                indicator_strengths
            ),
            "indicator_evidence": " | ".join(
                indicator_evidence
            ),
        }
    ]

tab1, tab2, tab3, tab4 = st.tabs([
    "📨 Email Generator",
    "🛡️ Detection Engine",
    "📚 Dataset Schema",
    "🏗️ System Architecture",
])

with tab1:
    st.subheader("Generate Sample Email")
    type_choice = st.selectbox("Select Email Type", ["Phishing", "Benign"])
    theme = st.selectbox("Choose a Theme", ["Bank", "Job Offer", "Invoice", "CEO Scam", "Microsoft", "Other"])

    sample_texts = {
        "Phishing": {
            "Bank": "Dear Customer, please verify your account now to avoid suspension. Click here: http://fakebank.com",
            "Job Offer": "Urgent! You're selected for a remote job at Google. Verify your identity here: http://scamjob.link",
            "Invoice": "Your invoice is overdue. Pay now to avoid penalties: http://payfraud.com",
            "CEO Scam": "I'm the CEO. Wire $5,000 now for confidential acquisition.",
            "Microsoft": "Security alert: Login attempt detected. Reset password: http://microsoft-login.xyz",
            "Other": "Urgent action required. Confirm your password immediately: http://security-check.xyz",
        },
        "Benign": {
            "Bank": "Your statement is ready. Visit your bank's official app to view it.",
            "Job Offer": "Thanks for applying. We’ll get back to you after reviewing your resume.",
            "Invoice": "Please find attached invoice for your recent order. Pay by next week.",
            "CEO Scam": "Weekly update from the CEO on our Q2 results. No actions needed.",
            "Microsoft": "Your Office 365 subscription has been renewed successfully.",
            "Other": "Thank you for attending today's project meeting. Notes are attached.",
        },
    }

    email_text = sample_texts[type_choice][theme]
    st.text_area("Generated Email", value=email_text, height=250)

with tab2:
    st.subheader("Paste or Upload Email for Detection")
    st.info("Upload a single JSON file, a JSON list, or a CSV using your expanded schema. You can also paste raw email text.")

    uploaded_file = st.file_uploader(
    "Upload Email Dataset",
    type=["json", "csv", "xlsx", "xls"]
)
    text_input = st.text_area("Or paste raw email text here")

    st.markdown("#### Detection Configuration")

    configuration_columns = st.columns(2)

    with configuration_columns[0]:
        selected_mode_label = st.selectbox(
            "Detection Mode",
            options=list(
                DETECTION_MODE_OPTIONS.keys()
            ),
            index=5,
            help=(
                "Choose one detector or a combined "
                "detector configuration."
            ),
        )

    selected_mode = DETECTION_MODE_OPTIONS[
        selected_mode_label
    ]

    combined_mode = selected_mode in {
        "weighted_heuristic_llm",
        "rule_association_llm",
        "full_ensemble",
    }

    with configuration_columns[1]:
        selected_fusion_label = st.selectbox(
            "Fusion Strategy",
            options=list(
                FUSION_OPTIONS.keys()
            ),
            index=0,
            disabled=not combined_mode,
            help=(
                "Fusion applies only when two or more "
                "detectors are selected."
            ),
        )

    selected_fusion_strategy = FUSION_OPTIONS[
        selected_fusion_label
    ]

    if selected_mode in LLM_MODES:
        st.warning(
            "This detection mode uses the OpenAI API "
            "and will consume tokens."
        )
    else:
        st.info(
            "This detection mode does not call the "
            "OpenAI API."
        )

    resume_previous = st.checkbox(
    "Resume previous interrupted analysis",
    value=True
)

    records = []
    max_records = 1

    checkpoint = None

    checkpoint_file = Path("output/checkpoint.json")

    if checkpoint_file.exists():
        with open(checkpoint_file, "r") as f:
            checkpoint = json.load(f)

    if uploaded_file:
        records = load_uploaded_records(uploaded_file)
        if records:
            st.success(f"Loaded {len(records)} record(s).")
            if len(records) > 1:
                st.markdown("#### Number of Records to Analyze")

                record_input = st.text_input(
                    "Enter the number of emails to analyze",
                    value=str(min(1000, len(records))),
                    help=f"Enter any value between 1 and {len(records):,}"
                )

                try:
                    max_records = int(record_input)

                    if max_records < 1:
                        st.warning("Minimum value is 1.")
                        max_records = 1

                    if max_records > len(records):
                        st.warning(
                            f"Only {len(records):,} records are available. "
                            f"Using {len(records):,} instead."
                        )
                        max_records = len(records)

                except ValueError:
                    st.error("Please enter a valid whole number.")
                    st.stop()
            else:
                max_records = 1
        else:
            st.error("Could not read any records from the uploaded file.")

    if st.button("Run Detection"):
        checkpoint_file = OUTPUT_DIR / "checkpoint.json"
        checkpoint = None

        if checkpoint_file.exists():
            with open(checkpoint_file, "r", encoding="utf-8") as f:
                checkpoint = json.load(f)

        # Always reset current-session token counter.
        # Previous tokens are restored separately from checkpoint during resume.
        reset_token_counter()

        if not resume_previous:
            st.session_state.pop("last_runtime_summary", None)
        print("\n" + "=" * 70)
        print("🚀 New detection run started")
        print("=" * 70)

        if uploaded_file:
            if not records:
                st.error("Could not read any records from the uploaded file.")
                st.stop()

            if len(records) == 1:
                data, record_identifier = (
                    prepare_record_for_detection(
                        records[0],
                        fallback_id=(
                            f"{Path(uploaded_file.name).stem}_record_1"
                        ),
                    )
                )

                true_label = get_record_true_label(data)

                results = detect_email_dict(
                    email_data=data,
                    mode=selected_mode,
                    true_label=true_label,
                    filename=record_identifier,
                    fusion_strategy=(
                        selected_fusion_strategy
                    ),
                )

                st.session_state["single_result"] = results

            else:
                partial_summary_path = OUTPUT_DIR / "detection_results_partial.csv"
                partial_detail_path = OUTPUT_DIR / "detailed_analysis_report_partial.csv"
                checkpoint_path = OUTPUT_DIR / "checkpoint.json"

                output_rows = []
                detailed_results = []
                detailed_indicator_rows = []

                start_index = 0
                previous_elapsed_seconds = 0
                previous_total_tokens = 0

                if resume_previous and checkpoint:
                    checkpoint_mismatch = (
                        checkpoint.get("source_file")
                        != uploaded_file.name
                        or checkpoint.get("detection_mode")
                        != selected_mode
                        or checkpoint.get("fusion_strategy")
                        != selected_fusion_strategy
                        or checkpoint.get("total_requested")
                        != max_records
                    )

                    if checkpoint_mismatch:
                        st.error(
                            "The checkpoint belongs to a different "
                            "dataset, record count, detection mode, "
                            "or fusion strategy. Upload the original "
                            "dataset with the same configuration, or "
                            "uncheck resume."
                        )
                        st.stop()

                    start_index = checkpoint.get("last_processed", 0)
                    st.info(f"Resuming from record {start_index + 1}")
                    previous_elapsed_seconds = checkpoint.get("elapsed_seconds", 0)
                    previous_total_tokens = checkpoint.get("total_tokens_used", 0)

                    if partial_summary_path.exists():
                        output_rows = pd.read_csv(partial_summary_path).to_dict(orient="records")

                    if partial_detail_path.exists():
                        detailed_indicator_rows = pd.read_csv(partial_detail_path).to_dict(orient="records")
                else:
                    for path in [partial_summary_path, partial_detail_path, checkpoint_path]:
                        if path.exists():
                            path.unlink()

                progress = st.progress(start_index / max_records)
                progress_text = st.empty()
                start_time = time.time()

                for idx in range(start_index, max_records):
                    raw_record = records[idx]

                    try:
                        record, record_identifier = (
                            prepare_record_for_detection(
                                raw_record,
                                fallback_id=(
                                    f"{Path(uploaded_file.name).stem}"
                                    f"_record_{idx + 1}"
                                ),
                            )
                        )

                        true_label = get_record_true_label(record)

                        results = detect_email_dict(
                            email_data=record,
                            mode=selected_mode,
                            true_label=true_label,
                            filename=record_identifier,
                            fusion_strategy=(
                                selected_fusion_strategy
                            ),
                        )

                        detailed_results.append(results)
                        output_rows.append(build_output_row(results))
                        detailed_indicator_rows.extend(build_detailed_indicator_rows(results))

                        pd.DataFrame(output_rows).to_csv(
                            partial_summary_path,
                            index=False
                        )

                        pd.DataFrame(detailed_indicator_rows).to_csv(
                            partial_detail_path,
                            index=False
                        )

                        with open(
                            checkpoint_path,
                            "w",
                            encoding="utf-8",
                        ) as f:
                            json.dump(
                                {
                                    "last_processed": idx + 1,
                                    "total_requested": max_records,
                                    "source_file": uploaded_file.name,
                                    "detection_mode": selected_mode,
                                    "fusion_strategy": (
                                        selected_fusion_strategy
                                    ),
                                    "timestamp": time.strftime(
                                        "%Y-%m-%d %H:%M:%S"
                                    ),
                                    "elapsed_seconds": (
                                        previous_elapsed_seconds
                                        + (
                                            time.time()
                                            - start_time
                                        )
                                    ),
                                    "total_tokens_used": (
                                        previous_total_tokens
                                        + get_total_tokens_used()
                                    ),
                                },
                                f,
                                indent=4,
                            )

                        current_progress = (idx + 1) / max_records

                        progress.progress(current_progress)

                        progress_text.write(
                            f"**Progress:** {idx + 1:,}/{max_records:,} emails ({current_progress * 100:.1f}%)"
                        )

                    except Exception as e:
                        st.error(
                            f"Analysis stopped at record {idx + 1}. "
                            f"Fix the issue, then rerun using the same dataset with resume checked. "
                            f"Error: {e}"
                        )

                        if partial_summary_path.exists():
                            st.session_state["result_df"] = pd.read_csv(partial_summary_path)

                        if partial_detail_path.exists():
                            st.session_state["detailed_indicator_df"] = pd.read_csv(partial_detail_path)

                        st.stop()

                elapsed_time = previous_elapsed_seconds + (time.time() - start_time)

                if checkpoint_path.exists():
                    checkpoint_path.unlink()
                
                if partial_summary_path.exists():
                    partial_summary_path.unlink()

                if partial_detail_path.exists():
                    partial_detail_path.unlink()

                st.success(
                    f"✅ Detection completed successfully! "
                    f"Analyzed {len(output_rows)} email(s) in {elapsed_time:.2f} seconds."
                )

                total_tokens = previous_total_tokens + get_total_tokens_used()
                avg_tokens = round(total_tokens / len(output_rows), 2) if output_rows else 0

                print("\n" + "=" * 70)
                print("📊 Detection Run Summary")
                print("=" * 70)
                print(f"📧 Emails analyzed        : {len(output_rows)}")
                print(f"🔢 Total tokens used     : {total_tokens:,}")
                print(f"📈 Average tokens/email  : {avg_tokens:,}")
                print("=" * 70)

                if selected_mode in LLM_MODES:
                    st.info(
                        f"📊 Total Tokens Used: "
                        f"**{total_tokens:,}** | "
                        f"Average per Email: "
                        f"**{avg_tokens:,}**"
                    )
                else:
                    st.info(
                        "📊 No LLM API calls were made for "
                        "this detection mode."
                    )

                st.session_state["last_runtime_summary"] = {
                    "emails_analyzed": len(output_rows),
                    "elapsed_time": elapsed_time,
                    "total_tokens": total_tokens,
                    "avg_tokens": avg_tokens,
                }

                st.session_state["result_df"] = pd.DataFrame(output_rows)
                st.session_state["detailed_indicator_df"] = pd.DataFrame(detailed_indicator_rows)
                st.session_state["detailed_results"] = detailed_results

        elif text_input:
            data = {
                "email_id": "pasted_email",
                "source_file": "pasted_email.txt",
                "email_text": text_input,
                "body_text": text_input,
            }

            results = detect_email_dict(
                email_data=data,
                mode=selected_mode,
                true_label="unknown",
                filename="pasted_email.txt",
                fusion_strategy=(
                    selected_fusion_strategy
                ),
            )

            st.session_state["single_result"] = (
                results
            )

        else:
            st.error("Please upload or paste an email first.")
            st.stop()

    # IMPORTANT: this section is OUTSIDE st.button()
    if "single_result" in st.session_state:
        show_results(st.session_state["single_result"])

    if "result_df" in st.session_state:
        st.markdown("### Detection Results")
        summary = st.session_state["result_df"]

        c1, c2, c3, c4 = st.columns(4)

        c1.metric(
            "Emails",
            len(summary),
        )

        c2.metric(
            "Benign",
            int(
                (
                    summary["prediction"]
                    == "benign"
                ).sum()
            ),
        )

        c3.metric(
            "Unknown / Review",
            int(
                (
                    ~summary["prediction"].isin(
                        [
                            "benign",
                            "phishing",
                        ]
                    )
                ).sum()
            ),
        )

        c4.metric(
            "Phishing",
            int(
                (
                    summary["prediction"]
                    == "phishing"
                ).sum()
            ),
        )
        st.dataframe(st.session_state["result_df"], use_container_width=True)

        st.download_button(
            "📥 Download Detection Results",
            st.session_state["result_df"].to_csv(index=False).encode("utf-8"),
            file_name="detection_results.csv",
            mime="text/csv",
            key="download_summary",
        )

    if "detailed_indicator_df" in st.session_state:
        st.download_button(
            "📥 Download Detailed Analysis Report",
            st.session_state["detailed_indicator_df"].to_csv(index=False).encode("utf-8"),
            file_name="detailed_analysis_report.csv",
            mime="text/csv",
            key="download_details",
        )

    if "detailed_results" in st.session_state:
        with st.expander(
            "🔍 Detailed Detector Analysis"
        ):
            for idx, result in enumerate(
                st.session_state[
                    "detailed_results"
                ],
                start=1,
            ):
                record_name = (
                    result.get("email_id")
                    or result.get("source_file")
                    or f"Record {idx}"
                )

                st.markdown(
                    f"##### Record {idx}: "
                    f"{record_name}"
                )

                detector_results = result.get(
                    "detector_results",
                    {},
                )

                heuristic = detector_results.get(
                    "weighted_heuristic",
                    {},
                )

                association = detector_results.get(
                    "rule_association",
                    {},
                )

                llm = detector_results.get(
                    "llm",
                    {},
                )

                final_result = result.get(
                    "final_result",
                    {},
                )

                if heuristic:
                    st.markdown(
                        "**Weighted Heuristic Indicators**"
                    )

                    indicators = heuristic.get(
                        "indicators",
                        heuristic.get(
                            "triggered_indicators",
                            [],
                        ),
                    )

                    st.dataframe(
                        indicator_dataframe(
                            indicators
                        ),
                        use_container_width=True,
                    )

                if association:
                    st.markdown(
                        "**Association Patterns**"
                    )

                    matched_patterns = (
                        association.get(
                            "matched_patterns",
                            [],
                        )
                    )

                    if matched_patterns:
                        st.dataframe(
                            pd.DataFrame(
                                matched_patterns
                            ),
                            use_container_width=True,
                        )
                    else:
                        st.caption(
                            "No association patterns matched."
                        )

                if llm:
                    st.markdown(
                        "**LLM Explanation**"
                    )

                    st.write(
                        llm.get(
                            "explanation",
                            "No explanation returned.",
                        )
                    )

                st.divider()
    if "last_runtime_summary" in st.session_state:
        summary = st.session_state["last_runtime_summary"]

        st.success(
            f"⏱️ Last Run Summary: "
            f"{summary['emails_analyzed']:,} emails analyzed in "
            f"{summary['elapsed_time']:.2f} seconds | "
            f"Total tokens: {summary['total_tokens']:,} | "
            f"Avg tokens/email: {summary['avg_tokens']:,}"
        )

with tab3:
    st.subheader("Schema Columns Supported")
    st.write("The app normalizes and analyzes these columns from your preprocessed research CSV:")
    st.code(", ".join(SCHEMA_COLUMNS))

    st.subheader("Most Useful Columns for Analysis")
    st.write("Prioritize these columns because they directly improve phishing, spam, and benign classification:")
    st.dataframe(pd.DataFrame({"recommended_column": IMPORTANT_COLUMNS}), use_container_width=True)

    st.subheader("Recommended Output Fields")
    st.dataframe(
    pd.DataFrame(
        {
            "field": [
                "detection_mode",
                "final_method",
                "prediction",
                "confidence",
                "actual_label",
                "correct",
                "heuristic_prediction",
                "heuristic_confidence",
                "association_prediction",
                "association_confidence",
                "matched_pattern_count",
                "llm_prediction",
                "llm_confidence",
                "phishing_score",
                "fusion_strategy",
            ],
            "purpose": [
                "Selected experimental detector configuration",
                "Detector or fusion method producing the final result",
                "Final binary phishing or benign prediction",
                "Confidence in the final prediction",
                "Normalized evaluation ground truth",
                "Whether the final prediction matches ground truth",
                "Weighted heuristic prediction",
                "Weighted heuristic confidence",
                "Rule-association prediction",
                "Rule-association confidence",
                "Number of matched association patterns",
                "LLM semantic prediction",
                "LLM semantic confidence",
                "Fused phishing probability",
                "Weighted fusion or majority voting",
            ],
        }
    ),
    use_container_width=True,
)

with tab4:
    st.subheader("Architecture Alignment")
    st.write("This implementation assumes email preprocessing is completed before upload, so the app begins from the normalized CSV/JSON dataset.")
    architecture_df = pd.DataFrame(ARCHITECTURE_MODULES)

    st.dataframe(
        architecture_df,
        use_container_width=True,
        hide_index=True
    )

    st.markdown("#### Configurable Fusion")

    st.code(
        "full_ensemble_score = "
        "0.30 * heuristic_phishing_probability + "
        "0.30 * association_phishing_probability + "
        "0.40 * llm_phishing_probability"
    )

    st.caption(
        "These are pilot weights. They should be "
        "validated using pilot or validation data "
        "before final evaluation."
    )

    st.markdown("#### Decision Threshold")

    decision_df = pd.DataFrame(
        {
            "phishing_probability": [
                "Below 0.50",
                "0.50 or above",
            ],
            "prediction": [
                "Benign",
                "Phishing",
            ],
            "interpretation": [
                "The fused phishing probability is below the threshold",
                "The fused phishing probability meets or exceeds the threshold",
            ],
        }
    )

    st.dataframe(
        decision_df,
        use_container_width=True,
        hide_index=True,
    )
