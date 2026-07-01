import json
import time
import pandas as pd
import streamlit as st

from utils import run_combined_detection

st.set_page_config(page_title="PhishSense AI", layout="wide")
st.markdown("""
<style>
/* Main background */
.stApp {
    background:
        linear-gradient(rgba(5, 12, 28, 0.82), rgba(5, 12, 28, 0.88)),
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

h2, h3, h4 {
    color: #1e293b !important;
    font-weight: 700 !important;
}

p, label, span, div {
    color: #111827;
}

/* Captions */
[data-testid="stCaptionContainer"] {
    color: #334155 !important;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    gap: 10px;
    border-bottom: 1px solid #cbd5e1;
}

.stTabs [data-baseweb="tab"] {
    background: #f1f5f9;
    border-radius: 10px 10px 0 0;
    padding: 10px 18px;
    color: #0f172a;
    font-weight: 600;
}

.stTabs [aria-selected="true"] {
    background: #dbeafe !important;
    color: #1d4ed8 !important;
    border-bottom: 3px solid #2563eb;
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
</style>
""", unsafe_allow_html=True)
st.title("🛡️ PhishSense AI")
st.subheader("Hybrid LLM & Heuristic Email Phishing Detection System")
st.caption(
"Research prototype implementing heuristic analysis, LLM semantic reasoning, hybrid confidence fusion, and explainable phishing detection."
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
    {"layer": "1. Incoming Emails", "implementation": "CSV, JSON, or pasted raw text input"},
    {"layer": "2. Dataset Normalization", "implementation": "schema_utils.normalize_email_record() standardizes the preprocessed schema"},
    {"layer": "3. Feature Extraction & Heuristics", "implementation": "Authentication, sender/domain, URL/routing, attachment, spam/marketing, and social-engineering indicators"},
    {"layer": "4A. Heuristic Engine", "implementation": "Weighted rule scoring with weak-signal cap and category-level indicators"},
    {"layer": "4B. LLM Semantic Reasoning", "implementation": "LLM label, confidence, intent, sender trust, URL risk, and explanation"},
    {"layer": "5. Hybrid Decision Fusion", "implementation": "Hybrid score = 0.35 heuristic confidence + 0.65 LLM phishing probability"},
    {"layer": "6. Final Output", "implementation": "Prediction, rule score, hybrid score, risk level, and analysis report"},
    {"layer": "7. Explainability", "implementation": "Triggered indicators, weighted indicator table, category scores, and LLM explanation"},
]


def load_uploaded_records(uploaded_file):
    if uploaded_file.name.lower().endswith(".json"):
        payload = json.load(uploaded_file)
        if isinstance(payload, list):
            return payload
        return [payload]

    if uploaded_file.name.lower().endswith(".csv"):
        try:
            df = pd.read_csv(uploaded_file)
        except pd.errors.ParserError:
            uploaded_file.seek(0)
            df = pd.read_csv(uploaded_file, engine="python", on_bad_lines="skip")
            st.warning("Some malformed CSV rows were skipped. Check commas/quotes in body_text, body_html, urls, or headers.")
        return df.fillna("").to_dict(orient="records")

    return []


def indicator_dataframe(indicators):
    if not indicators:
        return pd.DataFrame(columns=["category", "rule", "weight", "strength", "evidence"])
    rows = []
    for item in indicators:
        rows.append({
            "category": item.get("category", ""),
            "rule": item.get("rule", ""),
            "weight": item.get("weight", 0),
            "strength": item.get("strength", ""),
            "evidence": item.get("evidence", ""),
        })
    return pd.DataFrame(rows).sort_values(by="weight", ascending=False)


def show_results(results):
    normalized = results["normalized_email"]
    rule_result = results["rule_result"]

    col1, col2, col3, col4, col5 = st.columns(5)
    # Final Decision
    decision = results["hybrid_label"].lower()

    if decision == "phishing":
        decision_display = "🔴 PHISHING"
    elif decision == "suspicious":
        decision_display = "🟡 SUSPICIOUS"
    else:
        decision_display = "🟢 BENIGN"

    # Risk Level
    risk = results["risk_level"].lower()

    if risk == "high":
        risk_display = "🔴 HIGH"
    elif risk == "medium":
        risk_display = "🟡 MEDIUM"
    else:
        risk_display = "🟢 LOW"

    col1.metric("Final Decision", decision_display)
    col2.metric("Risk Level", risk_display)
    col3.metric("Hybrid Score", f"{results['hybrid_score']}%")
    col4.metric("Rule Score", rule_result["score"])
    col5.metric(
        "LLM",
        f"{results['llm_label'].upper()} ({results['llm_confidence']})"
    )

    st.markdown("#### 🧠 Hybrid Fusion Report")
    st.json(results["analysis_report"])

    st.markdown("#### 💬 LLM Semantic Reasoning")
    st.code(results["llm_explanation"])

    st.markdown("#### 🔍 Weighted Heuristic Indicators")
    st.dataframe(indicator_dataframe(rule_result.get("indicators", [])), use_container_width=True)

    with st.expander("📊 Heuristic Category Scores"):
        st.json(rule_result.get("category_scores", {}))

    with st.expander("📄 Normalized Email Record"):
        st.json(normalized)


def build_output_row(results):
    rule_result = results["rule_result"]
    normalized = results["normalized_email"]
    top_rules = [i.get("rule", "") for i in results.get("top_indicators", [])]

    return {
        "email_id": normalized.get("email_id", ""),
        "source_dataset": normalized.get("source_dataset", ""),
        "true_category": normalized.get("high_level_category", ""),
        "subcategory": normalized.get("subcategory", ""),
        "rule_score": rule_result.get("score", 0),
        "rule_confidence": rule_result.get("rule_confidence", 0),
        "rule_label": "phishing" if rule_result.get("is_phishing") else "benign",
        "llm_label": results["llm_label"],
        "llm_confidence": results["llm_confidence"],
        "hybrid_score": results["hybrid_score"],
        "risk_level": results["risk_level"],
        "hybrid_label": results["hybrid_label"],
        "top_indicators": ", ".join(top_rules),
        "triggered_rules": ", ".join(rule_result.get("flagged_keywords", [])),
    }

def build_detailed_indicator_rows(results):
    rule_result = results["rule_result"]
    normalized = results["normalized_email"]

    rows = []
    for indicator in rule_result.get("indicators", []):
        rows.append({
            "email_id": normalized.get("email_id", ""),
            "source_dataset": normalized.get("source_dataset", ""),
            "true_category": normalized.get("high_level_category", ""),
            "subcategory": normalized.get("subcategory", ""),
            "rule_score": rule_result.get("score", 0),
            "rule_confidence": rule_result.get("rule_confidence", 0),
            "rule_label": "phishing" if rule_result.get("is_phishing") else "benign",
            "llm_label": results.get("llm_label", ""),
            "llm_confidence": results.get("llm_confidence", ""),
            "hybrid_score": results.get("hybrid_score", ""),
            "risk_level": results.get("risk_level", ""),
            "hybrid_label": results.get("hybrid_label", ""),
            "indicator_category": indicator.get("category", ""),
            "indicator_rule": indicator.get("rule", ""),
            "indicator_weight": indicator.get("weight", 0),
            "indicator_strength": indicator.get("strength", ""),
            "indicator_evidence": indicator.get("evidence", ""),
        })

    return rows

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

    uploaded_file = st.file_uploader("Upload email JSON or CSV", type=["json", "csv"])
    text_input = st.text_area("Or paste raw email text here")

    records = []
    max_records = 1

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
        if uploaded_file:
            if not records:
                st.error("Could not read any records from the uploaded file.")
                st.stop()

            if len(records) == 1:
                data = records[0]
                email_text = data.get("email_text") or data.get("body_text") or data.get("body_html") or ""
                results = run_combined_detection(email_text, data)
                st.session_state["single_result"] = results

            else:
                output_rows = []
                detailed_results = []
                detailed_indicator_rows = []
                progress = st.progress(0)

                start_time = time.time()

                for idx, record in enumerate(records[:max_records]):
                    email_text = record.get("email_text") or record.get("body_text") or record.get("body_html") or ""
                    results = run_combined_detection(email_text, record)

                    detailed_results.append(results)
                    output_rows.append(build_output_row(results))
                    detailed_indicator_rows.extend(build_detailed_indicator_rows(results))

                    progress.progress((idx + 1) / max_records)

                elapsed_time = time.time() - start_time

                st.success(
                    f"✅ Detection completed successfully! "
                    f"Analyzed {len(output_rows)} email(s) in {elapsed_time:.2f} seconds."
                )
                st.session_state["result_df"] = pd.DataFrame(output_rows)
                st.session_state["detailed_results"] = detailed_results

                if detailed_indicator_rows:
                    st.session_state["detailed_indicator_df"] = pd.DataFrame(detailed_indicator_rows)

        elif text_input:
            data = {"email_text": text_input, "body_text": text_input}
            results = run_combined_detection(text_input, data)
            st.session_state["single_result"] = results

        else:
            st.error("Please upload or paste an email first.")
            st.stop()

    # IMPORTANT: this section is OUTSIDE st.button()
    if "single_result" in st.session_state:
        show_results(st.session_state["single_result"])

    if "result_df" in st.session_state:
        st.markdown("### Detection Results")
        summary = st.session_state["result_df"]

        c1,c2,c3,c4 = st.columns(4)

        c1.metric(
        "Emails",
        len(summary)
        )

        c2.metric(
        "Benign",
        (summary.hybrid_label=="benign").sum()
        )

        c3.metric(
        "Suspicious",
        (summary.hybrid_label=="suspicious").sum()
        )

        c4.metric(
        "Phishing",
        (summary.hybrid_label=="phishing").sum()
        )
        st.dataframe(st.session_state["result_df"], use_container_width=True)

        st.download_button(
            "📥 Download Detection Results",
            st.session_state["result_df"].to_csv(index=False).encode("utf-8"),
            file_name="phishsense_detection_results.csv",
            mime="text/csv",
            key="download_summary",
        )

    if "detailed_indicator_df" in st.session_state:
        st.download_button(
            "📥 Download Detailed Analysis Report",
            st.session_state["detailed_indicator_df"].to_csv(index=False).encode("utf-8"),
            file_name="phishsense_detailed_indicator_report.csv",
            mime="text/csv",
            key="download_details",
        )

    if "detailed_results" in st.session_state:
        with st.expander("🔍 Detailed Indicator Analysis"):
            for idx, result in enumerate(st.session_state["detailed_results"], start=1):
                st.markdown(
                    f"##### Record {idx}: {result['normalized_email'].get('email_id','')}"
                )
                st.dataframe(
                    indicator_dataframe(result["rule_result"].get("indicators", [])),
                    use_container_width=True,
                )

with tab3:
    st.subheader("Schema Columns Supported")
    st.write("The app normalizes and analyzes these columns from your preprocessed research CSV:")
    st.code(", ".join(SCHEMA_COLUMNS))

    st.subheader("Most Useful Columns for Analysis")
    st.write("Prioritize these columns because they directly improve phishing, spam, and benign classification:")
    st.dataframe(pd.DataFrame({"recommended_column": IMPORTANT_COLUMNS}), use_container_width=True)

    st.subheader("Recommended Output Fields")
    st.dataframe(pd.DataFrame({
        "field": ["rule_score", "rule_confidence", "llm_label", "llm_confidence", "hybrid_score", "risk_level", "hybrid_label", "top_indicators"],
        "purpose": [
            "Transparent heuristic score from weighted indicators",
            "Normalized 0-1 heuristic confidence",
            "LLM semantic classification",
            "Parsed or default LLM confidence",
            "Aggregated fusion score from rule + LLM evidence",
            "Low / Medium / High risk decision support",
            "Final label for evaluation (Benign / Suspicious / Phishing)",
            "Explainability summary for analysts",
        ],
    }), use_container_width=True)

with tab4:
    st.subheader("Architecture Alignment")
    st.write("This implementation assumes email preprocessing is completed before upload, so the app begins from the normalized CSV/JSON dataset.")
    st.table(pd.DataFrame(ARCHITECTURE_MODULES))

    st.markdown("#### Current Hybrid Fusion Formula")
    st.code("hybrid_score = 0.35 * heuristic_confidence + 0.65 * llm_phishing_probability")

    st.markdown("#### Risk Mapping")
    st.dataframe(pd.DataFrame({
        "hybrid_score": ["0-39", "40-69", "70-100"],
        "risk_level": ["Low", "Medium", "High"],
        "interpretation": ["Likely benign", "Needs analyst review", "High phishing likelihood"],
    }), use_container_width=True)
