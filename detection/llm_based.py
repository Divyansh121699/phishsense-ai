import os
import json
from pathlib import Path
from openai import OpenAI
from dotenv import load_dotenv

try:
    from detection.schema_utils import (
        normalize_email_record,
        get_true_label,
    )
except ImportError:
    from schema_utils import (
        normalize_email_record,
        get_true_label,
    )

load_dotenv()

# ========== CONFIG ==========

MODEL_NAME = "gpt-5"

PHISHING_DIR = Path("phishing_emails/")
BENIGN_DIR = Path("benign_emails/")
OUTPUT_BASE = Path("detection/output_llm_gpt5/")
DETAILS_DIR = OUTPUT_BASE / "details"

OUTPUT_BASE.mkdir(parents=True, exist_ok=True)
DETAILS_DIR.mkdir(parents=True, exist_ok=True)

api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("❌ OPENAI_API_KEY not found in environment. Please check your .env file.")

client = OpenAI(api_key=api_key)

# ========== TOKEN TRACKING ==========

TOTAL_TOKENS_USED = 0


def reset_token_counter():
    global TOTAL_TOKENS_USED
    TOTAL_TOKENS_USED = 0


def get_total_tokens_used():
    return TOTAL_TOKENS_USED

# ========== LLM SCORING FUNCTION ==========

def get_llm_prediction(email_text, email_meta=None):
    """Classify an email using the LLM."""

    context = ""
    normalized = {}
    if email_meta:
        normalized = normalize_email_record(email_meta)
        email_text = normalized.get("email_text", email_text)

        # Prevent very large emails from exceeding the model context window
        MAX_EMAIL_CHARS = 12000

        if email_text and len(email_text) > MAX_EMAIL_CHARS:
            print(f"⚠️ Email truncated from {len(email_text):,} to {MAX_EMAIL_CHARS:,} characters.")
            email_text = email_text[:MAX_EMAIL_CHARS]

    urls = normalized.get("urls", [])

    if isinstance(urls, list):
        urls = urls[:10]
    else:
        urls = str(urls)[:1000]

    context = f"""
    Metadata:
    - Sender: {normalized.get('sender', '')}
    - Receiver: {normalized.get('receiver', '')}
    - Subject: {normalized.get('subject', '')}
    - URL count: {normalized.get('url_count', 0)}
    - URLs: {urls}
    - Has attachment: {normalized.get('has_attachment', False)}
    - Attachment count: {normalized.get('attachment_count', 0)}
    - Has image: {normalized.get('has_image', False)}
    - Image count: {normalized.get('image_count', 0)}
    - Authentication results: {str(normalized.get('authentication_results', ''))[:1000]}
    - Received headers: {str(normalized.get('received_headers', ''))[:1000]}
    - Is HTML: {normalized.get('is_html', False)}
    - Is plain text: {normalized.get('is_plain_text', False)}
    """

    prompt = f"""
You are a strict cybersecurity analyst responsible for detecting phishing emails in a high-risk corporate environment.

Classify the email as either:

- phishing: an email whose primary purpose is deception or fraud, including credential theft, impersonation, malware delivery, financial scams, fake products or services, malicious links, or any attempt to manipulate the recipient into unsafe actions. Credential theft is one common form of phishing but is not the only form.

- benign: a legitimate email that does not contain deceptive, fraudulent, scam-like, or malicious intent.

Important:
- Some phishing emails resemble advertisements, newsletters, promotional offers, or commercial emails. Evaluate the underlying intent rather than the writing style alone.
- Classify an email as phishing if its primary purpose is to deceive, impersonate, conduct fraud, distribute malware, promote fake or fraudulent products/services, or manipulate the recipient into unsafe actions.
- Legitimate newsletters, advertisements, and promotional emails from trusted organizations should be labeled benign.
- Do not classify an email as phishing based solely on the presence of a URL.
- Consider all available evidence, including sender identity, domain reputation, authentication results, URLs, attachments, HTML content, and overall intent.
- Classify an email as phishing whenever its primary purpose is deception, fraud, impersonation, malware delivery, financial scams, fake products or services, malicious links, or manipulation of the recipient, even if it does not explicitly request credentials or payment.

When analyzing, consider:
- Urgency, threats, pressure, or suspicious requests
- Requests for login credentials, account access, payment, gift cards, wire transfers, or sensitive data
- Suspicious, mismatched, shortened, obfuscated, or high-risk URLs
- Sender/domain mismatch or impersonation of trusted brands
- SPF/DKIM/DMARC failures in authentication results
- Suspicious routing headers
- Attachments, HTML-only content, embedded images, or image-heavy emails
- Whether the email attempts to exploit trust, curiosity, fear, urgency, or financial incentives to influence the recipient's behavior.
- Whether the overall purpose of the email is deceptive, fraudulent, or intended to manipulate the recipient, even if it does not explicitly request credentials

---

Email metadata and content to analyze:
{context}

Email body:
\"\"\"
{email_text}
\"\"\"

---

Respond only in this exact format:
Label: <phishing or benign>
Confidence: <0.00 to 1.00>
Intent: <credential theft, financial fraud, impersonation, malware delivery, scam/fraud, legitimate communication, marketing, or unknown>
Sender Trust: <low, medium, or high>
URL Risk: <low, medium, or high>
Social Engineering Risk: <low, medium, or high>
Explanation: <maximum 2-3 sentences summarizing the strongest evidence supporting the classification. Reference the most influential phishing indicators such as impersonation, malicious intent, suspicious sender behavior, risky URLs, scam techniques, fraudulent offers, authentication failures, or social engineering tactics.>
"""
    try:
        response = client.responses.create(
            model=MODEL_NAME,
            input=prompt,
            reasoning={"effort": "low"},
            text={"verbosity": "low"},
            max_output_tokens=1200,
        )

    except Exception as e:
        error_text = str(e)

        if "context_length_exceeded" in error_text or "context window" in error_text:

            print("⚠️ Context window exceeded. Retrying with smaller prompt...")

            # Further reduce email body
            shortened_email_text = email_text[:3000]

            # Reduce metadata as well
            shortened_context = context[:2000]

            retry_prompt = f"""
    You are a cybersecurity analyst.

    Classify the email as phishing or benign.

    Metadata:
    {shortened_context}

    Email:
    \"\"\"
    {shortened_email_text}
    \"\"\"

    Respond only:

    Label:
    Confidence:
    Intent:
    Sender Trust:
    URL Risk:
    Social Engineering Risk:
    Explanation:
    """

            response = client.responses.create(
                model=MODEL_NAME,
                input=retry_prompt,
                reasoning={"effort": "low"},
                text={"verbosity": "low"},
                max_output_tokens=500,
            )

        else:
            raise

    content = response.output_text.strip()

    def extract_field(text, field_name, default=""):
        for line in text.splitlines():
            if line.lower().startswith(field_name.lower() + ":"):
                return line.split(":", 1)[1].strip()
        return default

    label = extract_field(
        content,
        "Label",
        "benign",
    ).strip().lower()

    confidence_text = extract_field(
        content,
        "Confidence",
        "0.80",
    ).strip()

    intent = extract_field(
        content,
        "Intent",
        "unknown",
    ).strip().lower()

    sender_trust = extract_field(
        content,
        "Sender Trust",
        "unknown",
    ).strip().lower()

    url_risk = extract_field(
        content,
        "URL Risk",
        "unknown",
    ).strip().lower()

    social_engineering_risk = extract_field(
        content,
        "Social Engineering Risk",
        "unknown",
    ).strip().lower()

    explanation = extract_field(
        content,
        "Explanation",
        "",
    ).strip()

    # Normalize the label.
    if label not in {"phishing", "benign"}:
        label = "benign"

    # Normalize confidence to the range 0.0–1.0.
    try:
        confidence = float(
            confidence_text.replace("%", "")
        )
    except (TypeError, ValueError):
        confidence = 0.80

    # Handle responses such as 85 or 85%.
    if confidence > 1:
        confidence = confidence / 100

    confidence = round(
        max(0.0, min(confidence, 1.0)),
        3,
    )

    llm_result = {
        "method": "llm",
        "model": MODEL_NAME,

        # Standardized detector output.
        "prediction": label,
        "confidence": confidence,
        "is_phishing": label == "phishing",

        # Keep the old key temporarily for backward compatibility.
        "label": label,

        # LLM-specific analysis.
        "intent": intent,
        "sender_trust": sender_trust,
        "url_risk": url_risk,
        "social_engineering_risk": social_engineering_risk,
        "explanation": explanation,

        # Useful for debugging response-format problems.
        "raw_response": content,
    }

    global TOTAL_TOKENS_USED

    tokens_used = response.usage.total_tokens if response.usage else 0
    TOTAL_TOKENS_USED += tokens_used

    print(f"🔢 Tokens used for this email: {tokens_used}")
    print(f"📊 Total tokens used in current detection run: {TOTAL_TOKENS_USED}")

    return llm_result

def normalize_evaluation_label(true_label):
    """
    Normalize the ground-truth label for evaluation.

    Spam is currently treated as malicious to remain consistent
    with the weighted heuristic evaluation.
    """

    if true_label is None:
        return "unknown", None

    normalized_label = str(true_label).strip().lower()

    if normalized_label == "spam":
        expected_prediction = "phishing"
    elif normalized_label in {"phishing", "benign"}:
        expected_prediction = normalized_label
    else:
        expected_prediction = None

    return normalized_label, expected_prediction

# ========== SCANNING FUNCTION ==========

def scan_directory(directory, true_label):
    results = []
    files = list(directory.glob("*.json"))

    for file in files:
        with open(file, "r", encoding="utf-8") as f:
            data = normalize_email_record(json.load(f))
        email_text = data.get("email_text", "")
        llm_result = get_llm_prediction(
            email_text,
            data,
        )

        prediction = llm_result["prediction"]

        actual_label, expected_prediction = (
            normalize_evaluation_label(true_label)
        )

        correct = (
            prediction == expected_prediction
            if expected_prediction is not None
            else None
        )

        result = {
            # Common detector fields.
            "method": "llm",
            "model": MODEL_NAME,
            "source_file": file.name,
            "email_id": data.get("email_id", ""),
            "source_dataset": data.get("source_dataset", ""),
            "high_level_category": data.get(
                "high_level_category",
                "",
            ),
            "subcategory": data.get("subcategory", ""),
            "generation_type": data.get(
                "generation_type",
                "",
            ),

            # Standardized prediction fields.
            "prediction": prediction,
            "confidence": llm_result["confidence"],
            "is_phishing": llm_result["is_phishing"],

            # Ground-truth evaluation fields.
            "actual_label": actual_label,
            "correct": correct,

            # LLM-specific fields.
            "intent": llm_result["intent"],
            "sender_trust": llm_result["sender_trust"],
            "url_risk": llm_result["url_risk"],
            "social_engineering_risk": (
                llm_result["social_engineering_risk"]
            ),
            "explanation": llm_result["explanation"],
            "raw_response": llm_result["raw_response"],

            # Temporary backward-compatible fields.
            "llm_label": prediction,
            "true_label": actual_label,
        }

        results.append(result)

        if correct is True:
            status = "Correct"
        elif correct is False:
            status = "Incorrect"
        else:
            status = "Not evaluated"

        print(
            f"🤖 {file.name} "
            f"→ LLM: {prediction} "
            f"| Confidence: {llm_result['confidence']:.3f} "
            f"| Actual: {actual_label} "
            f"| Result: {status}"
        )
        with open(OUTPUT_BASE / f"{file.stem}_llm_result.json", "w", encoding="utf-8") as out_f:
            json.dump(result, out_f, indent=4)

    return results

def analyze_email_llm(
        
    file_path,
    true_label=None,
):
    """
    Analyze one JSON email file using the LLM detector.

    This function will later be used by the detection controller.
    """

    file_path = Path(file_path)

    with open(file_path, "r", encoding="utf-8") as file:
        data = normalize_email_record(
            json.load(file)
        )
    if true_label is None:
        true_label = get_true_label(data)

    email_text = data.get("email_text", "")

    llm_result = get_llm_prediction(
        email_text,
        data,
    )

    prediction = llm_result["prediction"]

    actual_label, expected_prediction = (
        normalize_evaluation_label(true_label)
    )

    correct = (
        prediction == expected_prediction
        if expected_prediction is not None
        else None
    )

    return {
        "method": "llm",
        "model": MODEL_NAME,
        "source_file": file_path.name,
        "email_id": data.get("email_id", ""),
        "source_dataset": data.get(
            "source_dataset",
            "",
        ),
        "high_level_category": data.get(
            "high_level_category",
            "",
        ),
        "subcategory": data.get(
            "subcategory",
            "",
        ),
        "generation_type": data.get(
            "generation_type",
            "",
        ),

        "prediction": prediction,
        "confidence": llm_result["confidence"],
        "is_phishing": llm_result["is_phishing"],

        "actual_label": actual_label,
        "correct": correct,

        "intent": llm_result["intent"],
        "sender_trust": llm_result["sender_trust"],
        "url_risk": llm_result["url_risk"],
        "social_engineering_risk": (
            llm_result["social_engineering_risk"]
        ),
        "explanation": llm_result["explanation"],
        "raw_response": llm_result["raw_response"],

        # Backward compatibility.
        "llm_label": prediction,
        "true_label": actual_label,
    }

def analyze_email_dict_llm(
        
    email_data,
    true_label="unknown",
    filename="uploaded_email.json",
):
    """
    Analyze an email dictionary using the LLM detector.

    This function is intended for Streamlit uploads.
    """

    data = normalize_email_record(email_data)

    if true_label == "unknown":
        true_label = get_true_label(data)

    email_text = data.get("email_text", "")

    llm_result = get_llm_prediction(
        email_text,
        data,
    )

    prediction = llm_result["prediction"]

    actual_label, expected_prediction = (
        normalize_evaluation_label(true_label)
    )

    correct = (
        prediction == expected_prediction
        if expected_prediction is not None
        else None
    )

    return {
        "method": "llm",
        "model": MODEL_NAME,
        "source_file": filename,
        "email_id": data.get("email_id", ""),
        "source_dataset": data.get(
            "source_dataset",
            "",
        ),
        "high_level_category": data.get(
            "high_level_category",
            "",
        ),
        "subcategory": data.get(
            "subcategory",
            "",
        ),
        "generation_type": data.get(
            "generation_type",
            "",
        ),

        "prediction": prediction,
        "confidence": llm_result["confidence"],
        "is_phishing": llm_result["is_phishing"],

        "actual_label": actual_label,
        "correct": correct,

        "intent": llm_result["intent"],
        "sender_trust": llm_result["sender_trust"],
        "url_risk": llm_result["url_risk"],
        "social_engineering_risk": (
            llm_result["social_engineering_risk"]
        ),
        "explanation": llm_result["explanation"],
        "raw_response": llm_result["raw_response"],

        # Backward compatibility.
        "llm_label": prediction,
        "true_label": actual_label,
    }

# ========== MAIN ==========

def run_llm_scan():
    phishing_results = scan_directory(PHISHING_DIR, "phishing")
    benign_results = scan_directory(BENIGN_DIR, "benign")
    all_results = phishing_results + benign_results

    with open(DETAILS_DIR / "llm_scan_results.json", "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=4)

    TP = FP = TN = FN = 0
    false_positives = []
    false_negatives = []

    for r in all_results:
        pred = r["prediction"]
        actual = r["actual_label"]

        if pred == "phishing" and actual == "phishing":
            TP += 1
        elif pred == "benign" and actual == "benign":
            TN += 1
        elif pred == "phishing" and actual == "benign":
            FP += 1
            false_positives.append(r)
        elif pred == "benign" and actual == "phishing":
            FN += 1
            false_negatives.append(r)

    summary = {
        "total_emails": len(all_results),
        "true_positives": TP,
        "true_negatives": TN,
        "false_positives": FP,
        "false_negatives": FN,
        "precision": round(TP / (TP + FP), 3) if (TP + FP) else 0,
        "recall": round(TP / (TP + FN), 3) if (TP + FN) else 0,
        "accuracy": round((TP + TN) / len(all_results), 3) if all_results else 0,
        "f1_score": round(2 * TP / (2 * TP + FP + FN), 3) if (2 * TP + FP + FN) else 0,
    }

    with open(DETAILS_DIR / "summary_metrics.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=4)

    with open(DETAILS_DIR / "false_positives.json", "w", encoding="utf-8") as f:
        json.dump(false_positives, f, indent=4)

    with open(DETAILS_DIR / "false_negatives.json", "w", encoding="utf-8") as f:
        json.dump(false_negatives, f, indent=4)

    print(f"\n📈 Summary written to {DETAILS_DIR}/summary_metrics.json")
    print(json.dumps(summary, indent=4))
    print(f"⚠️  False Positives: {len(false_positives)} | False Negatives: {len(false_negatives)}")

if __name__ == "__main__":
    run_llm_scan()
