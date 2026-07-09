import os
import json
from pathlib import Path
from openai import OpenAI
from dotenv import load_dotenv

try:
    from detection.schema_utils import normalize_email_record
except ImportError:
    from schema_utils import normalize_email_record

load_dotenv()

# ========== CONFIG ==========

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
    - Source dataset: {normalized.get('source_dataset', '')}
    - Source file: {normalized.get('source_file', '')}
    - High-level category, if labeled: {normalized.get('high_level_category', '')}
    - Subcategory, if labeled: {normalized.get('subcategory', '')}
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
    - Generation type: {normalized.get('generation_type', '')}
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
- Whether the email is human-generated or LLM-generated
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
            model="gpt-5",
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
                model="gpt-5",
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

    label = extract_field(content, "Label", "benign").lower()
    confidence = extract_field(content, "Confidence", "0.80")
    intent = extract_field(content, "Intent", "unknown")
    sender_trust = extract_field(content, "Sender Trust", "unknown")
    url_risk = extract_field(content, "URL Risk", "unknown")
    social_engineering_risk = extract_field(content, "Social Engineering Risk", "unknown")
    explanation = extract_field(content, "Explanation", "")

    try:
        confidence = float(confidence)
    except ValueError:
        confidence = 0.80

    if label not in ["phishing", "benign"]:
        label = "benign"

    llm_result = {
        "label": label,
        "confidence": confidence,
        "intent": intent,
        "sender_trust": sender_trust,
        "url_risk": url_risk,
        "social_engineering_risk": social_engineering_risk,
        "explanation": explanation,
        "raw_response": content,
    }

    global TOTAL_TOKENS_USED

    tokens_used = response.usage.total_tokens if response.usage else 0
    TOTAL_TOKENS_USED += tokens_used

    print(f"🔢 Tokens used for this email: {tokens_used}")
    print(f"📊 Total tokens used in current detection run: {TOTAL_TOKENS_USED}")

    return llm_result

# ========== SCANNING FUNCTION ==========

def scan_directory(directory, true_label):
    results = []
    files = list(directory.glob("*.json"))

    for file in files:
        with open(file, "r", encoding="utf-8") as f:
            data = normalize_email_record(json.load(f))
        email_text = data.get("email_text", "")
        llm_result = get_llm_prediction(email_text, data)
        llm_label = llm_result["label"]
        explanation = llm_result["explanation"]

        result = {
            "source_file": file.name,
            "email_id": data.get("email_id", ""),
            "source_dataset": data.get("source_dataset", ""),
            "subcategory": data.get("subcategory", ""),
            "generation_type": data.get("generation_type", ""),
            "llm_label": llm_label,
            "true_label": true_label,
            "explanation": explanation,
        }

        results.append(result)

        print(f"🤖 {file.name} → LLM: {llm_label} | Actual: {true_label}")
        with open(OUTPUT_BASE / f"{file.stem}_llm_result.json", "w", encoding="utf-8") as out_f:
            json.dump(result, out_f, indent=4)

    return results

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
        pred = r["llm_label"]
        actual = r["true_label"]

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
