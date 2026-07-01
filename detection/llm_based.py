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
OUTPUT_BASE = Path("detection/output_llm/")
DETAILS_DIR = OUTPUT_BASE / "details"

OUTPUT_BASE.mkdir(parents=True, exist_ok=True)
DETAILS_DIR.mkdir(parents=True, exist_ok=True)

api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("❌ OPENAI_API_KEY not found in environment. Please check your .env file.")

client = OpenAI(api_key=api_key)

# ========== LLM SCORING FUNCTION ==========

def get_llm_prediction(email_text, email_meta=None):
    """Classify an email using the LLM.

    email_meta can be a full record from the expanded schema. It is normalized
    and added as structured context so the model can consider URLs, headers,
    authentication results, attachments, category, and generation type.
    """
    context = ""
    if email_meta:
        normalized = normalize_email_record(email_meta)
        email_text = normalized.get("email_text", email_text)
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
- URLs: {normalized.get('urls', [])}
- Has attachment: {normalized.get('has_attachment', False)}
- Attachment count: {normalized.get('attachment_count', 0)}
- Has image: {normalized.get('has_image', False)}
- Image count: {normalized.get('image_count', 0)}
- Authentication results: {normalized.get('authentication_results', '')}
- Generation type: {normalized.get('generation_type', '')}
- Is HTML: {normalized.get('is_html', False)}
- Is plain text: {normalized.get('is_plain_text', False)}
"""

    prompt = f'''
You are a strict cybersecurity analyst responsible for detecting phishing emails in a high-risk corporate environment.

Classify the email as either:
- phishing: a deceptive attempt to steal credentials, money, account access, or sensitive data
- benign: a normal, legitimate message

Important: spam/marketing emails may be unwanted, but only label phishing when there are clear phishing indicators.

When analyzing, consider:
- Urgency, threats, pressure, or suspicious requests
- Requests for login credentials, account access, payment, gift cards, or wire transfers
- Suspicious, mismatched, shortened, or high-risk URLs
- Sender/domain mismatch or impersonation of trusted brands
- SPF/DKIM/DMARC failures in authentication results
- Suspicious routing headers
- Attachments, HTML-only content, embedded images, or image-heavy emails
- Whether the email is human-generated or LLM-generated

---

Email metadata and content to analyze:
{context}
"""
{email_text}
"""

---

Respond only in this exact format:
Label: <phishing or benign>
Confidence: <0.00 to 1.00>
Intent: <credential theft, financial fraud, spam/marketing, legitimate communication, or unknown>
Sender Trust: <low, medium, or high>
URL Risk: <low, medium, or high>
Social Engineering Risk: <low, medium, or high>
Explanation: <clear reason for your decision, including the strongest indicators>
'''

    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
    )

    content = response.choices[0].message.content.strip().lower()
    label = "phishing" if "label: phishing" in content else "benign"

    print(f"🔢 Tokens used: {response.usage.total_tokens}")
    return label, content

# ========== SCANNING FUNCTION ==========

def scan_directory(directory, true_label):
    results = []
    files = list(directory.glob("*.json"))

    for file in files:
        with open(file, "r", encoding="utf-8") as f:
            data = normalize_email_record(json.load(f))
        email_text = data.get("email_text", "")
        llm_label, explanation = get_llm_prediction(email_text, data)

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
