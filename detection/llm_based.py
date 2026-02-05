import os
import json
from pathlib import Path
from openai import OpenAI
from dotenv import load_dotenv

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

def get_llm_prediction(email_text):
    prompt = f"""
You are a strict cybersecurity analyst responsible for detecting phishing emails in a high-risk corporate environment.

Classify the email as either:
- **phishing**: a deceptive attempt to steal credentials or sensitive data
- **benign**: a normal, legitimate message

🛑 Avoid false positives — only label as phishing if **clear red flags** are found.

When analyzing, consider:
- Urgency, threats, or pressure to act
- Requests for login credentials, account access, or money
- Suspicious or mismatched links
- Impersonation of trusted brands or individuals
- Poor grammar, spelling, or formatting
- Unusual sender addresses or fake domains

---

📄 Email to analyze:
\"\"\"
{email_text}
\"\"\"

---

🎯 Respond **only** in this exact format:
Label: <phishing or benign>  
Explanation: <clear reason for your decision. Highlight suspicious words, behaviors, or patterns>

🔍 Example 1:
Label: phishing  
Explanation: The email creates urgency ("verify in 24 hours"), asks for account credentials, and impersonates a bank.

🔍 Example 2:
Label: benign  
Explanation: The email is a standard newsletter with no requests for action or sensitive data. Language and links are normal.
"""

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
            data = json.load(f)
        email_text = data.get("email_text", "")
        llm_label, explanation = get_llm_prediction(email_text)

        result = {
            "source_file": file.name,
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

    # Save combined results
    with open(DETAILS_DIR / "llm_scan_results.json", "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=4)

    # Confusion matrix
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
        "accuracy": round((TP + TN) / len(all_results), 3),
        "f1_score": round(2 * TP / (2 * TP + FP + FN), 3) if (2 * TP + FP + FN) else 0
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
