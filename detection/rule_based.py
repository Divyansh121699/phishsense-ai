import os
import json
import re
from pathlib import Path

# ========== CONFIG ==========
PHISHING_DIR = Path("phishing_emails/")
BENIGN_DIR = Path("benign_emails/")
OUTPUT_DIR = Path("detection/output_rule/")
DETAILS_DIR = OUTPUT_DIR / "details"
SCORE_THRESHOLD = 25  # Flag as phishing if score >= this

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
DETAILS_DIR.mkdir(parents=True, exist_ok=True)

# ========== RULES ==========
SUSPICIOUS_KEYWORDS = [
    "verify", "click here", "update your account", "login to your account",
    "suspended", "limited", "unauthorized", "urgent", "confirm your information",
    "act now", "wire funds", "confidential", "reset your password", "security alert",
    "invoice overdue", "2FA", "government funds", "account locked"
]

SOCIAL_ENGINEERING_PHRASES = [
    "CEO", "HR", "IT admin", "urgent request", "confidential", "immediate attention",
    "must act", "strictly confidential", "executive", "wire transfer"
]

URL_REGEX = r"(https?://[^\s]+)"

false_negatives = []

# ========== DETECTION FUNCTION ==========
def analyze_email(file_path, true_label):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    text = data.get("email_text", "").lower()
    score = 0
    flags = []

    keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text]
    score += len(keyword_hits) * 10
    flags.extend(keyword_hits)

    soc_hits = [phrase for phrase in SOCIAL_ENGINEERING_PHRASES if phrase.lower() in text]
    score += len(soc_hits) * 12
    flags.extend(soc_hits)

    has_link = bool(re.search(URL_REGEX, text))
    if has_link:
        score += 20
        flags.append("link_detected")

    sender = data.get("sender", "").lower()
    if any(x in sender for x in ["support@", "no-reply@"]) and not any(trusted in sender for trusted in ["amazon", "paypal", "microsoft", "google", "apple"]):
        score += 15
        flags.append("suspicious_sender")

    subject = data.get("subject", "").lower()
    if any(x in subject for x in ["immediate", "action required", "account locked", "urgent", "verify"]):
        score += 10
        flags.append("urgent_subject")

    if re.search(r"^(dear\s+(user|customer|member|client))", text[:100]):
        score += 10
        flags.append("generic_greeting")

    attachments = data.get("attachments", [])
    if any(att.lower().endswith(ext) for att in attachments for ext in [".exe", ".html", ".htm", ".scr"]):
        score += 15
        flags.append("suspicious_attachment")

    if any(att.endswith(".htm") or att.endswith(".html") for att in attachments):
        score += 20
        flags.append("html_attachment")

    scammy_tlds = [".top", ".xyz", ".icu", ".click", ".info"]
    if any(sender.endswith(tld) for tld in scammy_tlds):
        score += 15
        flags.append("high_risk_tld")

    if re.search(r"[!?.]{3,}", text):
        score += 5
        flags.append("excessive_punctuation")

    ADDITIONAL_URGENCY = ["limited time", "account will be closed", "within 24 hours", "security breach", "your action is required"]
    urgency_hits = [kw for kw in ADDITIONAL_URGENCY if kw in text]
    if urgency_hits:
        score += len(urgency_hits) * 3
        flags.extend(urgency_hits)

    if len(keyword_hits) >= 2:
        score += 5

    BRANDS = ["amazon", "microsoft", "paypal", "fedex", "coinbase", "linkedin", "doe", "netflix"]
    for brand in BRANDS:
        if brand in text:
            score += 5
            flags.append(f"brand_mention:{brand}")

    if any(word in subject for word in ["invoice", "payment", "urgent", "alert", "resume", "offer"]):
        score += 5
        flags.append("suspicious_subject")

    if len(text.split()) < 20:
        score += 5
        flags.append("very_short_email")

    if len(flags) == 0 and has_link:
        score += 10
        flags.append("link_with_no_context")

    obfuscation_patterns = [r"c[l1!][i1!][c|k]", r"v[e3]r[i1]f[y]", r"a[c@]{2}ount"]
    for pattern in obfuscation_patterns:
        if re.search(pattern, text):
            score += 10
            flags.append("obfuscated_pattern")

    for word in ["click", "verify", "confirm", "account", "password"]:
        if text.count(word) > 2:
            score += 5
            flags.append(f"repeated:{word}")

    if has_link and len(text.split()) < 50:
        score += 10
        flags.append("short_email_with_link")

    for brand in BRANDS:
        if brand in text and brand not in sender:
            score += 10
            flags.append(f"brand_domain_mismatch:{brand}")

    if len(text.strip()) < 20 and any(w in subject for w in ["invoice", "payment", "alert", "resume", "urgent"]):
        score += 15
        flags.append("suspicious_subject_no_body")

    more_urgency = ["within 24 hours", "act fast", "your account will be suspended", "immediate action"]
    if any(phrase in text for phrase in more_urgency):
        score += 5
        flags.append("time_pressure_phrase")

    score = min(score, 100)
    is_phishing = score >= SCORE_THRESHOLD

    result = {
        "source_file": str(file_path.name),
        "score": score,
        "is_phishing": is_phishing,
        "actual_label": true_label,
        "flagged_keywords": flags,
        "contains_link": has_link,
        "num_words": len(text.split()),
        "num_links": len(re.findall(URL_REGEX, text)),
        "num_suspicious_keywords": len(keyword_hits),
        "num_social_engineering_hits": len(soc_hits),
        "brand_mentions": [b for b in BRANDS if b in text],
        "filename": file_path.name
    }

    if result["actual_label"] == "phishing" and not result["is_phishing"]:
        false_negatives.append(result)

    return result

# ========== MAIN FUNCTION ==========
def run_detection():
    all_emails = []
    phishing_files = list(PHISHING_DIR.glob("*.json"))
    benign_files = list(BENIGN_DIR.glob("*.json"))

    for file_path in phishing_files:
        result = analyze_email(file_path, "phishing")
        all_emails.append(result)

    for file_path in benign_files:
        result = analyze_email(file_path, "benign")
        all_emails.append(result)

    print(f"📂 Scanned {len(all_emails)} total emails ({len(phishing_files)} phishing + {len(benign_files)} benign)\n")

    TP = FP = TN = FN = 0
    false_positives = []
    true_positives = []
    true_negatives = []

    for result in all_emails:
        predicted_label = "phishing" if result["is_phishing"] else "benign"
        actual_label = result["actual_label"]
        result["predicted_label"] = predicted_label

        if predicted_label == "phishing" and actual_label == "phishing":
            TP += 1
            true_positives.append(result)
        elif predicted_label == "benign" and actual_label == "benign":
            TN += 1
            true_negatives.append(result)
        elif predicted_label == "phishing" and actual_label == "benign":
            FP += 1
            false_positives.append(result)
        elif predicted_label == "benign" and actual_label == "phishing":
            FN += 1
            false_negatives.append(result)

        out_file = OUTPUT_DIR / (result["source_file"].replace(".json", "_detected.json"))
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=4)

        print(f"✅ {result['source_file']} → Score: {result['score']} | Predicted: {predicted_label} | Actual: {actual_label}")

    # Save overall metrics
    summary = {
        "total_emails": len(all_emails),
        "true_positives": TP,
        "true_negatives": TN,
        "false_positives": FP,
        "false_negatives": FN,
        "precision": round(TP / (TP + FP), 3) if (TP + FP) > 0 else 0,
        "recall": round(TP / (TP + FN), 3) if (TP + FN) > 0 else 0,
        "accuracy": round((TP + TN) / len(all_emails), 3),
        "f1_score": round(2 * TP / (2 * TP + FP + FN), 3) if (2 * TP + FP + FN) > 0 else 0
    }

    with open(DETAILS_DIR / "summary_metrics.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=4)
    print(f"\n📈 Confusion Matrix Summary saved to {DETAILS_DIR}/summary_metrics.json")
    print(json.dumps(summary, indent=4))

    with open(DETAILS_DIR / "false_negatives.json", "w", encoding="utf-8") as f:
        json.dump(false_negatives, f, indent=4)
    print(f"⚠️  Saved {len(false_negatives)} false negatives to {DETAILS_DIR}/false_negatives.json")

    with open(DETAILS_DIR / "false_positives.json", "w", encoding="utf-8") as f:
        json.dump(false_positives, f, indent=4)
    print(f"⚠️  Saved {len(false_positives)} false positives to {DETAILS_DIR}/false_positives.json")

    # Save all detections in one summary file
    with open(DETAILS_DIR / "summary_detected.json", "w", encoding="utf-8") as f:
        json.dump(all_emails, f, indent=4)
    print(f"📄 All detection details saved to {DETAILS_DIR}/summary_detected.json")

def analyze_email_dict(email_data: dict, true_label="unknown", filename="uploaded_email.json"):
        """Analyze an email provided as a dictionary (used for Streamlit UI uploads)."""
        text = email_data.get("email_text", "").lower()
        temp_dir = Path("temp/")
        temp_dir.mkdir(parents=True, exist_ok=True)
        temp_path = temp_dir / filename

        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(email_data, f, indent=2)

        result = analyze_email(temp_path, true_label=true_label)

        try:
            temp_path.unlink()  # Delete temp file after use
        except Exception as e:
            print(f"Warning: Couldn't delete temp file: {e}")

        return result

if __name__ == "__main__":
    run_detection()