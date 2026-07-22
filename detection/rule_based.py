import json
import re
from pathlib import Path
from urllib.parse import urlparse

try:
    from detection.schema_utils import normalize_email_record, get_true_label, URL_REGEX
except ImportError:
    from schema_utils import normalize_email_record, get_true_label, URL_REGEX

# ========== CONFIG ==========
PHISHING_DIR = Path("phishing_emails/")
BENIGN_DIR = Path("benign_emails/")
OUTPUT_DIR = Path("detection/output_rule/")
DETAILS_DIR = OUTPUT_DIR / "details"
SCORE_THRESHOLD = 50  # stronger threshold after weighted scoring redesign

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
DETAILS_DIR.mkdir(parents=True, exist_ok=True)

# Weak signals are capped so normal corporate/newsletter emails with links do not become phishing by themselves.
WEAK_SCORE_CAP = 20

TRUSTED_BRANDS = [
    "amazon", "microsoft", "paypal", "fedex", "coinbase", "linkedin",
    "netflix", "google", "apple", "bankofamerica", "chase", "wellsfargo"
]
HIGH_RISK_TLDS = [".top", ".xyz", ".icu", ".click", ".info", ".link", ".live", ".monster", ".cam"]
SHORTENER_DOMAINS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"]

CRITICAL_PHRASES = [
    "password", "reset your password", "verify your account", "confirm your account",
    "login to your account", "wire transfer", "wire funds", "gift card", "bank account",
    "ssn", "social security", "2fa", "mfa code", "one-time password", "otp"
]

MODERATE_PHRASES = [
    "account suspended", "account locked", "unauthorized", "security alert", "invoice overdue",
    "payment failed", "final notice", "limited time", "within 24 hours", "act now",
    "limited", "alert"
]

WEAK_PHRASES = [
    "click here", "urgent", "immediate attention", "hr", "ceo", "executive", "confidential",
    "verify", "confirm"
]

SPAM_PHRASES = {
    "free": 5,
    "winner": 5,
    "limited offer": 6,
    "special offer": 6,
    "discount": 5,
    "unsubscribe": 5,
    "promotion": 4,
    "deal": 4,
    "marketing": 4,
    "offer expires": 6,
    "buy now": 6,
    "click below": 5,
}

def _to_int(value, default=0):
    try:
        if value is None or value == "":
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _domain_from_email(value: str) -> str:
    match = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", value or "")
    return match.group(1).lower() if match else ""


def _domain_from_url(url: str) -> str:
    try:
        parsed = urlparse(url)
        return (parsed.netloc or "").lower().split(":")[0]
    except Exception:
        return ""


def _has_ip_domain(domain: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain or ""))


def _parse_authentication(auth_results: str):
    auth = (auth_results or "").lower()
    findings = []
    for protocol in ["spf", "dkim", "dmarc"]:
        if re.search(rf"{protocol}\s*=\s*(fail|softfail|permerror|temperror)", auth):
            findings.append((f"{protocol.upper()} fail", 25, "authentication", "critical"))
        elif re.search(rf"{protocol}\s*=\s*pass", auth):
            findings.append((f"{protocol.upper()} pass", -5, "authentication", "benign"))
    if "fail" in auth and not findings:
        findings.append(("authentication failure", 18, "authentication", "critical"))
    return findings


def _add_indicator(indicators, category, rule, weight, evidence="", strength="moderate"):

    indicators.append({
        "category": category,
        "rule": rule,
        "weight": weight,
        "evidence": evidence,
        "strength": strength,
    })

def build_atomic_indicators(
        
    data: dict,
    indicators: list[dict],
    brands_in_text: list[str],
    has_link: bool,
) -> dict[str, bool]:
    """
    Convert detailed weighted-rule findings into simple True/False
    indicators for rule-association analysis.

    This function does not change the weighted heuristic score.
    """

    triggered_rules = {
        str(indicator.get("rule", "")).strip().lower()
        for indicator in indicators
        if indicator.get("weight", 0) > 0
    }

    text = str(data.get("email_text", "")).lower()

    credential_terms = [
        "password",
        "reset your password",
        "verify your account",
        "confirm your account",
        "login to your account",
        "sign in to your account",
        "2fa",
        "mfa code",
        "one-time password",
        "otp",
    ]

    urgency_terms = [
        "urgent",
        "immediate",
        "immediately",
        "immediate attention",
        "action required",
        "act now",
        "within 24 hours",
        "final notice",
        "account suspended",
        "account locked",
        "limited time",
    ]

    payment_terms = [
        "wire transfer",
        "wire funds",
        "payment",
        "invoice",
        "gift card",
        "bank account",
        "pay immediately",
        "payment failed",
        "invoice overdue",
    ]

    executive_terms = [
    "ceo",
    "chief executive officer",
    "chief executive",
    "cfo",
    "chief financial officer",
    "company president",
    "vice president",
    ]

    immediate_reply_terms = [
        "reply immediately",
        "respond immediately",
        "reply now",
        "respond now",
        "reply as soon as possible",
    ]

    suspicious_url_rules = {
        "high-risk tld",
        "shortened url",
        "url uses ip address",
        "obfuscated url",
    }

    dangerous_attachment_rules = {
        "dangerous attachment reference",
        "suspicious attachment reference",
    }

    return {
        "has_url": bool(has_link),

        "suspicious_url": any(
            rule in triggered_rules
            for rule in suspicious_url_rules
        ),

        "credential_request": any(
            term in text
            for term in credential_terms
        ),

        "urgency": (
            any(term in text for term in urgency_terms)
            or "urgent subject" in triggered_rules
        ),

        "brand_mention": bool(brands_in_text),

        "sender_mismatch": any(
            rule.startswith("brand domain mismatch:")
            for rule in triggered_rules
        ),

        "authentication_failure": any(
            rule in {
                "spf fail",
                "dkim fail",
                "dmarc fail",
                "authentication failure",
            }
            for rule in triggered_rules
        ),

        "attachment_present": bool(
            data.get("has_attachment")
            or _to_int(data.get("attachment_count")) > 0
        ),

        "dangerous_attachment": any(
            rule in triggered_rules
            for rule in dangerous_attachment_rules
        ),

        "image_present": bool(
            data.get("has_image")
            or _to_int(data.get("image_count")) > 0
        ),

        "payment_request": any(
            term in text
            for term in payment_terms
        ),

        "executive_reference": any(
            term in text
            for term in executive_terms
        ),

        "immediate_reply_request": any(
            term in text
            for term in immediate_reply_terms
        ),

        "generic_greeting": (
            "generic greeting" in triggered_rules
        ),

        "short_email_with_link": (
            "short email with link" in triggered_rules
        ),

        "multiple_urls": (
            "multiple urls" in triggered_rules
        ),

        "obfuscated_content": (
            "obfuscated pattern" in triggered_rules
        ),

        "spam_marketing_language": any(
            indicator.get("category") == "spam_marketing"
            and indicator.get("weight", 0) > 0
            for indicator in indicators
        ),
    }


# ========== DETECTION FUNCTION ==========
def analyze_email(file_path, true_label=None):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    data = normalize_email_record(data)
    true_label = true_label or get_true_label(data)

    text = data.get("email_text", "").lower()
    body_text = data.get("body_text", "").lower()
    body_html = data.get("body_html", "").lower()
    sender = data.get("sender", "").lower()
    subject = data.get("subject", "").lower()
    urls = data.get("urls", []) or []
    auth_results = data.get("authentication_results", "").lower()
    received_headers = data.get("received_headers", "").lower()
    sender_domain = _domain_from_email(sender)

    indicators = []

    # 1. Authentication features
    for rule, weight, category, strength in _parse_authentication(auth_results):
        _add_indicator(indicators, category, rule, weight, auth_results[:160], strength)

    # 2. Sender and domain analysis
    if any(x in sender for x in ["support@", "no-reply@", "noreply@"] ) and not any(t in sender for t in TRUSTED_BRANDS):
        _add_indicator(indicators, "sender_domain", "suspicious sender alias", 10, sender, "moderate")

    brands_in_text = [brand for brand in TRUSTED_BRANDS if brand in text]
    for brand in brands_in_text:
        if sender_domain and brand not in sender_domain:
            _add_indicator(indicators, "sender_domain", f"brand domain mismatch:{brand}", 12, f"sender={sender_domain}", "moderate")
        else:
            _add_indicator(indicators, "sender_domain", f"brand mention:{brand}", 1, brand, "weak")

    if re.search(r"^(dear\s+(user|customer|member|client))", body_text[:120] or text[:120]):
        _add_indicator(indicators, "content", "generic greeting", 2, "Dear user/customer", "weak")

    # 3. URL and routing analysis
    has_link = bool(data.get("has_url")) or bool(urls) or bool(re.search(URL_REGEX, text))
    url_count = _to_int(data.get("url_count"), len(urls)) or len(urls)

    if has_link:
        _add_indicator(indicators, "url_routing", "link detected", 2, str(url_count), "weak")

    if url_count >= 3:
        _add_indicator(indicators, "url_routing", "multiple URLs", 3, str(url_count), "weak")

    for url in urls:
        domain = _domain_from_url(url)
        lower_url = url.lower()
        if any(domain.endswith(tld) for tld in HIGH_RISK_TLDS):
            _add_indicator(indicators, "url_routing", "high-risk TLD", 12, url, "moderate")
        if any(
            domain == shortener
            or domain.endswith(f".{shortener}")
            for shortener in SHORTENER_DOMAINS
        ):
            _add_indicator(indicators, "url_routing", "shortened URL", 10, url, "moderate")
        if _has_ip_domain(domain):
            _add_indicator(indicators, "url_routing", "URL uses IP address", 18, url, "critical")
        if "%" in lower_url or "@" in lower_url or "xn--" in lower_url:
            _add_indicator(indicators, "url_routing", "obfuscated URL", 15, url, "moderate")

    if received_headers and any(x in received_headers for x in ["unknown", "suspicious", "localhost"]):
        _add_indicator(indicators, "url_routing", "suspicious received header", 3, received_headers[:120], "weak")

    # 4. Social engineering and content intent
    for phrase in CRITICAL_PHRASES:
        if phrase in text:
            _add_indicator(indicators, "social_engineering", phrase, 18, phrase, "critical")

    for phrase in MODERATE_PHRASES:
        if phrase in text:
            _add_indicator(indicators, "social_engineering", phrase, 9, phrase, "moderate")

    for phrase in WEAK_PHRASES:
        if phrase in text:
            _add_indicator(indicators, "social_engineering", phrase, 2, phrase, "weak")

    for phrase, weight in SPAM_PHRASES.items():
        if phrase in text:
            _add_indicator(
                indicators,
                "spam_marketing",
                phrase,
                weight,
                phrase,
                "moderate"
            )

    if any(word in subject for word in ["immediate", "action required", "account locked", "urgent", "verify"]):
        _add_indicator(indicators, "content", "urgent subject", 7, subject, "moderate")

    if re.search(r"[!?.]{3,}", text):
        _add_indicator(indicators, "content", "excessive punctuation", 4, "!!!/???", "weak")

    if len(text.split()) < 20:
        _add_indicator(indicators, "content", "very short email", 2, f"{len(text.split())} words", "weak")

    if has_link and len(text.split()) < 50:
        _add_indicator(indicators, "content", "short email with link", 8, f"{len(text.split())} words", "moderate")

    obfuscation_patterns = [r"c[l1!][i1!][c|k]", r"v[e3]r[i1]f[y]", r"a[c@]{2}ount"]
    for pattern in obfuscation_patterns:
        if re.search(pattern, text):
            _add_indicator(indicators, "content", "obfuscated pattern", 10, pattern, "moderate")

    # 5. Attachment/image indicators
    attachment_count = _to_int(data.get("attachment_count"))
    if data.get("has_attachment") or attachment_count > 0:
        _add_indicator(indicators, "attachment", "attachment present", 2, str(attachment_count), "weak")

    if data.get("has_image") or _to_int(data.get("image_count")) > 0:
        _add_indicator(indicators, "attachment", "image present", 1, str(data.get("image_count", 0)), "weak")

    if any(ext in body_html for ext in [".exe", ".scr", ".bat", ".cmd", ".js"]):
        _add_indicator(indicators, "attachment", "dangerous attachment reference", 16, "executable/script reference", "critical")
    elif any(ext in body_html for ext in [".html", ".htm"]):
        _add_indicator(indicators, "attachment", "suspicious attachment reference", 10, "HTML attachment reference", "moderate")

    # Weighted scoring with weak-signal cap.
    critical_score = sum(i["weight"] for i in indicators if i["strength"] == "critical" and i["weight"] > 0)
    moderate_score = sum(i["weight"] for i in indicators if i["strength"] == "moderate" and i["weight"] > 0)
    weak_score = sum(i["weight"] for i in indicators if i["strength"] == "weak" and i["weight"] > 0)
    benign_adjustment = sum(i["weight"] for i in indicators if i["weight"] < 0)

    score = critical_score + moderate_score + min(weak_score, WEAK_SCORE_CAP) + benign_adjustment
    score = max(0, min(int(round(score)), 100))
    is_phishing = score >= SCORE_THRESHOLD

    category_scores = {}
    for indicator in indicators:
        category_scores[indicator["category"]] = category_scores.get(indicator["category"], 0) + indicator["weight"]

    positive_category_scores = {
        category: max(score, 0)
        for category, score in category_scores.items()
    }

    total_positive_category_score = sum(positive_category_scores.values())

    category_score_percentages = {
        category: round((score / total_positive_category_score) * 100, 2)
        if total_positive_category_score > 0 else 0
        for category, score in positive_category_scores.items()
    }

    unique_flags = []
    seen = set()

    for indicator in indicators:
        rule = indicator["rule"]

        if rule not in seen and indicator["weight"] > 0:
            unique_flags.append(rule)
            seen.add(rule)

    # Convert the detailed rule findings into simple binary indicators.
    # These will later be used by the rule-association method.
    atomic_indicators = build_atomic_indicators(
        data=data,
        indicators=indicators,
        brands_in_text=brands_in_text,
        has_link=has_link,
    )

    # Standardized prediction value used across all detection methods.
    predicted_label = "phishing" if is_phishing else "benign"

    # The true label is used only after prediction for evaluation.
    normalized_true_label = (
        str(true_label).strip().lower()
        if true_label is not None
        else "unknown"
    )

    # Spam is treated as malicious in the current evaluation workflow.
    if normalized_true_label == "spam":
        expected_prediction = "phishing"
    elif normalized_true_label in {"phishing", "benign"}:
        expected_prediction = normalized_true_label
    else:
        expected_prediction = None

    prediction_correct = (
        predicted_label == expected_prediction
        if expected_prediction is not None
        else None
    )

    result = {
        # Common fields that will also be used by the association and LLM methods.
        "method": "weighted_heuristic",
        "source_file": str(Path(file_path).name),
        "email_id": data.get("email_id", ""),
        "source_dataset": data.get("source_dataset", ""),
        "high_level_category": data.get("high_level_category", ""),
        "subcategory": data.get("subcategory", ""),
        "generation_type": data.get("generation_type", ""),

        # Original weighted heuristic outputs.
        "score": score,
        "rule_confidence": round(score / 100, 3),
        "risk_level": (
            "high"
            if score >= 70
            else "medium"
            if score >= 40
            else "low"
        ),
        "is_phishing": is_phishing,

        # Standardized outputs used by every detection method.
        "prediction": predicted_label,
        "confidence": round(score / 100, 3),

        # Ground-truth evaluation fields.
        "actual_label": normalized_true_label,
        "correct": prediction_correct,
        "flagged_keywords": unique_flags,

        # Detailed weighted-rule findings.
        "indicators": indicators,

        # Simplified findings for the new rule-association method.
        "atomic_indicators": atomic_indicators,

        "category_scores": category_scores,
        "category_score_percentages": category_score_percentages,
        "contains_link": has_link,
        "num_words": len(text.split()),
        "num_links": url_count,
        "num_suspicious_keywords": len([p for p in CRITICAL_PHRASES + MODERATE_PHRASES + WEAK_PHRASES if p in text]),
        "num_social_engineering_hits": len([i for i in indicators if i["category"] == "social_engineering"]),
        "num_spam_hits": len([i for i in indicators if i["category"] == "spam_marketing"]),
        "brand_mentions": brands_in_text,
        "has_attachment": bool(data.get("has_attachment")),
        "attachment_count": attachment_count,
        "has_image": bool(data.get("has_image")),
        "image_count": _to_int(data.get("image_count")),
        "is_html": bool(data.get("is_html")),
        "is_plain_text": bool(data.get("is_plain_text")),
        "filename": Path(file_path).name,
    }
    return result


# ========== MAIN FUNCTION ==========
def run_detection():
    all_emails = []
    phishing_files = list(PHISHING_DIR.glob("*.json"))
    benign_files = list(BENIGN_DIR.glob("*.json"))

    for file_path in phishing_files:
        all_emails.append(analyze_email(file_path, "phishing"))

    for file_path in benign_files:
        all_emails.append(analyze_email(file_path, "benign"))

    print(f"📂 Scanned {len(all_emails)} total emails ({len(phishing_files)} phishing + {len(benign_files)} benign)\n")

    TP = FP = TN = FN = 0
    false_positives = []
    false_negatives = []

    for result in all_emails:
        predicted_label = result["prediction"]
        actual_label = result["actual_label"]

        # Keep this field temporarily for compatibility with old output files.
        result["predicted_label"] = predicted_label

        actual_is_malicious = actual_label in {"phishing", "spam"}
        pred_is_malicious = predicted_label == "phishing"

        if pred_is_malicious and actual_is_malicious:
            TP += 1
        elif not pred_is_malicious and not actual_is_malicious:
            TN += 1
        elif pred_is_malicious and not actual_is_malicious:
            FP += 1
            false_positives.append(result)
        elif not pred_is_malicious and actual_is_malicious:
            FN += 1
            false_negatives.append(result)

        out_file = OUTPUT_DIR / (result["source_file"].replace(".json", "_detected.json"))
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=4)

        correctness = result.get("correct")

        if correctness is True:
            status = "Correct"
        elif correctness is False:
            status = "Incorrect"
        else:
            status = "Not evaluated"

        print(
            f"✅ {result['source_file']} "
            f"→ Score: {result['score']} "
            f"| Predicted: {predicted_label} "
            f"| Actual: {actual_label} "
            f"| Result: {status}"
        )


    total = TP + TN + FP + FN
    summary = {
        "total_emails": total,
        "true_positives": TP,
        "true_negatives": TN,
        "false_positives": FP,
        "false_negatives": FN,
        "precision": round(TP / (TP + FP), 3) if (TP + FP) else 0,
        "recall": round(TP / (TP + FN), 3) if (TP + FN) else 0,
        "accuracy": round((TP + TN) / total, 3) if total else 0,
        "f1_score": round(2 * TP / (2 * TP + FP + FN), 3) if (2 * TP + FP + FN) else 0,
    }

    with open(DETAILS_DIR / "summary_metrics.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=4)
    with open(DETAILS_DIR / "false_positives.json", "w", encoding="utf-8") as f:
        json.dump(false_positives, f, indent=4)
    with open(DETAILS_DIR / "false_negatives.json", "w", encoding="utf-8") as f:
        json.dump(false_negatives, f, indent=4)
    with open(DETAILS_DIR / "summary_detected.json", "w", encoding="utf-8") as f:
        json.dump(all_emails, f, indent=4)

    print(f"\n📈 Summary written to {DETAILS_DIR}/summary_metrics.json")
    print(json.dumps(summary, indent=4))


def analyze_email_dict(email_data: dict, true_label="unknown", filename="uploaded_email.json"):
    """Analyze an email provided as a dictionary, used for Streamlit uploads."""
    email_data = normalize_email_record(email_data)
    if true_label == "unknown":
        true_label = get_true_label(email_data)

    temp_dir = Path("temp/")
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_path = temp_dir / filename

    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(email_data, f, indent=2)

    result = analyze_email(temp_path, true_label=true_label)

    try:
        temp_path.unlink()
    except Exception as e:
        print(f"Warning: couldn't delete temp file: {e}")

    return result


if __name__ == "__main__":
    run_detection()
