"""Utilities for normalizing emails from the research dataset schema.

The app originally expected a single `email_text` field.  These helpers allow the
same detection pipeline to work with the richer combined dataset schema used for
phishing, spam, benign, human-generated, and LLM-generated emails.
"""

from __future__ import annotations

import ast
import re
from html import unescape
from typing import Any, Dict, Iterable, List

URL_REGEX = r"https?://[^\s\"'<>]+"

CANONICAL_COLUMNS = [
    "email_id",
    "source_dataset",
    "source_file",
    "high_level_category",
    "subcategory",
    "sender",
    "receiver",
    "subject",
    "date",
    "body_text",
    "body_html",
    "urls",
    "url_count",
    "has_url",
    "has_attachment",
    "attachment_count",
    "has_image",
    "image_count",
    "received_headers",
    "authentication_results",
    "generation_type",
    "is_html",
    "is_plain_text",
]


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return value > 0
    value_str = str(value).strip().lower()
    return value_str in {"1", "true", "yes", "y", "present", "available"}


def _to_int(value: Any) -> int:
    try:
        if value is None or value == "":
            return 0
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and str(value) == "nan":
        return ""
    return str(value)


def strip_html(html: str) -> str:
    html = _safe_text(html)
    html = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html)
    html = re.sub(r"(?s)<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", unescape(html)).strip()


def parse_urls(value: Any) -> List[str]:
    """Parse URLs from a list, JSON-like string, or raw text."""
    if value is None:
        return []
    if isinstance(value, list):
        candidates = value
    else:
        text = _safe_text(value).strip()
        if not text:
            return []
        candidates = []
        if text.startswith("[") and text.endswith("]"):
            try:
                parsed = ast.literal_eval(text)
                if isinstance(parsed, list):
                    candidates = parsed
            except (ValueError, SyntaxError):
                candidates = []
        if not candidates:
            candidates = re.split(r"[,;\n\t ]+", text)

    urls = []
    for item in candidates:
        item_text = _safe_text(item).strip().strip("'\"")
        if item_text.startswith("http://") or item_text.startswith("https://"):
            urls.append(item_text)
        else:
            urls.extend(re.findall(URL_REGEX, item_text))
    return list(dict.fromkeys(urls))


def extract_urls_from_fields(*fields: str) -> List[str]:
    urls: List[str] = []
    for field in fields:
        urls.extend(re.findall(URL_REGEX, _safe_text(field)))
    return list(dict.fromkeys(urls))


def normalize_email_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Return a canonical email record compatible with the new schema and old app."""
    normalized = {column: record.get(column, "") for column in CANONICAL_COLUMNS}

    body_text = _safe_text(record.get("body_text") or record.get("email_text") or record.get("text") or "")
    body_html = _safe_text(record.get("body_html") or record.get("html") or "")
    html_as_text = strip_html(body_html)

    urls = parse_urls(record.get("urls"))
    if not urls:
        urls = extract_urls_from_fields(body_text, body_html)

    normalized.update(
        {
            "email_id": _safe_text(record.get("email_id") or record.get("id") or ""),
            "sender": _safe_text(record.get("sender") or record.get("from") or ""),
            "receiver": _safe_text(record.get("receiver") or record.get("to") or ""),
            "subject": _safe_text(record.get("subject") or ""),
            "date": _safe_text(record.get("date") or ""),
            "body_text": body_text,
            "body_html": body_html,
            "urls": urls,
            "url_count": _to_int(record.get("url_count")) or len(urls),
            "has_url": _to_bool(record.get("has_url")) or bool(urls),
            "has_attachment": _to_bool(record.get("has_attachment")),
            "attachment_count": _to_int(record.get("attachment_count")),
            "has_image": _to_bool(record.get("has_image")),
            "image_count": _to_int(record.get("image_count")),
            "received_headers": _safe_text(record.get("received_headers") or ""),
            "authentication_results": _safe_text(record.get("authentication_results") or ""),
            "generation_type": _safe_text(record.get("generation_type") or "not applicable"),
            "is_html": _to_bool(record.get("is_html")) or bool(body_html.strip()),
            "is_plain_text": _to_bool(record.get("is_plain_text")) or bool(body_text.strip()),
        }
    )

    analysis_text_parts = [
        f"From: {normalized['sender']}",
        f"To: {normalized['receiver']}",
        f"Subject: {normalized['subject']}",
        f"Date: {normalized['date']}",
        body_text,
        html_as_text,
        "URLs: " + ", ".join(urls) if urls else "",
        f"Authentication Results: {normalized['authentication_results']}",
        f"Received Headers: {normalized['received_headers']}",
    ]
    normalized["email_text"] = "\n".join(part for part in analysis_text_parts if part and part.strip())
    return normalized


def normalize_records(records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [normalize_email_record(record) for record in records]


def get_true_label(record: Dict[str, Any], default: str = "unknown") -> str:
    label = _safe_text(record.get("high_level_category") or record.get("true_label") or record.get("label") or default).lower()
    if label in {"phishing", "spam", "benign"}:
        return label
    return default
