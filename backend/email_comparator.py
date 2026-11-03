
import re
import ipaddress
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
from difflib import SequenceMatcher

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from feature_extractor import FeatureExtractor


extractor = FeatureExtractor()


def parse_email(raw_bytes):
    message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    features = extractor.extract_from_eml_bytes(raw_bytes)

    return message, features


def normalize_email(value):
    return str(value or "").strip().lower()


def get_domain(value):
    value = normalize_email(value)

    match = re.search(r"@([a-z0-9.-]+\.[a-z]{2,})", value)

    return match.group(1) if match else ""


def get_urls(features):
    urls = features.get("urls", [])

    if isinstance(urls, str):
        return [urls] if urls else []

    return list(urls or [])


def content_similarity(message_a, message_b):
    subject_a = str(message_a.get("Subject", "") or "")
    subject_b = str(message_b.get("Subject", "") or "")

    body_a = str(message_a.get_body(preferencelist=("plain",)) or "")
    body_b = str(message_b.get_body(preferencelist=("plain",)) or "")

    # Extract readable body content
    body_a = body_a.get_content() if hasattr(body_a, "get_content") else body_a
    body_b = body_b.get_content() if hasattr(body_b, "get_content") else body_b

    text_a = subject_a + " " + str(body_a)
    text_b = subject_b + " " + str(body_b)

    if not text_a.strip() or not text_b.strip():
        return 0.0

    vectorizer = TfidfVectorizer()

    matrix = vectorizer.fit_transform([text_a, text_b])

    return round(float(cosine_similarity(matrix[0], matrix[1])[0][0] * 100), 2)


def compare_emails(raw_a, raw_b):
    message_a, features_a = parse_email(raw_a)
    message_b, features_b = parse_email(raw_b)

    from_a = normalize_email(message_a.get("From"))
    from_b = normalize_email(message_b.get("From"))

    reply_a = normalize_email(message_a.get("Reply-To"))
    reply_b = normalize_email(message_b.get("Reply-To"))

    return_a = normalize_email(message_a.get("Return-Path"))
    return_b = normalize_email(message_b.get("Return-Path"))

    domain_a = get_domain(from_a)
    domain_b = get_domain(from_b)

    urls_a = set(get_urls(features_a))
    urls_b = set(get_urls(features_b))

    similarity = content_similarity(message_a, message_b)

    differences = []

    if domain_a != domain_b:
        differences.append({
            "field": "Sender Domain",
            "reference": domain_a,
            "suspected": domain_b,
            "severity": "high"
        })

    if reply_a != reply_b:
        differences.append({
            "field": "Reply-To",
            "reference": reply_a or "Missing",
            "suspected": reply_b or "Missing",
            "severity": "high"
        })

    if return_a != return_b:
        differences.append({
            "field": "Return-Path",
            "reference": return_a or "Missing",
            "suspected": return_b or "Missing",
            "severity": "medium"
        })

    if urls_a != urls_b:
        differences.append({
            "field": "URLs",
            "reference": sorted(urls_a),
            "suspected": sorted(urls_b),
            "severity": "high"
        })

    return {
        "content_similarity_percent": similarity,
        "same_content": similarity >= 90,
        "identity_comparison": {
            "reference_from": from_a,
            "suspected_from": from_b,
            "reference_domain": domain_a,
            "suspected_domain": domain_b,
            "same_sender_domain": domain_a == domain_b
        },
        "differences": differences,
        "url_comparison": {
            "reference_url_count": len(urls_a),
            "suspected_url_count": len(urls_b),
            "common_urls": sorted(urls_a & urls_b),
            "only_reference": sorted(urls_a - urls_b),
            "only_suspected": sorted(urls_b - urls_a)
        },
        "forensic_evidence": {
            "reference": features_a.get("forensic_evidence", []),
            "suspected": features_b.get("forensic_evidence", [])
        },
        "verdict": (
            "NEEDS_REVIEW"
            if differences
            else "NO_SIGNIFICANT_DIFFERENCE_FOUND"
        ),
        "important_note": (
            "Content similarity and header differences are comparison signals, "
            "not proof of phishing. Independently verify authentication, "
            "sender identity, URLs and infrastructure before assigning a verdict."
        )
    }
