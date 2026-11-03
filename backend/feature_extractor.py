"""
MATSYA Cyber Forensics Engine — Advanced Email Feature Extractor
Extracts multi-dimensional feature representations from RFC-822 .eml emails
combining raw text, structured headers, authentication signals (SPF/DKIM/DMARC),
URL telemetry, attachment signatures, BEC indicators, and forensic evidence.
"""

from email import policy
from email.parser import BytesParser
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlparse
import ipaddress
import os
import re

IPV4_PATTERN = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
URL_PATTERN = re.compile(r"""https?://[^\s<>"')\]]+""", re.IGNORECASE)

FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "protonmail.com", "proton.me", "mail.com", "zoho.com", "icloud.com",
    "yandex.com", "gmx.com", "live.com"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "buzz", "club", "work", "icu", "surf", "cam", "bid",
    "loan", "click", "rest", "stream", "gq", "cf", "ml", "ga", "tk", "support"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "rebrand.ly", "goo.gl", "tiny.cc"
}

SUSPICIOUS_URL_KEYWORDS = [
    "login", "verify", "account", "update", "banking", "secure", "wallet",
    "credential", "signin", "auth", "wire", "invoice", "confirm", "portal",
    "support", "password", "session", "suspended", "security"
]

URGENCY_KEYWORDS = [
    "urgent", "immediately", "immediate", "action required", "within 24 hours",
    "account suspended", "suspended", "expire", "expires", "critical",
    "act now", "final notice", "unauthorized", "suspension", "terminated",
    "security alert", "warning", "compromised", "verify your identity"
]

FEAR_KEYWORDS = [
    "lawsuit", "police", "legal action", "arrest", "penalty", "violation",
    "breach", "court", "attorney", "subpoena", "sanction"
]

FINANCIAL_KEYWORDS = [
    "invoice", "wire transfer", "payment", "bank", "beneficiary",
    "account number", "swift", "remittance", "payroll", "direct deposit",
    "routing number", "funds", "balance", "crypto", "bitcoin", "usdt",
    "gift card", "overdue", "voucher", "billing", "vendor"
]

EXECUTIVE_KEYWORDS = [
    "ceo", "cfo", "coo", "chief executive", "director", "president",
    "confidential request", "wire immediately", "keep this between us",
    "i'm in a meeting", "are you at your desk", "quick favor"
]

SUSPICIOUS_ATTACHMENT_EXTENSIONS = {
    ".exe", ".scr", ".iso", ".img", ".vbs", ".js", ".bat", ".cmd",
    ".ps1", ".hta", ".docm", ".xlsm", ".pptm", ".jar", ".wsf", ".cpl",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".ace"
}

EXECUTABLE_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".hta", ".ps1"}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img"}


def extract_domain(email_or_url: str) -> str:
    """Extract clean domain name from email or URL string."""
    if not email_or_url:
        return ""
    val = str(email_or_url).strip().lower()
    if "@" in val:
        val = val.split("@")[-1].strip(">").strip(")")
    elif val.startswith(("http://", "https://")):
        try:
            val = urlparse(val).hostname or ""
        except Exception:
            val = ""
    val = re.sub(r"[^\w.-]", "", val).strip(".")
    return val


def is_public_ipv4(value: str) -> bool:
    """Check if string is a globally routable IPv4 address."""
    try:
        ip = ipaddress.ip_address(str(value).strip())
        return ip.version == 4 and ip.is_global
    except ValueError:
        return False


class FeatureExtractor:
    """
    Forensic email feature extractor generating unified NLP text representations,
    standardized numerical vector arrays, and deterministic forensic evidence.
    """

    FEATURE_NAMES = [
        # Identity and Domain
        "sender_reply_to_mismatch",
        "sender_return_path_mismatch",
        "sender_name_spoofing",
        "sender_domain_is_freemail",
        "sender_domain_is_suspicious_tld",
        "sender_domain_length",
        "sender_domain_subdomain_count",
        "sender_has_ip_domain",
        # Authentication Results
        "spf_pass",
        "spf_fail",
        "spf_softfail",
        "spf_missing",
        "dkim_pass",
        "dkim_fail",
        "dkim_missing",
        "dmarc_pass",
        "dmarc_fail",
        "dmarc_missing",
        "auth_failure_count",
        # URL Telemetry
        "url_count",
        "domain_count",
        "url_ip_host_count",
        "url_shortener_count",
        "url_suspicious_keywords_count",
        "url_max_path_length",
        "url_https_ratio",
        "url_has_at_symbol",
        "url_has_punycode",
        "url_max_subdomains",
        # Linguistic & Social Engineering Signals
        "urgency_keywords_count",
        "threat_fear_keywords_count",
        "psychological_pressure_score",
        # Financial & BEC Signals
        "financial_keywords_count",
        "executive_keywords_count",
        "bec_composite_score",
        # Attachment Telemetry
        "attachment_count",
        "suspicious_attachment_count",
        "double_extension_count",
        "attachment_total_size_kb",
        "has_executable_attachment",
        "has_archive_attachment",
        "has_office_macro_attachment",
        # Email Headers & Structural Signals
        "header_count",
        "received_hop_count",
        "has_originating_ip",
        "originating_ip_is_public",
        "has_x_mailer",
        "subject_length",
        "subject_caps_ratio",
        "subject_exclamation_count",
        "body_length",
        "body_caps_ratio",
        "html_part_count",
        "plain_part_count",
        "is_html_only",
    ]

    @classmethod
    def get_feature_names(cls) -> list[str]:
        return list(cls.FEATURE_NAMES)

    def extract_from_eml_bytes(self, raw_bytes: bytes) -> dict:
        """Parse raw RFC-822 bytes and return complete feature extraction dossier."""
        try:
            message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        except Exception:
            # Fallback permissive parsing
            message = BytesParser().parsebytes(raw_bytes)
        return self.extract_from_email_message(message, raw_bytes)

    def extract_from_email_message(self, message, raw_bytes: bytes = b"") -> dict:
        """Extract multi-modal feature set from an email.message.Message object."""
        subject = str(message.get("Subject", "") or "")
        sender = str(message.get("From", "") or "")
        reply_to = str(message.get("Reply-To", "") or "")
        return_path = str(message.get("Return-Path", "") or "")
        message_id = str(message.get("Message-ID", "") or "")
        auth_results = str(message.get("Authentication-Results", "") or "")
        rec_spf = str(message.get("Received-SPF", "") or "")
        x_orig_ip = str(message.get("X-Originating-IP", "") or "")

        # Extract headers dictionary
        headers = {}
        for k, v in message.items():
            headers[str(k).lower()] = str(v)

        received_headers = message.get_all("Received", []) or []

        # Extract body parts and attachments
        body_parts = []
        html_part_count = 0
        plain_part_count = 0
        attachments = []

        for part in message.walk():
            content_type = part.get_content_type()
            disposition = str(part.get_content_disposition() or "")
            filename = part.get_filename() or ""

            if disposition == "attachment" or filename:
                payload = part.get_payload(decode=True) or b""
                size_kb = round(len(payload) / 1024.0, 2)
                f_hash = sha256(payload).hexdigest() if payload else ""
                ext = Path(filename).suffix.lower()
                is_suspicious = ext in SUSPICIOUS_ATTACHMENT_EXTENSIONS
                is_exec = ext in EXECUTABLE_EXTENSIONS
                is_macro = ext in MACRO_EXTENSIONS
                is_archive = ext in ARCHIVE_EXTENSIONS
                is_double_ext = bool(re.search(r"\.[a-zA-Z0-9]{2,4}\.[a-zA-Z0-9]{2,4}$", filename))

                attachments.append({
                    "filename": filename,
                    "content_type": content_type,
                    "size_kb": size_kb,
                    "sha256": f_hash,
                    "extension": ext,
                    "is_suspicious": is_suspicious,
                    "is_executable": is_exec,
                    "is_macro": is_macro,
                    "is_archive": is_archive,
                    "is_double_extension": is_double_ext,
                })
            else:
                if content_type == "text/plain":
                    plain_part_count += 1
                    try:
                        content = part.get_content()
                        if isinstance(content, str):
                            body_parts.append(content)
                    except Exception:
                        pass
                elif content_type == "text/html":
                    html_part_count += 1
                    try:
                        content = part.get_content()
                        if isinstance(content, str):
                            # Strip basic HTML tags for text representation
                            cleaned = re.sub(r"<[^>]+>", " ", content)
                            body_parts.append(cleaned)
                    except Exception:
                        pass

        body = "\n".join(body_parts).strip()
        if not body and raw_bytes:
            # Fallback raw decode
            try:
                raw_text = raw_bytes.decode("utf-8", errors="replace")
                body = raw_text[:20000]
            except Exception:
                pass

        return self.extract_from_dict({
            "subject": subject,
            "body": body,
            "sender": sender,
            "reply_to": reply_to,
            "return_path": return_path,
            "message_id": message_id,
            "authentication_results": f"{auth_results} {rec_spf}".strip(),
            "x_originating_ip": x_orig_ip,
            "received_headers": received_headers,
            "headers_dict": headers,
            "html_part_count": html_part_count,
            "plain_part_count": plain_part_count,
            "attachments": attachments,
        })

    def extract_from_dict(self, data: dict) -> dict:
        """
        Extract features from dictionary inputs (used by EML parser, CSV loader, or API).
        """
        subject = str(data.get("subject", "") or "")
        body = str(data.get("body", "") or "")
        sender = str(data.get("sender", "") or "")
        reply_to = str(data.get("reply_to", "") or "")
        return_path = str(data.get("return_path", "") or "")
        auth_raw = str(data.get("authentication_results", "") or "").lower()
        x_orig_ip = str(data.get("x_originating_ip", "") or "")
        rec_headers = data.get("received_headers") or []
        attachments = data.get("attachments") or []

        # Parse URLs from provided urls list or regex match over subject + body
        urls = list(data.get("urls") or [])
        if not urls:
            combined_text_for_urls = f"{subject}\n{body}"
            urls = sorted(set(URL_PATTERN.findall(combined_text_for_urls)))

        # Also parse attachment names if provided as CSV string
        if not attachments and data.get("attachment_names"):
            att_names = [a.strip() for a in str(data.get("attachment_names")).split(",") if a.strip()]
            for name in att_names:
                ext = Path(name).suffix.lower()
                attachments.append({
                    "filename": name,
                    "content_type": "application/octet-stream",
                    "size_kb": 0.0,
                    "sha256": "",
                    "extension": ext,
                    "is_suspicious": ext in SUSPICIOUS_ATTACHMENT_EXTENSIONS,
                    "is_executable": ext in EXECUTABLE_EXTENSIONS,
                    "is_macro": ext in MACRO_EXTENSIONS,
                    "is_archive": ext in ARCHIVE_EXTENSIONS,
                    "is_double_extension": bool(re.search(r"\.[a-zA-Z0-9]{2,4}\.[a-zA-Z0-9]{2,4}$", name)),
                })

        # --- Sender & Domain Telemetry ---
        sender_domain = extract_domain(sender)
        reply_to_domain = extract_domain(reply_to)
        return_path_domain = extract_domain(return_path)

        sender_reply_to_mismatch = 1.0 if (sender_domain and reply_to_domain and sender_domain != reply_to_domain) else 0.0
        sender_return_path_mismatch = 1.0 if (sender_domain and return_path_domain and sender_domain != return_path_domain) else 0.0

        # Executive / Brand spoofing check in sender display name
        sender_lower = sender.lower()
        display_name_spoof = 0.0
        known_brands = ["microsoft", "google", "apple", "paypal", "bank of america", "chase", "dhl", "fedex", "amazon"]
        for brand in known_brands:
            if brand in sender_lower and brand not in sender_domain:
                display_name_spoof = 1.0
                break
        for exec_title in ["ceo", "cfo", "director", "executive"]:
            if exec_title in sender_lower and sender_domain in FREEMAIL_DOMAINS:
                display_name_spoof = 1.0
                break

        sender_domain_is_freemail = 1.0 if sender_domain in FREEMAIL_DOMAINS else 0.0
        tld = sender_domain.split(".")[-1] if "." in sender_domain else ""
        sender_domain_is_suspicious_tld = 1.0 if tld in SUSPICIOUS_TLDS else 0.0
        sender_domain_length = float(len(sender_domain))
        sender_domain_subdomain_count = float(max(0, sender_domain.count(".") - 1)) if sender_domain else 0.0
        sender_has_ip_domain = 1.0 if bool(IPV4_PATTERN.search(sender_domain)) else 0.0

        # --- Authentication Signals (SPF, DKIM, DMARC) ---
        spf_pass = 1.0 if "spf=pass" in auth_raw or "pass (spf" in auth_raw else 0.0
        spf_fail = 1.0 if "spf=fail" in auth_raw or "spf=permerror" in auth_raw or "fail (spf" in auth_raw else 0.0
        spf_softfail = 1.0 if "spf=softfail" in auth_raw or "spf=neutral" in auth_raw else 0.0
        spf_missing = 1.0 if ("spf=" not in auth_raw and "spf" not in auth_raw) else 0.0

        dkim_pass = 1.0 if "dkim=pass" in auth_raw else 0.0
        dkim_fail = 1.0 if "dkim=fail" in auth_raw or "dkim=permerror" in auth_raw else 0.0
        dkim_missing = 1.0 if "dkim=" not in auth_raw else 0.0

        dmarc_pass = 1.0 if "dmarc=pass" in auth_raw else 0.0
        dmarc_fail = 1.0 if "dmarc=fail" in auth_raw else 0.0
        dmarc_missing = 1.0 if "dmarc=" not in auth_raw else 0.0

        auth_failure_count = float(spf_fail + dkim_fail + dmarc_fail + (0.5 * spf_softfail))

        # --- URL Analysis ---
        url_count = float(len(urls))
        extracted_domains = set()
        url_ip_host_count = 0.0
        url_shortener_count = 0.0
        url_suspicious_keywords_count = 0.0
        url_max_path_length = 0.0
        https_count = 0.0
        url_has_at_symbol = 0.0
        url_has_punycode = 0.0
        url_max_subdomains = 0.0

        for u in urls:
            try:
                parsed = urlparse(u)
                host = (parsed.hostname or "").lower()
                if host:
                    extracted_domains.add(host)
                    if bool(IPV4_PATTERN.fullmatch(host)):
                        url_ip_host_count += 1.0
                    if any(shortener in host for shortener in URL_SHORTENERS):
                        url_shortener_count += 1.0
                    if "xn--" in host:
                        url_has_punycode = 1.0
                    sub_count = max(0, host.count(".") - 1)
                    if sub_count > url_max_subdomains:
                        url_max_subdomains = float(sub_count)

                if "@" in u:
                    url_has_at_symbol = 1.0
                if u.lower().startswith("https://"):
                    https_count += 1.0

                path_len = len(parsed.path or "")
                if path_len > url_max_path_length:
                    url_max_path_length = float(path_len)

                u_lower = u.lower()
                for kw in SUSPICIOUS_URL_KEYWORDS:
                    if kw in u_lower:
                        url_suspicious_keywords_count += 1.0
            except Exception:
                pass

        domain_count = float(len(extracted_domains))
        url_https_ratio = (https_count / url_count) if url_count > 0 else 1.0

        # --- Linguistic Indicators ---
        full_text_lower = f"{subject} {body}".lower()

        urgency_count = sum(1.0 for kw in URGENCY_KEYWORDS if kw in full_text_lower)
        fear_count = sum(1.0 for kw in FEAR_KEYWORDS if kw in full_text_lower)
        psychological_pressure_score = (urgency_count * 1.5) + (fear_count * 2.0)

        financial_count = sum(1.0 for kw in FINANCIAL_KEYWORDS if kw in full_text_lower)
        executive_count = sum(1.0 for kw in EXECUTIVE_KEYWORDS if kw in full_text_lower)

        bec_score = 0.0
        if financial_count > 0 and (executive_count > 0 or urgency_count > 0):
            bec_score += 2.0
        if sender_reply_to_mismatch or sender_return_path_mismatch:
            bec_score += 2.5
        if display_name_spoof:
            bec_score += 2.0

        # --- Attachment Telemetry ---
        att_count = float(len(attachments))
        suspicious_att_count = sum(1.0 for a in attachments if a.get("is_suspicious"))
        double_ext_count = sum(1.0 for a in attachments if a.get("is_double_extension"))
        att_total_size = sum(float(a.get("size_kb", 0.0)) for a in attachments)
        has_exec_att = 1.0 if any(a.get("is_executable") for a in attachments) else 0.0
        has_archive_att = 1.0 if any(a.get("is_archive") for a in attachments) else 0.0
        has_macro_att = 1.0 if any(a.get("is_macro") for a in attachments) else 0.0

        # --- Header & Structural Telemetry ---
        headers_dict = data.get("headers_dict") or {}
        header_count = float(len(headers_dict)) if headers_dict else 10.0
        hop_count = float(len(rec_headers))

        # Check originating IP
        orig_ip = ""
        if x_orig_ip:
            found = IPV4_PATTERN.findall(x_orig_ip)
            if found:
                orig_ip = found[0]
        if not orig_ip and rec_headers:
            for h in reversed(rec_headers):
                ips = IPV4_PATTERN.findall(str(h))
                for ip_str in ips:
                    if is_public_ipv4(ip_str):
                        orig_ip = ip_str
                        break
                if orig_ip:
                    break

        has_orig_ip = 1.0 if orig_ip else 0.0
        orig_ip_is_pub = 1.0 if (orig_ip and is_public_ipv4(orig_ip)) else 0.0
        has_x_mailer = 1.0 if "x-mailer" in headers_dict else 0.0

        # Subject & Body textual stats
        subj_len = float(len(subject))
        subj_caps = float(sum(1 for c in subject if c.isupper()) / max(1, len(subject)))
        subj_exclamations = float(subject.count("!"))

        body_len = float(len(body))
        body_caps = float(sum(1 for c in body if c.isupper()) / max(1, len(body)))

        html_parts = float(data.get("html_part_count", 0))
        plain_parts = float(data.get("plain_part_count", 0))
        is_html_only = 1.0 if (html_parts > 0 and plain_parts == 0) else 0.0

        # Build structured feature dictionary
        structured_features = {
            "sender_reply_to_mismatch": sender_reply_to_mismatch,
            "sender_return_path_mismatch": sender_return_path_mismatch,
            "sender_name_spoofing": display_name_spoof,
            "sender_domain_is_freemail": sender_domain_is_freemail,
            "sender_domain_is_suspicious_tld": sender_domain_is_suspicious_tld,
            "sender_domain_length": sender_domain_length,
            "sender_domain_subdomain_count": sender_domain_subdomain_count,
            "sender_has_ip_domain": sender_has_ip_domain,
            "spf_pass": spf_pass,
            "spf_fail": spf_fail,
            "spf_softfail": spf_softfail,
            "spf_missing": spf_missing,
            "dkim_pass": dkim_pass,
            "dkim_fail": dkim_fail,
            "dkim_missing": dkim_missing,
            "dmarc_pass": dmarc_pass,
            "dmarc_fail": dmarc_fail,
            "dmarc_missing": dmarc_missing,
            "auth_failure_count": auth_failure_count,
            "url_count": url_count,
            "domain_count": domain_count,
            "url_ip_host_count": url_ip_host_count,
            "url_shortener_count": url_shortener_count,
            "url_suspicious_keywords_count": url_suspicious_keywords_count,
            "url_max_path_length": url_max_path_length,
            "url_https_ratio": url_https_ratio,
            "url_has_at_symbol": url_has_at_symbol,
            "url_has_punycode": url_has_punycode,
            "url_max_subdomains": url_max_subdomains,
            "urgency_keywords_count": urgency_count,
            "threat_fear_keywords_count": fear_count,
            "psychological_pressure_score": psychological_pressure_score,
            "financial_keywords_count": financial_count,
            "executive_keywords_count": executive_count,
            "bec_composite_score": bec_score,
            "attachment_count": att_count,
            "suspicious_attachment_count": suspicious_att_count,
            "double_extension_count": double_ext_count,
            "attachment_total_size_kb": att_total_size,
            "has_executable_attachment": has_exec_att,
            "has_archive_attachment": has_archive_att,
            "has_office_macro_attachment": has_macro_att,
            "header_count": header_count,
            "received_hop_count": hop_count,
            "has_originating_ip": has_orig_ip,
            "originating_ip_is_public": orig_ip_is_pub,
            "has_x_mailer": has_x_mailer,
            "subject_length": subj_len,
            "subject_caps_ratio": subj_caps,
            "subject_exclamation_count": subj_exclamations,
            "body_length": body_len,
            "body_caps_ratio": body_caps,
            "html_part_count": html_parts,
            "plain_part_count": plain_parts,
            "is_html_only": is_html_only,
        }

        # --- Deterministic Forensic Evidence ---
        forensic_evidence = []
        if sender_reply_to_mismatch:
            forensic_evidence.append(
                f"Identity Anomaly: From domain '{sender_domain}' differs from Reply-To domain '{reply_to_domain}'."
            )
        if sender_return_path_mismatch:
            forensic_evidence.append(
                f"Identity Anomaly: From domain '{sender_domain}' differs from Return-Path domain '{return_path_domain}'."
            )
        if display_name_spoof:
            forensic_evidence.append(
                f"Executive/Brand Spoofing Flag: Sender display name contains brand or executive role mismatched with envelope domain '{sender_domain}'."
            )
        if spf_fail:
            forensic_evidence.append("SPF Authentication Failure: Originating mail server failed domain authorization.")
        if dkim_fail:
            forensic_evidence.append("DKIM Authentication Failure: Cryptographic message signature invalid or modified in transit.")
        if dmarc_fail:
            forensic_evidence.append("DMARC Policy Failure: Sender fails domain alignment policy.")
        if url_ip_host_count > 0:
            forensic_evidence.append(f"Suspicious URL: {int(url_ip_host_count)} destination URL(s) point directly to numeric IP address instead of FQDN.")
        if url_shortener_count > 0:
            forensic_evidence.append(f"Obfuscation: {int(url_shortener_count)} shortened URL redirector(s) detected in email body.")
        if has_macro_att:
            forensic_evidence.append("High Risk Attachment: Document with enabled Microsoft Office Macro payload (.docm/.xlsm) attached.")
        if has_exec_att:
            forensic_evidence.append("Critical Risk Attachment: Direct executable or script binary attachment detected.")
        if double_ext_count > 0:
            forensic_evidence.append("Evasion Technique: Attachment disguised using double file extension syntax.")
        if bec_score >= 3.0:
            forensic_evidence.append("BEC Fraud Pattern: Combination of urgent financial transfer request and sender identity divergence.")

        # Text combined for NLP
        raw_text_combined = f"{subject}\n{sender}\n{body}".strip()

        return {
            "text_combined": raw_text_combined,
            "subject": subject,
            "sender": sender,
            "body": body,
            "sender_domain": sender_domain,
            "urls": urls,
            "domains": sorted(extracted_domains),
            "originating_ip": orig_ip,
            "structured_features": structured_features,
            "vector": [structured_features[name] for name in self.FEATURE_NAMES],
            "feature_names": list(self.FEATURE_NAMES),
            "forensic_evidence": forensic_evidence,
            "attachments": attachments,
        }
