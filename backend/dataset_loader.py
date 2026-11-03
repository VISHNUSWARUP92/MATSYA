"""
MATSYA Cyber Forensics — Dataset Ingestion, Normalization & Leak-Free Splitting
Handles public and custom cyber threat email datasets, label normalization,
near-duplicate grouping, and campaign-aware train/test splitting.
"""

from hashlib import sha256
from pathlib import Path
import csv
import json
import os
import re
import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedGroupKFold, GroupShuffleSplit

from feature_extractor import FeatureExtractor

# Standard multi-class label taxonomy
TARGET_CLASSES = [
    "likely_legitimate",
    "likely_phishing",
    "business_email_compromise",
    "malware_delivery",
    "spam",
    "suspicious",
]

# Mapping table to normalize divergent external label annotations
LABEL_SYNONYMS = {
    # Legitimate
    "legitimate": "likely_legitimate",
    "legit": "likely_legitimate",
    "benign": "likely_legitimate",
    "ham": "likely_legitimate",
    "safe": "likely_legitimate",
    "clean": "likely_legitimate",
    "normal": "likely_legitimate",
    "0": "likely_legitimate",
    # Phishing
    "phishing": "likely_phishing",
    "phish": "likely_phishing",
    "credential_harvesting": "likely_phishing",
    "credential_theft": "likely_phishing",
    "fake": "likely_phishing",
    "1": "likely_phishing",
    # BEC
    "bec": "business_email_compromise",
    "business_email_compromise": "business_email_compromise",
    "ceo_fraud": "business_email_compromise",
    "wire_fraud": "business_email_compromise",
    "invoice_fraud": "business_email_compromise",
    "executive_impersonation": "business_email_compromise",
    # Malware
    "malware": "malware_delivery",
    "malware_delivery": "malware_delivery",
    "trojan": "malware_delivery",
    "ransomware": "malware_delivery",
    "exploit": "malware_delivery",
    "attachment_threat": "malware_delivery",
    "virus": "malware_delivery",
    # Spam
    "spam": "spam",
    "bulk": "spam",
    "marketing": "spam",
    "unsolicited": "spam",
    "junk": "spam",
    # Suspicious
    "suspicious": "suspicious",
    "anomaly": "suspicious",
    "unverified": "suspicious",
    "uncertain": "suspicious",
    "unknown": "suspicious",
}


def normalize_label(raw_label: str) -> str:
    """Normalize input label to canonical 6-class MATSYA taxonomy."""
    cleaned = str(raw_label or "").strip().lower()
    cleaned = re.sub(r"[\s_-]+", "_", cleaned)
    if cleaned in LABEL_SYNONYMS:
        return LABEL_SYNONYMS[cleaned]
    # Check partial contains
    for key, canonical in LABEL_SYNONYMS.items():
        if key in cleaned:
            return canonical
    return "suspicious"


def compute_content_fingerprint(subject: str, body: str) -> str:
    """Generate normalized text hash for exact duplicate detection."""
    norm_s = re.sub(r"\W+", " ", (subject or "").lower()).strip()
    norm_b = re.sub(r"\W+", " ", (body or "").lower())[:1000].strip()
    combined = f"{norm_s}|{norm_b}"
    return sha256(combined.encode("utf-8", errors="replace")).hexdigest()


def compute_shingle_hash(text: str, k: int = 4) -> set:
    """Generate k-word shingles for near-duplicate Jaccard similarity."""
    words = re.findall(r"\w+", (text or "").lower())
    if len(words) < k:
        return set(words)
    return {" ".join(words[i:i+k]) for i in range(len(words) - k + 1)}


class DatasetLoader:
    """
    Ingests email threat datasets with automated column resolution,
    label canonicalization, deduplication, campaign grouping, and audit logging.
    """

    def __init__(self):
        self.extractor = FeatureExtractor()

    def load_from_csv(self, file_path: str | Path, source_name: str = "", license_name: str = "") -> dict:
        """
        Load dataset from CSV with robust field resolution and metadata compilation.
        """
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Dataset CSV not found at: {path}")

        raw_bytes = path.read_bytes()
        file_sha256 = sha256(raw_bytes).hexdigest()

        # Read into pandas dataframe
        try:
            df = pd.read_csv(path, encoding="utf-8")
        except UnicodeDecodeError:
            df = pd.read_csv(path, encoding="latin-1")

        if df.empty:
            raise ValueError(f"Dataset at {path} is empty.")

        # Column normalization
        col_map = {}
        for col in df.columns:
            c_low = str(col).strip().lower().replace(" ", "_")
            if c_low in ["subject", "email_subject", "title"]:
                col_map["subject"] = col
            elif c_low in ["body", "content", "email_body", "text", "message"]:
                col_map["body"] = col
            elif c_low in ["sender", "from", "email_from", "from_address"]:
                col_map["sender"] = col
            elif c_low in ["reply_to", "reply-to"]:
                col_map["reply_to"] = col
            elif c_low in ["return_path", "return-path"]:
                col_map["return_path"] = col
            elif c_low in ["auth", "authentication", "authentication_results", "spf"]:
                col_map["authentication_results"] = col
            elif c_low in ["urls", "links", "url_list"]:
                col_map["urls"] = col
            elif c_low in ["attachments", "attachment_names", "files"]:
                col_map["attachment_names"] = col
            elif c_low in ["label", "target", "class", "threat_type", "category"]:
                col_map["label"] = col

        if "label" not in col_map:
            raise ValueError(f"Dataset missing required label column. Found: {list(df.columns)}")

        # Fill missing core fields
        if "subject" not in col_map:
            df["_subject"] = ""
            col_map["subject"] = "_subject"
        if "body" not in col_map:
            df["_body"] = ""
            col_map["body"] = "_body"

        records = []
        exact_hashes = {}
        shingle_cache = []
        group_ids = []
        next_group_id = 0

        for idx, row in df.iterrows():
            sub = str(row[col_map["subject"]]) if pd.notna(row[col_map["subject"]]) else ""
            bod = str(row[col_map["body"]]) if pd.notna(row[col_map["body"]]) else ""
            snd = str(row[col_map.get("sender", "")]) if ("sender" in col_map and pd.notna(row[col_map["sender"]])) else ""
            rep = str(row[col_map.get("reply_to", "")]) if ("reply_to" in col_map and pd.notna(row[col_map["reply_to"]])) else ""
            ret = str(row[col_map.get("return_path", "")]) if ("return_path" in col_map and pd.notna(row[col_map["return_path"]])) else ""
            ath = str(row[col_map.get("authentication_results", "")]) if ("authentication_results" in col_map and pd.notna(row[col_map["authentication_results"]])) else ""
            url_val = row[col_map.get("urls", "")] if ("urls" in col_map and pd.notna(row[col_map["urls"]])) else ""
            att_val = row[col_map.get("attachment_names", "")] if ("attachment_names" in col_map and pd.notna(row[col_map["attachment_names"]])) else ""
            raw_lbl = str(row[col_map["label"]])

            norm_lbl = normalize_label(raw_lbl)

            # Deduplication & Campaign Grouping
            fp = compute_content_fingerprint(sub, bod)
            assigned_group = None

            if fp in exact_hashes:
                assigned_group = exact_hashes[fp]
            else:
                # Near-duplicate check with shingle Jaccard similarity
                shingles = compute_shingle_hash(f"{sub} {bod}")
                for prev_idx, prev_shingles, prev_grp in shingle_cache:
                    if shingles and prev_shingles:
                        intersection = len(shingles & prev_shingles)
                        union = len(shingles | prev_shingles)
                        if union > 0 and (intersection / union) >= 0.82:
                            assigned_group = prev_grp
                            break

                if assigned_group is None:
                    assigned_group = f"grp_{next_group_id}"
                    next_group_id += 1

                exact_hashes[fp] = assigned_group
                shingle_cache.append((idx, shingles, assigned_group))

            group_ids.append(assigned_group)

            urls_list = []
            if isinstance(url_val, str) and url_val.strip():
                urls_list = [u.strip() for u in url_val.split(",") if u.strip()]

            raw_dict = {
                "subject": sub,
                "body": bod,
                "sender": snd,
                "reply_to": rep,
                "return_path": ret,
                "authentication_results": ath,
                "urls": urls_list,
                "attachment_names": att_val,
                "label": norm_lbl,
                "group_id": assigned_group,
            }
            records.append(raw_dict)

        # Build extracted feature dataset
        features_list = []
        labels_list = []
        texts_list = []

        for item in records:
            ext = self.extractor.extract_from_dict(item)
            features_list.append(ext["vector"])
            texts_list.append(ext["text_combined"])
            labels_list.append(item["label"])

        feature_names = self.extractor.get_feature_names()
        X_structured = np.array(features_list, dtype=np.float32)
        X_text = np.array(texts_list, dtype=object)
        y = np.array(labels_list, dtype=object)
        groups = np.array(group_ids, dtype=object)

        # Class distribution count
        unique_classes, counts = np.unique(y, return_counts=True)
        class_dist = {cls: int(cnt) for cls, cnt in zip(unique_classes, counts)}

        metadata = {
            "source_file": path.name,
            "source_name": source_name or "MATSYA Threat Dataset Ingestion",
            "license": license_name or "Cybersecurity Research / Internal Evaluation",
            "sha256": file_sha256,
            "total_records": len(records),
            "unique_campaign_groups": len(set(group_ids)),
            "class_distribution": class_dist,
            "structured_features_count": len(feature_names),
        }

        return {
            "X_structured": X_structured,
            "X_text": X_text,
            "y": y,
            "groups": groups,
            "records": records,
            "feature_names": feature_names,
            "metadata": metadata,
        }

    def create_leak_free_split(
        self,
        X_structured: np.ndarray,
        X_text: np.ndarray,
        y: np.ndarray,
        groups: np.ndarray,
        test_size: float = 0.20,
        random_state: int = 42
    ) -> dict:
        """
        Split dataset into train and holdout test set using GroupShuffleSplit
        to guarantee no campaign or duplicate leakage into test evaluation.
        """
        # Ensure groups is 1D array
        gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
        train_idx, test_idx = next(gss.split(X_structured, y, groups))

        # Check that no group is shared across splits
        train_groups = set(groups[train_idx])
        test_groups = set(groups[test_idx])
        overlap = train_groups.intersection(test_groups)
        assert len(overlap) == 0, f"Critical Data Leakage Detected: Shared groups {overlap}"

        return {
            "train_idx": train_idx,
            "test_idx": test_idx,
            "X_train_struct": X_structured[train_idx],
            "X_test_struct": X_structured[test_idx],
            "X_train_text": X_text[train_idx],
            "X_test_text": X_text[test_idx],
            "y_train": y[train_idx],
            "y_test": y[test_idx],
            "groups_train": groups[train_idx],
            "groups_test": groups[test_idx],
        }
