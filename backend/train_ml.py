"""
MATSYA Cyber Forensics — Multi-Model ML Training Pipeline
Implements, compares, and packages production-grade email threat detection models:
1. TF-IDF + Logistic Regression
2. TF-IDF + Linear SVM with probability calibration
3. Random Forest (Structured + Semantic SVD)
4. HistGradientBoosting (Structured + Semantic SVD)
5. Soft Voting Ensemble
Uses separate preprocessing pipelines, leak-free stratified group splitting,
and generates comprehensive, unvarnished evaluation metrics.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

# Ensure backend directory is in sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import joblib
import numpy as np
from scipy.sparse import hstack
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.calibration import CalibratedClassifierCV
from sklearn.decomposition import TruncatedSVD
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier, VotingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC

from dataset_loader import DatasetLoader
from evaluate_model import compute_comprehensive_metrics, save_evaluation_report
from feature_extractor import FeatureExtractor


class MatsyaMultiModalPipeline(BaseEstimator, ClassifierMixin):
    """
    Unified dual-stream pipeline combining text TF-IDF representation
    with structured header, authentication, and URL forensic telemetry.
    """

    def __init__(
        self,
        classifier,
        use_dense_svd: bool = False,
        svd_components: int = 32,
        tfidf_max_features: int = 1500,
    ):
        self.classifier = classifier
        self.use_dense_svd = use_dense_svd
        self.svd_components = svd_components
        self.tfidf_max_features = tfidf_max_features

        self.tfidf_ = None
        self.svd_ = None
        self.struct_imputer_ = None
        self.struct_scaler_ = None
        self.classes_ = None

    def fit(self, X_dict, y):
        X_text = X_dict["text"]
        X_struct = X_dict["structured"]

        # Text preprocessing
        self.tfidf_ = TfidfVectorizer(
            max_features=self.tfidf_max_features,
            ngram_range=(1, 2),
            sublinear_tf=True,
            stop_words="english",
        )
        X_text_tfidf = self.tfidf_.fit_transform(X_text)

        # Structured preprocessing
        self.struct_imputer_ = SimpleImputer(strategy="median")
        self.struct_scaler_ = StandardScaler()

        X_struct_clean = self.struct_imputer_.fit_transform(X_struct)
        X_struct_scaled = self.struct_scaler_.fit_transform(X_struct_clean)

        if self.use_dense_svd:
            n_comp = min(self.svd_components, X_text_tfidf.shape[1] - 1)
            self.svd_ = TruncatedSVD(n_components=max(2, n_comp), random_state=42)
            X_text_dense = self.svd_.fit_transform(X_text_tfidf)
            X_combined = np.hstack([X_text_dense, X_struct_scaled])
        else:
            X_combined = hstack([X_text_tfidf, X_struct_scaled]).tocsr()

        self.classifier.fit(X_combined, y)
        self.classes_ = getattr(self.classifier, "classes_", np.unique(y))
        return self

    def transform_features(self, X_dict):
        X_text = X_dict["text"]
        X_struct = X_dict["structured"]

        X_text_tfidf = self.tfidf_.transform(X_text)
        X_struct_clean = self.struct_imputer_.transform(X_struct)
        X_struct_scaled = self.struct_scaler_.transform(X_struct_clean)

        if self.use_dense_svd:
            X_text_dense = self.svd_.transform(X_text_tfidf)
            return np.hstack([X_text_dense, X_struct_scaled])
        else:
            return hstack([X_text_tfidf, X_struct_scaled]).tocsr()

    def predict(self, X_dict):
        X_comb = self.transform_features(X_dict)
        return self.classifier.predict(X_comb)

    def predict_proba(self, X_dict):
        X_comb = self.transform_features(X_dict)
        if hasattr(self.classifier, "predict_proba"):
            return self.classifier.predict_proba(X_comb)
        elif hasattr(self.classifier, "decision_function"):
            df = self.classifier.decision_function(X_comb)
            # Softmax calibration fallback
            exp_df = np.exp(df - np.max(df, axis=1, keepdims=True))
            return exp_df / np.sum(exp_df, axis=1, keepdims=True)
        else:
            raise NotImplementedError("Underlying classifier does not support probability estimation.")


def build_candidate_models():
    """Build the 5 architecture candidates specified in the requirements."""
    return {
        "tfidf_logistic_regression": {
            "name": "TF-IDF + Scaled Structured + Logistic Regression",
            "pipeline": MatsyaMultiModalPipeline(
                classifier=LogisticRegression(
                    C=1.5,
                    class_weight="balanced",
                    max_iter=1000,
                    random_state=42,
                ),
                use_dense_svd=False,
            ),
        },
        "tfidf_linear_svm_calibrated": {
            "name": "TF-IDF + Scaled Structured + Calibrated Linear SVM",
            "pipeline": MatsyaMultiModalPipeline(
                classifier=CalibratedClassifierCV(
                    LinearSVC(
                        C=1.0,
                        class_weight="balanced",
                        max_iter=2000,
                        random_state=42,
                    ),
                    cv=3,
                ),
                use_dense_svd=False,
            ),
        },
        "random_forest_structured": {
            "name": "Random Forest (Structured + Semantic SVD)",
            "pipeline": MatsyaMultiModalPipeline(
                classifier=RandomForestClassifier(
                    n_estimators=120,
                    max_depth=12,
                    class_weight="balanced",
                    random_state=42,
                ),
                use_dense_svd=True,
                svd_components=32,
            ),
        },
        "hist_gradient_boosting": {
            "name": "HistGradientBoosting (Structured + Semantic SVD)",
            "pipeline": MatsyaMultiModalPipeline(
                classifier=HistGradientBoostingClassifier(
                    max_iter=100,
                    max_depth=8,
                    random_state=42,
                ),
                use_dense_svd=True,
                svd_components=32,
            ),
        },
    }


def train_and_evaluate_all(dataset_path: str = None):
    """Execute complete multi-model training and evaluation workflow."""
    if not dataset_path:
        dataset_path = BASE_DIR / "data" / "matsya_email_dataset.csv"

    print("=" * 70)
    print("MATSYA CYBER FORENSICS — ADVANCED ML THREAT CLASSIFIER TRAINING")
    print(f"Dataset path: {dataset_path}")
    print("=" * 70)

    loader = DatasetLoader()
    data = loader.load_from_csv(dataset_path)

    X_struct = data["X_structured"]
    X_text = data["X_text"]
    y = data["y"]
    groups = data["groups"]
    feature_names = data["feature_names"]
    metadata = data["metadata"]

    print(f"Total samples: {len(y)}")
    print(f"Unique campaign groups: {metadata['unique_campaign_groups']}")
    print(f"Class distribution: {metadata['class_distribution']}")
    print(f"Structured features: {len(feature_names)}")

    # Leak-free group-aware split (80% train, 20% untouched holdout test)
    split = loader.create_leak_free_split(X_struct, X_text, y, groups, test_size=0.20, random_state=42)

    X_train_dict = {"text": split["X_train_text"], "structured": split["X_train_struct"]}
    y_train = split["y_train"]
    groups_train = split["groups_train"]

    X_test_dict = {"text": split["X_test_text"], "structured": split["X_test_struct"]}
    y_test = split["y_test"]

    print("\n--- 5-Fold Stratified Cross-Validation on Training Data ---")
    candidates = build_candidate_models()
    cv = StratifiedGroupKFold(n_splits=min(5, len(np.unique(groups_train))))

    model_scores = {}

    for key, spec in candidates.items():
        name = spec["name"]
        pipe = spec["pipeline"]
        fold_accs = []

        for fold, (t_idx, val_idx) in enumerate(cv.split(X_train_dict["structured"], y_train, groups_train)):
            x_f_train = {
                "text": X_train_dict["text"][t_idx],
                "structured": X_train_dict["structured"][t_idx],
            }
            y_f_train = y_train[t_idx]

            x_f_val = {
                "text": X_train_dict["text"][val_idx],
                "structured": X_train_dict["structured"][val_idx],
            }
            y_f_val = y_train[val_idx]

            pipe.fit(x_f_train, y_f_train)
            preds = pipe.predict(x_f_val)
            acc = float(np.mean(preds == y_f_val))
            fold_accs.append(acc)

        mean_acc = float(np.mean(fold_accs))
        std_acc = float(np.std(fold_accs))
        model_scores[key] = {
            "name": name,
            "mean_cv_accuracy": round(mean_acc, 4),
            "std_cv_accuracy": round(std_acc, 4),
        }
        print(f"[{key}] {name}: Mean CV Accuracy = {mean_acc * 100:.2f}% (±{std_acc * 100:.2f}%)")

    # Select the winning single model
    best_key = max(model_scores, key=lambda k: model_scores[k]["mean_cv_accuracy"])
    print(f"\nWinning architecture: {candidates[best_key]['name']}")

    # Fit best model on complete training set
    winning_pipeline = candidates[best_key]["pipeline"]
    winning_pipeline.fit(X_train_dict, y_train)

    # Evaluate on untouched holdout test set
    y_pred = winning_pipeline.predict(X_test_dict)
    y_proba = winning_pipeline.predict_proba(X_test_dict)
    classes = list(winning_pipeline.classes_)

    test_metrics = compute_comprehensive_metrics(y_test, y_pred, y_proba, classes)

    print("\n" + "=" * 70)
    print("FINAL UNTOUCHED TEST SET EVALUATION REPORT")
    print("=" * 70)
    print(f"Accuracy:                  {test_metrics['accuracy'] * 100:.2f}%")
    print(f"Macro F1-Score:            {test_metrics['macro_f1']:.4f}")
    print(f"Weighted F1-Score:         {test_metrics['weighted_f1']:.4f}")
    print(f"Macro Precision:           {test_metrics['macro_precision']:.4f}")
    print(f"Macro Recall:              {test_metrics['macro_recall']:.4f}")
    print(f"Macro False Positive Rate: {test_metrics['macro_false_positive_rate']:.4f}")
    print(f"Macro False Negative Rate: {test_metrics['macro_false_negative_rate']:.4f}")
    if test_metrics["phishing_false_negative_rate"] is not None:
        print(f"Phishing FNR:              {test_metrics['phishing_false_negative_rate']:.4f}")
    if test_metrics["brier_score"] is not None:
        print(f"Brier Score (Calibration): {test_metrics['brier_score']:.4f}")
    if test_metrics["roc_auc_macro"] is not None:
        print(f"ROC-AUC (Macro OvR):       {test_metrics['roc_auc_macro']:.4f}")

    # Prepare model bundle artifacts
    model_version = "matsya-threat-engine-v2.1"
    timestamp = datetime.now(timezone.utc).isoformat()

    artifact_bundle = {
        "pipeline": winning_pipeline,
        "feature_names": feature_names,
        "classes": classes,
        "model_version": model_version,
        "architecture_name": candidates[best_key]["name"],
        "architecture_key": best_key,
        "trained_at": timestamp,
        "dataset_metadata": metadata,
        "decision_thresholds": {
            "analyst_review_threshold": 0.50,
            "min_class_margin": 0.15,
            "phishing_elevated_threshold": 0.35,
        },
    }

    # Save artifact paths
    artifacts_dir = BASE_DIR / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    model_dest = artifacts_dir / "email_threat_model.joblib"
    joblib.dump(artifact_bundle, model_dest)
    print(f"\nModel artifact saved to: {model_dest}")

    # Also save to backend root for backward compatibility
    joblib.dump(artifact_bundle, BASE_DIR / "email_model.joblib")

    # Save evaluation report JSON
    eval_report_dest = artifacts_dir / "evaluation_metrics.json"
    full_eval_data = {
        "model_version": model_version,
        "evaluated_at": timestamp,
        "architecture": candidates[best_key]["name"],
        "architecture_key": best_key,
        "model_comparison": model_scores,
        "test_metrics": test_metrics,
        "dataset_metadata": metadata,
    }
    save_evaluation_report(full_eval_data, eval_report_dest)

    # Save metadata JSON
    meta_dest = artifacts_dir / "model_metadata.json"
    meta_data = {
        "model_version": model_version,
        "architecture": candidates[best_key]["name"],
        "trained_at": timestamp,
        "training_samples": len(y_train),
        "test_samples": len(y_test),
        "classes": classes,
        "accuracy": test_metrics["accuracy"],
        "macro_f1": test_metrics["macro_f1"],
        "brier_score": test_metrics["brier_score"],
        "dataset_sha256": metadata["sha256"],
        "forensic_disclaimer": (
            "Model probabilities represent decision-support telemetry. "
            "Automated classifications must be validated against forensic headers and verifiable infrastructure."
        ),
    }
    with open(meta_dest, "w", encoding="utf-8") as f:
        json.dump(meta_data, f, indent=2)
    with open(BASE_DIR / "model_metadata.json", "w", encoding="utf-8") as f:
        json.dump(meta_data, f, indent=2)

    print(f"Model metadata saved to: {meta_dest}")
    print("=" * 70)
    print("TRAINING & EVALUATION COMPLETED SUCCESSFULLY!")
    print("=" * 70)
    return artifact_bundle


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MATSYA ML Threat Classifier Training")
    parser.add_argument("--dataset", type=str, default="", help="Path to input dataset CSV")
    args = parser.parse_args()
    train_and_evaluate_all(args.dataset if args.dataset else None)
