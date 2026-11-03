
from pathlib import Path
import json
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import StratifiedKFold, cross_val_score


# ============================================================
# MATSYA EMAIL PHISHING DEMONSTRATION DATASET
# ============================================================
#
# NOTE:
# This is still a demonstration dataset for your hackathon project.
# For production use, train on a large, properly labeled dataset.
# ============================================================

TRAINING_DATA = [

    # ========================
    # PHISHING EMAILS
    # ========================

    (
        "URGENT security alert. Your account has been suspended. "
        "Click the link immediately and verify your password to restore access.",
        "phishing",
    ),
    (
        "Your bank account is temporarily blocked. Confirm your login credentials "
        "and account information immediately to prevent permanent closure.",
        "phishing",
    ),
    (
        "Congratulations! You have won a cash prize. Click here now to claim "
        "your reward before the offer expires.",
        "phishing",
    ),
    (
        "Microsoft security team detected suspicious activity. "
        "Verify your identity and password immediately.",
        "phishing",
    ),
    (
        "Your Office 365 account will be deleted today unless you confirm "
        "your credentials using the secure verification link.",
        "phishing",
    ),
    (
        "Your package delivery failed. Pay a small delivery fee immediately "
        "using the payment link below.",
        "phishing",
    ),
    (
        "We detected an unusual login attempt. Confirm your username, "
        "password and verification code now.",
        "phishing",
    ),
    (
        "Final warning! Your email account will be permanently suspended. "
        "Click here immediately to avoid losing access.",
        "phishing",
    ),
    (
        "Your payroll information requires verification. "
        "Please submit your bank details through this urgent link.",
        "phishing",
    ),
    (
        "You are eligible for a special refund. "
        "Enter your card details to receive the payment.",
        "phishing",
    ),
    (
        "Immediate action required. Your account password has expired. "
        "Click the verification link and enter your credentials.",
        "phishing",
    ),
    (
        "Invoice overdue. Open the attached secure document and login "
        "to complete your payment immediately.",
        "phishing",
    ),
    (
        "Your account has been compromised. "
        "Reset your password immediately using this link.",
        "phishing",
    ),
    (
        "Confirm your identity now to prevent account suspension. "
        "Failure to act within 24 hours will result in permanent closure.",
        "phishing",
    ),
    (
        "You have received an unexpected payment. "
        "Verify your bank credentials to accept the transaction.",
        "phishing",
    ),
    (
        "Security verification required. "
        "Login through the link below and confirm your password.",
        "phishing",
    ),


    # ========================
    # LEGITIMATE EMAILS
    # ========================

    (
        "Team meeting agenda for tomorrow afternoon. "
        "Please review the attached agenda before the meeting.",
        "legitimate",
    ),
    (
        "Please find the monthly project report attached for your review.",
        "legitimate",
    ),
    (
        "Your requested invoice is attached for your records and review.",
        "legitimate",
    ),
    (
        "The office will remain closed during the upcoming public holiday.",
        "legitimate",
    ),
    (
        "Thank you for attending the project status meeting yesterday.",
        "legitimate",
    ),
    (
        "Your appointment is confirmed for next Monday at 10 AM.",
        "legitimate",
    ),
    (
        "Please review the draft document and share your feedback "
        "with the team by Friday.",
        "legitimate",
    ),
    (
        "The quarterly sales report is now available for the management team.",
        "legitimate",
    ),
    (
        "Your internship application has been received successfully. "
        "Our recruitment team will review your application.",
        "legitimate",
    ),
    (
        "Thank you for applying for the Microsoft internship program. "
        "Your application is currently under review.",
        "legitimate",
    ),
    (
        "Microsoft Internship Alert: new internship opportunities "
        "are available on the official careers portal.",
        "legitimate",
    ),
    (
        "Your interview has been scheduled for the next recruitment round. "
        "Please check the official portal for additional details.",
        "legitimate",
    ),
    (
        "The software development team has successfully completed "
        "the scheduled deployment.",
        "legitimate",
    ),
    (
        "Your course registration has been confirmed successfully.",
        "legitimate",
    ),
    (
        "Please submit your assignment before the deadline mentioned "
        "in the course portal.",
        "legitimate",
    ),
    (
        "The university has published the examination timetable "
        "on the official website.",
        "legitimate",
    ),
]


# ============================================================
# TRAIN MODEL
# ============================================================

def main():

    texts = [text for text, label in TRAINING_DATA]
    labels = [label for text, label in TRAINING_DATA]

    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                lowercase=True,
                ngram_range=(1, 2),
                min_df=1,
                max_df=0.95,
                sublinear_tf=True,
                max_features=5000,
            ),
        ),

        (
            "classifier",
            LogisticRegression(
                max_iter=2000,
                class_weight="balanced",
                random_state=42,
                solver="liblinear",
            ),
        ),
    ])


    # ========================================================
    # CROSS VALIDATION
    # ========================================================

    min_class_count = min(labels.count("phishing"), labels.count("legitimate"))

    cv_folds = min(5, min_class_count)

    cv = StratifiedKFold(
        n_splits=cv_folds,
        shuffle=True,
        random_state=42,
    )

    scores = cross_val_score(
        model,
        texts,
        labels,
        cv=cv,
        scoring="accuracy",
    )

    print("\n==============================")
    print("MATSYA ML MODEL TRAINING")
    print("==============================")

    print(f"Training examples: {len(TRAINING_DATA)}")
    print(f"Phishing examples: {labels.count('phishing')}")
    print(f"Legitimate examples: {labels.count('legitimate')}")

    print("\nCross Validation Accuracy:")

    for index, score in enumerate(scores, start=1):
        print(f"Fold {index}: {score * 100:.2f}%")

    print(
        f"\nAverage CV Accuracy: "
        f"{scores.mean() * 100:.2f}%"
    )


    # ========================================================
    # FINAL MODEL TRAINING
    # ========================================================

    model.fit(texts, labels)


    # ========================================================
    # SAVE MODEL
    # ========================================================

    base_path = Path(__file__).parent

    output_path = base_path / "email_model.joblib"

    joblib.dump(model, output_path)


    # ========================================================
    # MODEL METADATA
    # ========================================================

    metadata = {

        "model_type":
            "TF-IDF (Unigram + Bigram) + Logistic Regression",

        "training_examples":
            len(TRAINING_DATA),

        "phishing_examples":
            labels.count("phishing"),

        "legitimate_examples":
            labels.count("legitimate"),

        "classes":
            list(model.named_steps["classifier"].classes_),

        "cross_validation_accuracy":
            round(float(scores.mean()), 4),

        "cv_folds":
            cv_folds,

        "warning":
            (
                "Demonstration model trained on a small manually created "
                "dataset. This model is suitable for hackathon demonstration "
                "and decision-support only, not production security detection."
            ),
    }


    metadata_path = base_path / "model_metadata.json"

    metadata_path.write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )


    print("\n==============================")
    print("MODEL TRAINED SUCCESSFULLY")
    print("==============================")

    print(f"Model saved to: {output_path}")

    print(f"Metadata saved to: {metadata_path}")

    print(
        "\nIMPORTANT: Restart FastAPI after training "
        "so the new model is loaded."
    )


if __name__ == "__main__":
    main()
