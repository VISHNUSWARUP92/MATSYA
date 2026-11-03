import sys
from pathlib import Path

# Ensure backend directory is in sys.path for direct scripts and module imports
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from contextlib import asynccontextmanager
from email import policy
from email.parser import BytesParser
from hashlib import sha256
from urllib.parse import urlparse

import ipaddress
import json
import re

import joblib

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect, text

from database import engine, SessionLocal
from models import InvestigationCase, create_tables
from intelligence import router as intelligence_router


# --------------------------------------------------
# MATSYA CONFIGURATION
# --------------------------------------------------

MAX_FILE_SIZE = 10 * 1024 * 1024

BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = BASE_DIR / "email_model.joblib"


# --------------------------------------------------
# EMAIL ROUTE + GEOLOCATION HELPERS
# --------------------------------------------------

IPV4_PATTERN = re.compile(
    r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
)


def is_public_ipv4(value: str) -> bool:
    """
    Return True only for globally routable IPv4 addresses.
    """

    try:
        ip = ipaddress.ip_address(value)

        if ip.version != 4:
            return False

        return bool(
            ip.is_global
            and not ip.is_private
            and not ip.is_loopback
            and not ip.is_multicast
            and not ip.is_reserved
        )

    except ValueError:
        return False


def extract_received_chain(message):
    """
    Extract public IPv4 addresses from Received headers.

    IMPORTANT:
    Received headers are added hop-by-hop. Header ordering can vary
    depending on the mail infrastructure, so the result is treated
    as a forensic heuristic rather than proof of sender location.
    """

    received_headers = message.get_all("Received", [])

    route = []

    for index, header in enumerate(received_headers):
        header_text = str(header)

        found_ips = IPV4_PATTERN.findall(header_text)

        public_ips = []

        for value in found_ips:
            if is_public_ipv4(value) and value not in public_ips:
                public_ips.append(value)

        route.append({
            "hop": index + 1,
            "header": header_text,
            "ips": public_ips,
        })

    return route


def flatten_route_ips(received_chain):
    """
    Return unique public IPs while preserving route order.
    """

    result = []

    for hop in received_chain:
        for ip in hop.get("ips", []):
            if ip not in result:
                result.append(ip)

    return result


def determine_suspected_origin(received_chain):
    """
    Select an earliest public IPv4 candidate from the
    Received header chain.

    This identifies suspected originating infrastructure,
    NOT the exact physical location of a person.
    """

    # The oldest Received header is generally closer to
    # the originating mail infrastructure.
    for hop in reversed(received_chain):
        ips = hop.get("ips", [])

        if ips:
            return {
                "ip": ips[0],
                "confidence": 70,
                "reason": (
                    "Earliest public IPv4 candidate found "
                    "in the Received header chain."
                ),
            }

    return {
        "ip": None,
        "confidence": 0,
        "reason": (
            "No public IPv4 address was found "
            "in Received headers."
        ),
    }


def extract_domain_from_email(value: str):
    """
    Extract domain from an email address/header value.
    """

    match = re.search(
        r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})",
        value or ""
    )

    if match:
        return match.group(1).lower()

    return None


# --------------------------------------------------
# DATABASE INITIALIZATION
# --------------------------------------------------

def initialize_database():
    """
    Create tables and safely update the existing cases table.
    """

    create_tables()

    inspector = inspect(engine)

    columns = {
        column["name"]
        for column in inspector.get_columns("investigation_cases")
    }

    # Add evidence_hash if an older database does not contain it.
    if "evidence_hash" not in columns:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "ALTER TABLE investigation_cases "
                    "ADD COLUMN evidence_hash VARCHAR(64)"
                )
            )


# --------------------------------------------------
# FASTAPI LIFESPAN
# --------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


# --------------------------------------------------
# FASTAPI APP
# --------------------------------------------------

app = FastAPI(
    title="MATSYA Cyber Intelligence API",
    description=(
        "Email forensics, experimental ML analysis, "
        "routing intelligence and SQLite case history"
    ),
    version="1.4.0",
    lifespan=lifespan,
)


# --------------------------------------------------
# CORS
# --------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------
# PRESERVE THREAT INTELLIGENCE ENDPOINTS
# --------------------------------------------------

app.include_router(intelligence_router)


# --------------------------------------------------
# OPTIONAL ML MODEL
# --------------------------------------------------

try:
    email_model = joblib.load(MODEL_PATH)
    ML_MODEL_STATUS = "loaded"

except Exception as exc:
    email_model = None
    ML_MODEL_STATUS = "unavailable"
    print(f"ML model unavailable: {exc}")


# --------------------------------------------------
# HOME
# --------------------------------------------------

@app.get("/")
def home():
    return {
        "service": "MATSYA Cyber Intelligence API",
        "status": "running",
        "database": "SQLite",
        "docs": "/docs",
    }


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.get("/api/health")
def health():
    database_status = "connected"

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))

    except Exception as exc:
        database_status = "unavailable"
        print(f"Database health check failed: {exc}")

    return {
        "status": (
            "healthy"
            if database_status == "connected"
            else "degraded"
        ),
        "database_status": database_status,
        "ml_model_status": ML_MODEL_STATUS,
    }


# --------------------------------------------------
# EMAIL ANALYSIS
# --------------------------------------------------

@app.post("/api/analyze")
async def analyze_email(file: UploadFile = File(...)):

    # Validate file extension.
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Please upload a valid .eml file.",
        )

    # Read with size protection.
    raw = await file.read(MAX_FILE_SIZE + 1)

    if not raw:
        raise HTTPException(
            status_code=400,
            detail="The file is empty.",
        )

    if len(raw) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="File exceeds the 10 MB limit.",
        )

    # Evidence integrity hash.
    evidence_hash = sha256(raw).hexdigest()

    # Parse EML.
    try:
        message = BytesParser(
            policy=policy.default
        ).parsebytes(raw)

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail="Unable to parse this email file.",
        ) from exc


    # --------------------------------------------------
    # EXTRACT EMAIL METADATA
    # --------------------------------------------------

    subject = str(message.get("Subject", ""))
    sender = str(message.get("From", ""))
    recipient = str(message.get("To", ""))
    cc = str(message.get("Cc", ""))
    date = str(message.get("Date", ""))

    reply_to = str(message.get("Reply-To", ""))
    return_path = str(message.get("Return-Path", ""))
    message_id = str(message.get("Message-ID", ""))

    headers = {
        str(key).lower(): str(value)
        for key, value in message.items()
    }


    # --------------------------------------------------
    # RECEIVED HEADER ROUTE ANALYSIS
    # --------------------------------------------------

    received_chain = extract_received_chain(message)

    route_ips = flatten_route_ips(received_chain)

    suspected_origin = determine_suspected_origin(
        received_chain
    )

    origin_ip = suspected_origin.get("ip")


    # --------------------------------------------------
    # EMAIL IDENTITY ANALYSIS
    # --------------------------------------------------

    sender_domain = extract_domain_from_email(sender)

    reply_to_domain = extract_domain_from_email(reply_to)

    return_path_domain = extract_domain_from_email(
        return_path
    )

    identity_mismatch = False

    identity_mismatch_reasons = []

    if (
        sender_domain
        and reply_to_domain
        and sender_domain != reply_to_domain
    ):
        identity_mismatch = True

        identity_mismatch_reasons.append(
            "From domain differs from Reply-To domain."
        )

    if (
        sender_domain
        and return_path_domain
        and sender_domain != return_path_domain
    ):
        identity_mismatch = True

        identity_mismatch_reasons.append(
            "From domain differs from Return-Path domain."
        )


    # --------------------------------------------------
    # EXTRACT READABLE BODY
    # --------------------------------------------------

    body_parts = []

    for part in message.walk():

        if part.get_content_type() in (
            "text/plain",
            "text/html",
        ):

            try:
                content = part.get_content()

                if isinstance(content, str):
                    body_parts.append(content)

            except Exception:
                continue

    body = "\n".join(body_parts)


    # --------------------------------------------------
    # RAW EMAIL TEXT
    # --------------------------------------------------

    combined = raw.decode(
        "utf-8",
        errors="replace"
    )


    # --------------------------------------------------
    # EXTRACT URLs
    # --------------------------------------------------

    urls = sorted(
        set(
            re.findall(
                r"""https?://[^\s<>"')\]]+""",
                combined,
                flags=re.IGNORECASE,
            )
        )
    )[:200]


    # --------------------------------------------------
    # EXTRACT DOMAINS
    # --------------------------------------------------

    domains = sorted(
        {
            parsed.hostname
            for url in urls
            if (
                parsed := urlparse(url)
            ).hostname
        }
    )


    # --------------------------------------------------
    # EXTRACT ALL IPV4 ADDRESSES
    # --------------------------------------------------

    candidates = set(
        IPV4_PATTERN.findall(combined)
    )

    ips = []

    for candidate in candidates:
        try:
            parsed_ip = ipaddress.ip_address(candidate)

            if parsed_ip.version == 4:
                ips.append(candidate)

        except ValueError:
            continue

    ips = sorted(set(ips))


    # --------------------------------------------------
    # TRANSPARENT HEURISTIC RISK SCORING
    # --------------------------------------------------

    findings = []

    score = 10


    # Missing sender.
    if not sender:
        findings.append(
            "Sender information is missing."
        )
        score += 20


    # Missing subject.
    if not subject:
        findings.append(
            "Subject information is missing."
        )
        score += 10


    # URL findings.
    if urls:
        findings.append(
            f"{len(urls)} URL(s) extracted. "
            "Review destinations safely."
        )

        score += min(30, len(urls) * 10)


    # General IP findings.
    if ips:
        findings.append(
            f"{len(ips)} IPv4 address(es) found; "
            "ownership and location require analyst validation."
        )

        score += min(15, len(ips) * 5)


    # Routing intelligence.
    if route_ips:
        findings.append(
            f"{len(route_ips)} public IPv4 address(es) "
            "identified from the Received header routing chain."
        )


    # Suspected origin.
    if origin_ip:
        findings.append(
            "Suspected originating infrastructure candidate: "
            f"{origin_ip}."
        )


    # Identity mismatch.
    if identity_mismatch:

        for reason in identity_mismatch_reasons:
            findings.append(
                f"Identity anomaly detected: {reason}"
            )

        score += 15


    # --------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # --------------------------------------------------

    suspicious_words = [
        "verify your account",
        "urgent action",
        "password expired",
        "account suspended",
        "confirm your password",
        "immediate action",
    ]

    lowered = f"{subject} {body}".lower()

    matched = [
        word
        for word in suspicious_words
        if word in lowered
    ]

    if matched:
        findings.append(
            "Potentially suspicious wording detected: "
            + ", ".join(matched)
        )

        score += min(30, 10 * len(matched))


    # --------------------------------------------------
    # EMAIL AUTHENTICATION RESULTS
    # --------------------------------------------------

    auth_results = headers.get(
        "authentication-results",
        ""
    ).lower()

    if any(
        token in auth_results
        for token in (
            "spf=fail",
            "dkim=fail",
            "dmarc=fail",
        )
    ):
        findings.append(
            "Authentication-Results indicates an SPF, "
            "DKIM, or DMARC failure."
        )

        score += 20


    # --------------------------------------------------
    # FINAL RISK SCORE
    # --------------------------------------------------

    score = min(score, 100)

    if score >= 70:
        risk_level = "High"

    elif score >= 40:
        risk_level = "Medium"

    else:
        risk_level = "Low"


    if not findings:
        findings.append(
            "No indicators from the current basic rules "
            "were found."
        )


    # --------------------------------------------------
    # EXPERIMENTAL ML PREDICTION
    # --------------------------------------------------

    ml_prediction = "unavailable"
    ml_probability = None

    if email_model is not None:

        ml_text = f"{subject}\n{body}"

        try:
            ml_prediction = str(
                email_model.predict([ml_text])[0]
            )

            if hasattr(email_model, "predict_proba"):

                probabilities = (
                    email_model.predict_proba([ml_text])[0]
                )

                classes = list(
                    getattr(
                        email_model,
                        "classes_",
                        []
                    )
                )

                phishing_index = next(
                    (
                        index
                        for index, label in enumerate(classes)
                        if str(label).lower() == "phishing"
                    ),
                    None,
                )

                if (
                    phishing_index is not None
                    and phishing_index < len(probabilities)
                ):
                    ml_probability = round(
                        float(
                            probabilities[phishing_index]
                        ),
                        4,
                    )

        except Exception as exc:
            print(f"ML prediction failed: {exc}")

            ml_prediction = "prediction_error"
            ml_probability = None


    # --------------------------------------------------
    # LIMITATIONS
    # --------------------------------------------------

    limitations = [
        "Risk score is based on basic heuristic rules.",
        (
            "The ML model uses a demonstration dataset "
            "and is not reliable for real-world phishing decisions."
        ),
        (
            "No live IP/domain reputation or geolocation "
            "lookup is performed by this endpoint."
        ),
        "Extracted URLs are not opened or executed.",
        "A low score does not prove an email is safe.",
        (
            "Extracted IP addresses and domains require "
            "analyst validation."
        ),
        (
            "IP routing analysis identifies approximate "
            "network infrastructure and cannot identify "
            "the exact physical location of an individual."
        ),
    ]

    if ML_MODEL_STATUS != "loaded":
        limitations.append(
            "The ML model file could not be loaded; "
            "ML prediction is unavailable."
        )


    # --------------------------------------------------
    # SAVE ANALYSIS TO SQLITE
    # --------------------------------------------------

    saved_case_id = None

    db = SessionLocal()

    try:

        saved_case = InvestigationCase(
            case_title=subject.strip() or file.filename,
            sender_email=sender or None,
            subject=subject or None,
            risk_score=score,
            risk_level=risk_level,
            findings=json.dumps(
                findings,
                ensure_ascii=False
            ),
            evidence_hash=evidence_hash,
        )

        db.add(saved_case)

        db.commit()

        db.refresh(saved_case)

        saved_case_id = saved_case.id


    except Exception as exc:

        db.rollback()

        print(f"Database save failed: {exc}")


    finally:

        db.close()


    # --------------------------------------------------
    # API RESPONSE
    # --------------------------------------------------

    return {
        "case_id": saved_case_id,
        "filename": file.filename,
        "sha256": evidence_hash,
        "file_size": len(raw),

        "report": {

            # Basic email metadata.
            "subject": subject,
            "sender": sender,
            "recipient": recipient,
            "cc": cc,
            "date": date,

            "reply_to": reply_to,
            "return_path": return_path,
            "message_id": message_id,

            # Raw headers.
            "headers": headers,

            # URL and domain intelligence.
            "urls": urls,
            "domains": domains,

            # All IPv4 addresses found anywhere.
            "ips": ips,

            # --------------------------------------------------
            # IDENTITY FORENSICS
            # --------------------------------------------------

            "identity_analysis": {
                "sender_domain": sender_domain,
                "reply_to_domain": reply_to_domain,
                "return_path_domain": return_path,
                "identity_mismatch": identity_mismatch,
                "reasons": identity_mismatch_reasons,
            },

            # --------------------------------------------------
            # EMAIL ROUTING FORENSICS
            # --------------------------------------------------

            "network_route": {

                "received_hops": [
                    {
                        "hop": hop["hop"],
                        "ips": hop["ips"],
                    }
                    for hop in received_chain
                ],

                "route_ips": route_ips,

                "suspected_origin": suspected_origin,
            },

            # Risk.
            "risk_score": score,
            "risk_level": risk_level,

            # ML.
            "ml_prediction": ml_prediction,
            "ml_probability": ml_probability,
            "ml_model_status": ML_MODEL_STATUS,

            # Findings.
            "findings": findings,

            # Limitations.
            "limitations": limitations,

            # Professional forensic disclaimer.
            "forensic_disclaimer": (
                "Network and IP analysis identifies "
                "approximate infrastructure information. "
                "It does not identify an individual's "
                "exact physical location."
            ),
        },
    }


# --------------------------------------------------
# SAVED CASES API
# --------------------------------------------------

@app.get("/api/cases")
def get_cases():

    db = SessionLocal()

    try:

        cases = (
            db.query(InvestigationCase)
            .order_by(
                InvestigationCase.id.desc()
            )
            .all()
        )

        return {
            "total": len(cases),

            "cases": [
                {
                    "id": case.id,

                    "case_title": case.case_title,

                    "sender_email": case.sender_email,

                    "subject": case.subject,

                    "risk_score": case.risk_score,

                    "risk_level": case.risk_level,

                    "findings": (
                        json.loads(case.findings)
                        if case.findings and isinstance(case.findings, str) and case.findings.startswith(("[", "{"))
                        else [case.findings] if case.findings else []
                    ),

                    "evidence_hash": case.evidence_hash,

                    "created_at": (
                        case.created_at.isoformat()
                        if case.created_at
                        else None
                    ),
                }

                for case in cases
            ],
        }


    finally:

        db.close()


# --------------------------------------------------
# SINGLE CASE API
# --------------------------------------------------

@app.get("/api/cases/{case_id}")
def get_case(case_id: int):

    db = SessionLocal()

    try:

        case = (
            db.query(InvestigationCase)
            .filter(
                InvestigationCase.id == case_id
            )
            .first()
        )

        if case is None:
            raise HTTPException(
                status_code=404,
                detail="Investigation case not found.",
            )

        try:
            findings = (
                json.loads(case.findings)
                if case.findings
                else []
            )

        except json.JSONDecodeError:
            findings = []

        return {
            "id": case.id,

            "case_title": case.case_title,

            "sender_email": case.sender_email,

            "subject": case.subject,

            "risk_score": case.risk_score,

            "risk_level": case.risk_level,

            "findings": findings,

            "evidence_hash": case.evidence_hash,

            "created_at": (
                case.created_at.isoformat()
                if case.created_at
                else None
            ),
        }


    finally:

        db.close()


if __name__ == "__main__":
    import uvicorn

    print("=" * 60)
    print("MATSYA Cyber Forensics Engine — FastAPI Server")
    print("API Endpoint : http://127.0.0.1:8000")
    print("Swagger Docs : http://127.0.0.1:8000/docs")
    print("=" * 60)

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
