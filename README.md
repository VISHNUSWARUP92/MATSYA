# 🛡️ MATSYA — Cyber Intelligence Platform

### AI-Powered Email Threat Detection & Digital Forensics

**MATSYA** is an email threat analysis and digital forensic investigation platform designed to help security analysts investigate suspicious emails, identify potential phishing indicators, and visualize email infrastructure intelligence.

## 🚀 Project Overview

Email-based cyberattacks, phishing campaigns, sender spoofing, and malicious URLs are major cybersecurity threats.

MATSYA provides a unified investigation workspace where users can upload suspicious `.eml` files and analyze email metadata, sender information, URLs, IP addresses, and potential security indicators.

## ✨ Key Features

- **Email Threat Detection:** Analyze suspicious emails and identify potential phishing indicators.
- **Email Forensics:** Extract email headers, sender details, metadata, and URLs.
- **ML-Based Classification:** Use a machine learning model to assist in classifying suspicious emails.
- **IP Geolocation:** Visualize approximate locations associated with public IP infrastructure.
- **Threat Intelligence:** Investigate extracted domains, IP addresses, and URLs.
- **Email Comparator:** Compare two emails to identify content similarities and forensic differences.
- **Attack Graph:** Visualize relationships between investigation entities.
- **Risk Assessment:** Generate risk scores and threat classifications.
- **Forensic Reports:** Generate investigation reports for analysis.

## 🧰 Technology Stack

| Component | Technologies |
|---|---|
| Frontend | React.js, Vite, JavaScript |
| Backend | Python, FastAPI |
| Machine Learning | Scikit-learn |
| Database | SQLite |
| Visualization | React-based charts and maps |
| Authentication | Firebase Authentication |
| Version Control | Git and GitHub |

## 🏗️ System Architecture

```text
              USER
                |
                v
        REACT FRONTEND
                |
                v
          FASTAPI BACKEND
                |
       +--------+---------+
       |        |         |
       v        v         v
   EMAIL     ML MODEL   THREAT
  PARSING   CLASSIFIER INTELLIGENCE
       |        |         |
       +--------+---------+
                |
                v
         RISK ASSESSMENT
                |
                v
       GEOLOCATION & GRAPH
                |
                v
        FORENSIC REPORT
```

## ⚙️ Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/VISHNUSWARUP92/MATSYA.git
cd MATSYA
```

### 2. Frontend Setup

```bash
npm install
npm run dev
```

### 3. Backend Setup

Open another terminal:

```bash
cd backend
python -m venv .venv
```

Activate virtual environment on Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start FastAPI:

```bash
python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Backend API documentation:

```text
http://127.0.0.1:8000/docs
```

## 🔬 Investigation Workflow

1. Upload a suspicious `.eml` email.
2. Extract email headers and metadata.
3. Analyze sender identity and authentication indicators.
4. Extract URLs, domains, and public IP addresses.
5. Run ML-assisted threat classification.
6. Review risk score and forensic findings.
7. Investigate infrastructure and approximate geolocation.
8. Generate a forensic investigation report.

## 🔐 Security & Limitations

- IP geolocation represents approximate network infrastructure locations, not an individual's exact physical location.
- Machine learning predictions are supporting signals, not definitive proof of malicious activity.
- SPF, DKIM, and DMARC information depends on the available email authentication headers.
- External threat intelligence integrations may require API credentials.
- Production deployment requires secure environment variables, persistent database storage, and appropriate access controls.

## 🔮 Future Scope

- Advanced phishing detection models.
- Integration with live threat intelligence feeds.
- Improved email authentication verification.
- Blockchain-based forensic evidence integrity.
- Advanced attack relationship visualization.
- Scalable cloud deployment.

## 👨‍💻 Project

**Project Name:** MATSYA — Cyber Intelligence Platform

**Domain:** Cybersecurity & Digital Forensics

**GitHub:** https://github.com/VISHNUSWARUP92/MATSYA

---

*Built to make email threat investigation more accessible, structured, and intelligent.*