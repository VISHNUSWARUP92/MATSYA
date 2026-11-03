# MATSYA Cyber Forensics — React + FastAPI

HackIndia AI CyberTech Hackathon 2026 — Team MATSYA.

AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform.

---

## ⚡ Quick Start (Windows — 1-Click Launch)

Double-click `run_all.bat` to launch both Backend and Frontend automatically!
- **FastAPI Backend**: http://127.0.0.1:8000
- **Swagger Documentation**: http://127.0.0.1:8000/docs
- **React Frontend**: http://localhost:5173

---

## 🛠️ Manual Setup & Run

### 1. Backend Setup & Run (FastAPI)

In a terminal, install Python dependencies and run the backend:

```powershell
# Install required Python packages
pip install -r backend/requirements.txt

# Start the FastAPI server (Runs on port 8000)
python backend/main.py
```

*Or run:*
```powershell
run_backend.bat
```

### 2. Frontend Setup & Run (React + Vite)

In a separate terminal:

```powershell
# Install Node dependencies
npm install

# Start Vite dev server (Runs on port 5173)
npm run dev
```

*Or run:*
```powershell
run_frontend.bat
```

### 3. Retrain the AI / ML Classifier (Optional)

```powershell
python backend/train_model.py
# Or: npm run train
```
