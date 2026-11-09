# CyberDost — Unified Phishing, PKI Trust & Web Security Intelligence Platform

CyberDost correlates cryptographic trust chains, network transport posture, visual/DOM headless sandboxing, and collaborative STIX 2.1 threat intelligence into a unified zero-trust defensive platform.

## Project Structure

```text
CyberDost-platform/
├── docker-compose.yml                   # Multi-container orchestration (Backend API + PostgreSQL)
├── README.md                            # Architecture documentation & setup guide
├── backend/                             # Python FastAPI Detection & Intelligence Engines
│   ├── Dockerfile                       # Playwright + Python 3.11 container image definition
│   ├── requirements.txt                 # Python dependencies
│   ├── schema.sql                       # PostgreSQL tables for scans, X.509 certs & STIX IOCs
│   ├── module_1_pki_auditor.py          # Layer A: Small-scalar ECC recovery, RSA GCD & CT log monitor
│   ├── module_2_web_security.py         # Layer B: IDN homographs, typosquatting, headers & /.env probe
│   ├── module_3_sandbox_visual.py       # Layer C: Headless Chromium, DOM hooks & 64-bit pHash similarity
│   ├── module_4_threat_intel_stix.py    # Layer D: Multi-layer risk fusion, voting & STIX 2.1 generator
│   ├── module_5_api_server.py           # FastAPI gateway & concurrent scan orchestrator
│   └── test_CyberDost.py                 # Automated test suite & CVE-2026-111943 exploit simulator
├── frontend/                            # React + Tailwind SOC Analyst Dashboard
│   ├── package.json
│   ├── vite.config.js
│   ├── index.html
│   └── src/
│       ├── main.jsx
│       ├── index.css
│       └── App.jsx
└── extension/                           # Chrome / Edge / Brave Real-Time Browser Guard (MV3)
    ├── manifest.json
    └── background.js
```

## Quick Start

### 1. Run Cryptographic & Phishing Verification Tests
```bash
cd backend
pip install -r requirements.txt
python test_CyberDost.py
```

### 2. Run Backend API Server
```bash
cd backend
playwright install chromium
uvicorn module_5_api_server:app --host 0.0.0.0 --port 8000 --reload
```

### 3. Run Frontend SOC Dashboard
```bash
cd frontend
npm install
npm run dev
```

### 4. Load Real-Time Browser Extension Guard
1. Open `chrome://extensions` in Chrome, Edge, or Brave.
2. Enable **Developer mode**.
3. Click **Load unpacked** and select the `extension/` folder.
