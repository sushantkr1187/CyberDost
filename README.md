# CyberDost
### Intelligent Phishing Detection & Multi-Layer Web Security Intelligence Platform

<p align="center">
  <img src="https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=white" alt="React" />
  <img src="https://img.shields.io/badge/Vite-5-646CFF?style=for-the-badge&logo=vite&logoColor=white" alt="Vite" />
  <img src="https://img.shields.io/badge/Tailwind_CSS-3-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white" alt="Tailwind CSS" />
  <img src="https://img.shields.io/badge/JavaScript-ES6+-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black" alt="JavaScript" />
  <img src="https://img.shields.io/badge/License-Apache_2.0-blue?style=for-the-badge" alt="Apache License 2.0" />
</p>

<p align="center"> 
<b>Detect. Analyse. Verify. Protect.</b> </br>
<i>An integrated security intelligence platform designed to identify phishing websites, investigate suspicious domains, assess TLS/PKI trust, analyse web security posture, and facilitate collaborative threat intelligence.</i>
</p>

---

## Overview

CyberDost is a multi-layer web security analysis platform that aims to make phishing detection more comprehensive than conventional URL reputation checks.

Traditional phishing detection systems often rely heavily on domain blacklists, URL signatures, or isolated reputation signals. CyberDost takes a broader approach by correlating multiple security indicators, including domain deception, certificate trust, cryptographic properties, HTTP security configuration, and suspicious website behaviour.

The platform combines these analysis layers into a unified risk assessment, presenting technical findings through an accessible security operations dashboard.

Its objective is to help users understand not only whether a website appears suspicious, but also *why it may be dangerous*.

## Core Capabilities

### 1. Multi-Layer Phishing Detection

Analyse suspicious URLs through four complementary security assessment layers.

| Layer | Analysis |
|---|---|
| Layer A — PKI & Certificate Trust | TLS certificate properties, trust status, issuer information and cryptographic indicators |
| Layer B — Domain Deception | Suspicious hostnames, brand impersonation, homoglyphs and domain structure |
| Layer C — Behavioural Analysis | Suspicious page behaviour, credential collection indicators and visual similarity |
| Layer D — Web Security Posture | HTTP security headers, server exposure and potentially sensitive endpoints |

The platform combines these findings into a composite risk score (0–100) to help communicate the overall assessment.

### 2. Domain & Brand Impersonation Analysis

Identify suspicious domain characteristics, including:

- Homoglyph and character-substitution attacks.
- Brand-name impersonation.
- Deceptive subdomain structures.
- Suspicious hostname patterns.
- Potentially abusive domain extensions.

### 3. PKI & Certificate Security Auditor

Examine certificate-related security information and cryptographic properties.

Features include:

- X.509 certificate subject and issuer inspection.
- Certificate validity information.
- Operating-system/browser trust indicators.
- SHA-256 certificate fingerprints.
- Cryptographic algorithm identification.
- Elliptic-curve key entropy analysis.
- Certificate-related security warnings.

The PKI analysis interface also includes an experimental low-entropy elliptic-curve scalar analysis demonstration.

### 4. Web Security Posture Assessment

Evaluate important web security configurations, including:

- Content Security Policy (CSP).
- HTTP Strict Transport Security (HSTS).
- X-Frame-Options.
- Server banner exposure.
- Potentially exposed sensitive paths.
- Overall HTTP security posture grading.

### 5. Behavioural & Visual Analysis

The platform presents behavioural findings such as:

- Suspicious password and OTP input fields.
- Potential credential-exfiltration indicators.
- Unusual page restrictions.
- Brand-template similarity.
- Visual clone detection indicators.

### 6. Collaborative Threat Intelligence

CyberDost includes a community-oriented threat intelligence interface.

Capabilities include:

- IOC (Indicator of Compromise) feed.
- Threat classification.
- Confidence scoring.
- Community upvotes and downvotes.
- Collaborative threat verification.

### 7. STIX 2.1 Intelligence Export

Generate structured threat intelligence representations using the STIX 2.1 bundle format.

The scanner supports:

- Indicator objects.
- URL-based STIX patterns.
- Confidence values.
- Certificate-related metadata extensions.
- JSON inspection and copying.

---

## System Architecture

CyberDost follows a frontend-backend architecture.

```text
                  USER
                    |
                    v
          REACT SECURITY DASHBOARD
                    |
          +---------+---------+
          |         |         |
          v         v         v
       SCANNER     PKI      THREAT
       MODULE     AUDITOR   INTELLIGENCE
          |         |         |
          +---------+---------+
                    |
                    v
               REST API
                    |
                    v
              FASTAPI BACKEND
                    |
          +---------+---------+
          |         |         |
          v         v         v
       DOMAIN     CERTIFICATE  WEB &
       ANALYSIS   ANALYSIS     BEHAVIOUR
          |         |         |
          +---------+---------+
                    |
                    v
          CORRELATED FINDINGS
                    |
                    v
          RISK ASSESSMENT
                    |
                    v
          DASHBOARD & STIX 2.1
```

*Note: This diagram represents the intended logical analysis workflow. Actual analysis execution depends on the backend implementation and its configured services.*

## Technology Stack

### Frontend

- **React 18** — Component-based user interface.
- **Vite 5** — Development server and build tooling.
- **Tailwind CSS 3** — Utility-first styling.
- **Lucide React** — Interface iconography.
- **JavaScript (ES Modules)** — Application logic.

### Backend Integration

- **FastAPI** — REST API integration.
- **REST / JSON** — Frontend-backend communication.
- **STIX 2.1** — Structured threat intelligence representation.

### Security Concepts

- X.509 and TLS certificates.
- Public Key Infrastructure (PKI).
- Elliptic Curve Cryptography (ECC).
- Domain impersonation and homoglyph detection.
- HTTP security headers.
- Indicators of Compromise (IOCs).
- Behavioural security analysis.

---

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

---

## Getting Started

### Prerequisites

Ensure that the following are installed:

- Node.js 18 or later.
- npm.
- Git.

### 1. Clone the Repository

```bash
git clone https://github.com/sushantkr1187/CyberDost.git
```

```bash
cd CyberDost
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Start the Development Server

```bash
npm run dev
```

Vite will start the application, typically at:

```text
http://localhost:5173
```

### 4. Create a Production Build

```bash
npm run build
```

### 5. Preview the Production Build

```bash
npm run preview
```

---

## Backend API Integration

The current frontend communicates with the deployed backend through REST endpoints.

**Backend base URL:**

```text
https://cyberdost-1.onrender.com
```

### Available API integrations

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/v1/intel/feed` | Retrieve threat intelligence feed |
| POST | `/api/v1/scan` | Submit a URL for security analysis |
| POST | `/api/v1/intel/vote/{id}/{dir}` | Submit a community intelligence vote |

### URL Scan Request

```json
{
  "url": "https://example.com",
  "run_headless_sandbox": false
}
```

The frontend expects a structured response containing fields such as:

- `summary`
- `domain_analysis`
- `pki_certificate_audit`
- `web_security_posture`
- `sandbox_behavioral_analysis`
- `stix_2_1_bundle`

The scanner also includes predefined demonstration scenarios that allow users to explore the dashboard when live analysis is unavailable.

**Backend compatibility:** The frontend currently uses a fixed backend URL. Update the endpoint configuration in `src/App.jsx` if you deploy your own backend.

---

## Risk Assessment

CyberDost uses a composite risk score to communicate the severity of detected indicators.

| Risk Score | Classification |
|---|---|
| 0–44 | Low |
| 45–74 | Suspicious |
| 75–100 | Critical |

These thresholds represent the frontend's current presentation logic, not a universally accepted security classification standard.

A high score should trigger further investigation rather than being treated as definitive proof of malicious activity.

---

## Current Development Status

CyberDost is an actively developing security intelligence project.

| Component | Status |
|---|---|
| React security dashboard | Implemented |
| Interactive URL scanner interface | Implemented |
| Four-layer risk visualization | Implemented |
| Domain deception findings interface | Implemented |
| PKI and certificate auditing interface | Implemented |
| HTTP security posture interface | Implemented |
| Behavioural analysis findings interface | Implemented |
| Threat intelligence feed integration | Implemented |
| Community voting interface | Implemented |
| STIX 2.1 JSON representation | Implemented |
| Live backend integration | Connected through configured API |
| Production-grade end-to-end security validation | Requires further verification |

*Implemented interfaces and frontend integrations should not be confused with independently verified backend detection capabilities.*

---

## Security & Responsible Use

CyberDost is intended for educational, defensive cybersecurity research and authorised security assessment.

Please follow these principles:

- Only submit URLs for which you have a legitimate reason to perform security analysis.
- Do not attempt to access, exploit or disrupt systems without authorisation.
- Treat automated detection results as indicators requiring verification.
- Never enter actual passwords, OTPs, banking credentials or other sensitive information into suspicious websites.
- Do not interpret a valid TLS certificate as proof that a website is legitimate.

CyberDost is not a substitute for professional security auditing or independent threat verification.

---

## AI-Assisted Development

AI tools played a supporting role throughout the development of CyberDost, helping accelerate implementation, refine the user interface, explore technical approaches, and improve documentation.

Tools used:

- **Google Gemini** — Assisted with development ideas, technical exploration, problem-solving, and implementation support.
- **OpenAI ChatGPT** — Assisted with code development, debugging, UI/UX refinement, architectural discussions, and documentation.

The final implementation, integration, testing, and project decisions remain the responsibility of the project developer.

---

## Future Roadmap

Potential areas of further development include:

- Real-time DNS and domain reputation intelligence.
- WHOIS and domain registration history analysis.
- Certificate Transparency log monitoring.
- Advanced homograph and IDN detection.
- Reputation correlation with external threat intelligence feeds.
- More comprehensive sandbox-based behavioural analysis.
- Automated redirect-chain inspection.
- Explainable risk scoring with confidence calibration.
- Historical threat tracking and analytics.
- API authentication, rate limiting and abuse prevention.
- Improved STIX interoperability and TAXII integration.

---

## Project Contributors

CyberDost was collaboratively developed by the following team members:

| Contributor | Name |
|---|---|
| 1 | **Sushant Kumar Kushwaha** |
| 2 | **Raktim Kangsha Banik** |
| 3 | **Shivam Poddar** |
| 4 | **Dhruba Ghosh** |

We collaborated on the development and implementation of CyberDost, contributing to building a unified platform for phishing detection, web security assessment, and collaborative threat intelligence.

**Project Team:** 0bit  

---

## Contributing

Contributions, suggestions, bug reports and feature requests are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Implement your changes.
4. Test the functionality.
5. Submit a pull request with a clear description.

Please ensure that security-related contributions are reproducible and appropriately documented.

---

## License
This project is licensed under the Apache License 2.0.

You may use, reproduce, modify, and distribute this software in accordance with the terms and conditions of the Apache License, Version 2.0.

A copy of the license should be included in the repository as a file named LICENSE.

Read the full license here:

[Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)

Copyright © 2026 CyberDost Contributors.

---

<p align="center">
  <strong>CyberDost — Making the digital world safer.</strong>
</p>
