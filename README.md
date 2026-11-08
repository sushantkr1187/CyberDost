# TrustMatrix — Next-Gen Intelligent Web Threat, Certificate & Phishing Defense Platform

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-30%2F30%20Passing-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Node.js%20v24+-orange.svg)]()
[![Architecture](https://img.shields.io/badge/Architecture-Zero%20External%20Dependencies-purple.svg)]()
[![STIX](https://img.shields.io/badge/Standards-STIX%202.1%20Bundle-cyan.svg)]()

> An intelligent, accessible cyber-defense platform that detects phishing, fraudulent portals, and malicious websites by uniting **threat heuristics**, **web application security auditing**, **cryptographic certificate validation (including the eMudhra TLS incident & ROCA scrutiny)**, and **collaborative threat intelligence**.

---

## 📌 Table of Contents
1. [The Problem: The Erosion of Web Trust](#-the-problem-the-erosion-of-web-trust)
2. [The eMudhra TLS Certificate Incident & Cryptographic Trust](#-the-emudhra-tls-certificate-incident--cryptographic-trust)
3. [Four Defense Pillars](#-four-defense-pillars)
4. [Platform Architecture](#-platform-architecture)
5. [Getting Started & Quick Start](#-getting-started--quick-start)
6. [CLI Scanner Utility](#-cli-scanner-utility)
7. [REST API & STIX 2.1 Feeds](#-rest-api--stix-21-feeds)
8. [Automated Test Suite](#-automated-test-suite)
9. [Preconfigured Sandbox Scenarios](#-preconfigured-sandbox-scenarios)

---

## 🚨 The Problem: The Erosion of Web Trust

The internet powers modern banking, e-commerce, recruitment, healthcare, government filings, and digital identity. However, this dependence has introduced sophisticated threats:
- **Sophisticated Phishing & Impersonation**: Cloned login portals that precisely mimic banking platforms (Chase, SBI, HDFC), enterprise portals (Workday, Office 365, Google Workspace), and government services (IRCTC, Tax portals).
- **Credential & Payment Harvesting**: Form actions exfiltrating banking PINs, credit cards, SSNs, Aadhaar, and OTPs directly to covert external servers or encrypted messaging bots (Telegram/Discord).
- **The "Green Padlock" Illusion**: Over 85% of active phishing sites now use valid HTTPS certificates from automated free domain-validated (DV) Certificate Authorities or compromised CAs. Users associate the padlock with safety, falling victim to credential theft under full TLS encryption.
- **Underlying Trust Infrastructure Vulnerabilities**: Weak cryptographic implementations, compromised or non-compliant Certificate Authorities (CAs), flawed key generation algorithms, and absent Certificate Transparency (CT) monitoring.

---

## 🔐 The eMudhra TLS Certificate Incident & Cryptographic Trust

In 2024–2025, audits by the CA/Browser Forum and independent cryptographic researchers exposed severe vulnerabilities within eMudhra’s TLS issuance infrastructure:
1. **Flawed Key Generation & Weak Randomness**: Deficiencies in pseudo-random number generator (PRNG) seeds produced subscriber keys and sub-CA parameters with reduced entropy, making RSA moduli vulnerable to factorization or recovery (analogous to the ROCA CVE-2017-15361 flaw).
2. **Delayed Certificate Transparency (CT) Logging**: Pre-certificates and certificates were logged with timing discrepancies or omitted Signed Certificate Timestamps (SCTs), concealing unauthorized issuances from domain owners.
3. **CA/B Forum Baseline Requirements Non-Compliance**: Issuance of subscriber certificates with non-standard parameters, legacy SHA-1 signatures, and inadequate validation of high-risk financial entities.

### How TrustMatrix Solves This
TrustMatrix conducts deep cryptographic and PKI inspection:
- **ROCA Factorization Test (CVE-2017-15361)**: Evaluates RSA moduli against subgroup residues across prime generators to detect Infineon/eMudhra-style weak prime generation.
- **Key Health & Entropy Scrutiny**: Enforces minimum RSA $\ge 2048$ bits, checks for low public exponents ($e=3$), even exponents, and validates elliptic curves (e.g. `secp256r1`, `secp384r1`, `ed25519`).
- **CA Pedigree & Advisory Cross-Referencing**: Continuously compares certificate issuers against active Root Store compliance notices (eMudhra, WoSign, StartCom, legacy Symantec).
- **Certificate Transparency (CT) & SCT Proofs**: Confirms presence of embedded SCTs from independent public logs (Google Argon/Xenon, Cloudflare, DigiCert).
- **DNS CAA (Certification Authority Authorization) Verification**: Confirms whether target domains enforce CAA records to prohibit unauthorized CAs from issuing rogue certificates.

---

## 🛡️ Four Defense Pillars

```
+-----------------------------------------------------------------------------------+
|                            TRUSTMATRIX COMPOSITE SCORE                            |
|                          Composite Risk Index (0 - 100)                           |
+---------------------+--------------------+--------------------+-------------------+
| 1. Threat Heuristics| 2. Certificate PKI | 3. Web App Posture | 4. Threat Intel   |
|      (35% Weight)   |    (25% Weight)    |    (20% Weight)    |    (20% Weight)   |
+---------------------+--------------------+--------------------+-------------------+
| * Homoglyph/Punycode| * eMudhra Audit    | * Grade A+ to F    | * Community IOCs  |
| * Typosquatting     | * ROCA (CVE-15361) | * CSP, HSTS, XFO   | * Peer Consensus  |
| * Brand Stuffing    | * Age (<48h check) | * Server Leaks     | * STIX 2.1 Export |
| * Form Exfiltration | * SCT Transparency | * Insecure CORS    | * Analyst Voting  |
| * Anti-Tamper JS    | * RSA >= 2048 bits | * Mixed Content    | * Live IOC Query  |
+---------------------+--------------------+--------------------+-------------------+
```

### Pillar 1: Intelligent Threat Detection & Heuristics
- **Lexical Analysis**: Detects lookalike domains, typosquatting (Damerau-Levenshtein distance to 60+ top targets), brand keyword stuffing (e.g. `chase-secure-login-portal.xyz`), high-risk disposable TLDs (`.xyz`, `.top`, `.click`, `.sbs`), and Shannon entropy calculation for DGA detection.
- **IDN Homograph & Punycode Engine**: Detects confusable characters (Cyrillic `а, о, е, р, с, у, х`, Greek lookalikes) designed to deceive visual inspection.
- **Page Content & Behavioral Inspection**: Form inspection for `<input type="password">`, credit card number inputs, CVV, SSN, Aadhaar/PAN fields, exfiltration webhooks (Telegram, Discord, mailto), social engineering urgency lures, and anti-analysis scripts (right-click disable, debugger traps).

### Pillar 2: Certificate Validation & Trust Infrastructure
- **Live TLS Socket Inspection**: Extracts raw X.509 certificate chains, protocol version (TLS 1.2, TLS 1.3), and cipher suites.
- **Certificate Age**: Flags newly minted certificates ($<48$ hours old) on unknown domains, a signature hallmark of ephemeral phishing infrastructure.
- **Subject Alternative Names (SANs)**: Validates target host against SAN list, flagging wildcard abuse or multi-tenant clusters ($>50$ unrelated domains).
- **Cryptographic Vulnerability Suite**: Executes modular residue tests for ROCA, checks prime lengths, and flags deprecated signatures (SHA-1, MD5).

### Pillar 3: Web Security Posture & Headers
- **Security Headers Scored**: Content-Security-Policy (CSP), Strict-Transport-Security (HSTS, includeSubDomains, preload), X-Frame-Options (Clickjacking defense), X-Content-Type-Options (`nosniff`), Referrer-Policy, Permissions-Policy, COOP, and CORP.
- **Letter Grade Computation**: Assigns industry-standard grades (A+, A, B, C, D, F).
- **Information Disclosure Audit**: Detects leaked software versions in `Server` or `X-Powered-By` banners and insecure CORS configurations (`Access-Control-Allow-Origin: *` with credentials).

### Pillar 4: Collaborative Threat Intelligence
- **Persistent SQLite IOC Repository**: Stores active domains, URLs, host IPs, and compromised certificate SHA-256 fingerprints using native `node:sqlite`.
- **Analyst Consensus & Peer Review**: Users and security researchers submit incident reports; verified analysts cast upvotes/downvotes. When consensus is achieved ($\ge 3$ upvotes), indicators automatically promote to the active IOC database.
- **STIX 2.1 Standard Export**: Exports full threat bundles in standardized OASIS STIX 2.1 format for SIEM/SOAR ingestion.

---

## 🏛️ Platform Architecture

```
HackMatrix/
├── package.json              # Project manifest & run scripts
├── server.js                 # HTTP Server & API entry point
├── cli.js                    # Standalone Command-Line Threat Scanner
├── src/
│   ├── app.js                # Router, REST API, and static file server
│   ├── database/
│   │   ├── db.js             # SQLite layer via native node:sqlite (ACID, WAL mode)
│   │   └── seed.js           # Seed data: IOCs, reports, advisories, monitored brands
│   ├── engines/
│   │   ├── unified_scanner.js# Master coordinator executing all 4 defense pillars
│   │   ├── threat_analyzer.js# Lexical, homoglyph, typosquatting, content heuristics
│   │   ├── cert_validator.js # TLS handshake, X509 analysis, ROCA & eMudhra audit
│   │   ├── sec_auditor.js    # Security headers scoring, grade calculation, disclosures
│   │   ├── dns_auditor.js    # A, MX, SPF, DMARC (p=reject), CAA record audit
│   │   └── scoring_engine.js # Composite Threat Risk Index (0-100) & recommendations
│   ├── threat_intel/
│   │   ├── feed_manager.js   # IOC database queries, STIX 2.1 bundle exporter
│   │   └── community.js      # Crowdsourced reporting, analyst triage & voting
│   ├── sandbox/
│   │   └── mock_targets.js   # Built-in realistic attack archetypes & baselines
│   └── utils/
│       ├── brands.js         # 60+ global/regional target brands (Banking, Tech, Govt)
│       ├── homoglyphs.js     # Unicode lookalikes, punycode decoder, Shannon entropy
│       └── crypto_audit.js   # ROCA Infineon check, small exponent, eMudhra audit
├── public/                   # Cyber SOC Dashboard Frontend
│   ├── index.html            # Responsive Dark Cyber SOC Interface
│   ├── css/styles.css        # Glassmorphic, modern cyber aesthetic styling
│   └── js/app.js             # Live gauge animations, REST API client, interactive UI
└── test/
    ├── all.js                # Master test runner (Unit + API suites)
    ├── run_tests.js          # Engine & heuristic unit tests (19 tests)
    └── api.test.js           # REST API & router integration tests (11 tests)
```

> **Zero External Dependencies**: Built entirely with Node.js standard library (`http`, `https`, `tls`, `crypto`, `dns`, `node:sqlite`, `fs`, `url`). Zero npm supply-chain vulnerabilities, zero build steps, instant startup.

---

## 🚀 Getting Started & Quick Start

### 1. Requirements
- Node.js v22.0.0 or higher (or `agy-node` / Electron Node runtime)
- Any operating system (Windows, macOS, Linux)

### 2. Launch the Platform
```bash
# Start the SOC web server (default port 3000)
agy-node server.js
```
Open **[http://localhost:3000](http://localhost:3000)** in your browser to access the interactive Cyber SOC dashboard.

---

## 💻 CLI Scanner Utility

The TrustMatrix CLI allows security operations and automated CI/CD pipelines to scan URLs directly:

```bash
# Scan a suspicious URL
agy-node cli.js scan https://chase-secure-login-portal.xyz/verify

# Scan the eMudhra vulnerable certificate archetype
agy-node cli.js scan https://suspicious-emudhra-issued-portal.com

# Scan live target with live network sockets
agy-node cli.js scan https://www.google.com --live

# View active Threat Indicators of Compromise (IOCs)
agy-node cli.js iocs

# View platform statistics
agy-node cli.js stats

# Export threat intelligence to a STIX 2.1 JSON file
agy-node cli.js export-stix > threat-feed-bundle.json
```

---

## 🌐 REST API & STIX 2.1 Feeds

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scan` | Inspect website across all 4 pillars (`{ "url": "..." }`) |
| `GET` | `/api/scans` | Retrieve recent scan history |
| `GET` | `/api/scans/:id` | Retrieve full technical telemetry for specific scan |
| `GET` | `/api/iocs` | Query active Indicators of Compromise |
| `GET` | `/api/iocs/export/stix` | Download complete threat database as STIX 2.1 JSON |
| `GET` | `/api/reports` | List community threat incident reports |
| `POST` | `/api/reports` | Submit new community threat report |
| `POST` | `/api/reports/:id/vote`| Cast analyst peer verification vote (`UPVOTE` / `DOWNVOTE`) |
| `GET` | `/api/advisories` | Retrieve CA advisories & eMudhra incident knowledge base |
| `GET` | `/api/brands` | List monitored high-value brands |
| `GET` | `/api/stats` | Retrieve platform threat statistics |

---

## 🧪 Automated Test Suite

TrustMatrix includes 30 automated unit and integration tests covering all defense modules:

```bash
# Run complete test suite (Unit + API)
agy-node test/all.js
```

### Test Coverage Highlights
- ✅ **Homoglyph & Punycode Detection**: Flags Cyrillic/Greek character spoofing.
- ✅ **Typosquatting Distance**: Flags single and double-character edit distance to target brands.
- ✅ **Credential Exfiltration**: Catches password forms dumping to Telegram/Discord webhooks.
- ✅ **Public Key Cryptography**: Flags weak RSA $< 2048$ bits and even public exponents.
- ✅ **eMudhra CA Audit**: Detects eMudhra sub-CA profiles and flags audit non-compliance.
- ✅ **Newly Issued Certificates**: Flags certificates issued $<48$ hours prior to scan.
- ✅ **Security Posture**: Calculates grades (A+ to F), checks CSP, HSTS, and CORS credentials flaws.
- ✅ **Consensus Auto-Promotion**: Verifies analyst peer votes promote reports to verified IOCs.
- ✅ **STIX 2.1 Export**: Validates OASIS STIX 2.1 bundle formatting.

---

## 🎯 Preconfigured Sandbox Scenarios

For rapid demonstrations and offline testing, five high-fidelity attack archetypes are built-in:

1. **Chase Bank Credential & Card Harvester** (`https://chase-secure-login-portal.xyz/verify`):
   - High-risk TLD `.xyz`, Chase brand stuffing, 2-hour old Let's Encrypt cert, card/CVV inputs, right-click disabled.
   - **Composite Score**: `92/100 (CRITICAL_MALICIOUS)`
2. **State Bank of India Aadhaar/PAN KYC Scam** (`https://onlinesbi-kyc-pan-update.top/login.html`):
   - Mobile smishing lure, PAN/Aadhaar/OTP harvest, credentials exfiltrated directly to Telegram bot webhook.
   - **Composite Score**: `92/100 (CRITICAL_MALICIOUS)`
3. **Fake Workday Remote Career Portal** (`https://workday-remote-career-portal.info/apply`):
   - Recruitment scam, candidate credential & SSN harvesting, advance-fee equipment deposit lure.
   - **Composite Score**: `88/100 (HIGH_RISK)`
4. **eMudhra Flawed CA Keygen & ROCA Vulnerability** (`https://suspicious-emudhra-issued-portal.com`):
   - eMudhra CA issuer, weak 1024-bit RSA key, ROCA Infineon pattern, deprecated SHA-1, missing CT SCTs.
   - **Composite Score**: `92/100 (CRITICAL_MALICIOUS)`
5. **Authentic JPMorgan Chase (Official Bank)** (`https://www.chase.com`):
   - DigiCert EV certificate, strict CSP, HSTS preload, DMARC p=reject, strict CAA enforcement.
   - **Composite Score**: `2/100 (SAFE, Grade A+)`
