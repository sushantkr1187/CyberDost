from difflib import SequenceMatcher
import math
import re
from typing import Any, Dict, List
from urllib.parse import urlparse
import httpx

PROTECTED_BRANDS: Dict[str, List[str]] = {
    "State Bank of India": ["onlinesbi.sbi", "sbi.co.in"],
    "HDFC Bank": ["hdfcbank.com", "netbanking.hdfcbank.com"],
    "ICICI Bank": ["icicibank.com", "infinity.icicibank.com"],
    "Axis Bank": ["axisbank.com", "axisbank.co.in"],
    "NPCI / UPI": ["npci.org.in", "bhimupi.org.in"],
    "UIDAI Aadhaar": ["uidai.gov.in", "myaadhaar.uidai.gov.in"],
    "Income Tax India": ["incometax.gov.in", "efilingindia.gov.in"],
    "Parivahan": ["parivahan.gov.in", "echallan.parivahan.gov.in"],
    "Google": ["google.com", "accounts.google.com"],
    "Microsoft": ["microsoft.com", "login.microsoftonline.com"],
}

BRAND_KEYWORDS: Dict[str, str] = {
    "sbi": "State Bank of India",
    "onlinesbi": "State Bank of India",
    "yono": "State Bank of India",
    "hdfc": "HDFC Bank",
    "icici": "ICICI Bank",
    "axisbank": "Axis Bank",
    "npci": "NPCI / UPI",
    "bhim": "NPCI / UPI",
    "aadhaar": "UIDAI Aadhaar",
    "uidai": "UIDAI Aadhaar",
    "parivahan": "Parivahan",
    "incometax": "Income Tax India",
    "microsoft": "Microsoft",
    "office365": "Microsoft",
}

LURE_TOKENS = {
    "kyc", "verify", "update", "pan", "reward", "refund", "unblock",
    "suspend", "secure", "login", "netbanking", "challan", "claim", "upi"
}

EXFIL_PATTERNS = {
    "Telegram Bot API Exfiltration": re.compile(
        r"api\.telegram\.org/bot[0-9]{8,10}:[a-zA-Z0-9_-]{35}", re.I
    ),
    "Discord Webhook Exfiltration": re.compile(
        r"discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+", re.I
    ),
    "EmailJS Client-Side Exfiltration": re.compile(
        r"api\.emailjs\.com/api/v1\.0/email/send", re.I
    ),
    "Anti-DevTools / Right-Click Blocker": re.compile(
        r"contextmenu.*preventDefault|keyCode\s*===\s*123|ctrlKey.*shiftKey.*73",
        re.I | re.S,
    ),
    "UPI Collect Intent Trap": re.compile(
        r"upi://pay\?pa=[^\"'\s>]+", re.I
    ),
}


def calculate_shannon_entropy(text: str) -> float:
    """Computes character randomness to spot DGA or auto-generated subdomains."""
    if not text:
        return 0.0
    freq = {ch: text.count(ch) for ch in set(text)}
    length = len(text)
    return round(
        -sum((count / length) * math.log2(count / length) for count in freq.values()),
        2,
    )


def analyze_typosquatting_and_idn(hostname: str) -> Dict[str, Any]:
    """Detects Punycode homographs, brand combo-squatting, and high-entropy hosts."""
    host = hostname.lower().strip()
    findings: List[str] = []
    suspected_brand = None
    risk_points = 0

    # Check if host is an official allowlisted domain
    for brand, official_domains in PROTECTED_BRANDS.items():
        if any(host == d or host.endswith(f".{d}") for d in official_domains):
            return {
                "is_official_brand_domain": True,
                "suspected_brand": brand,
                "hostname_entropy": calculate_shannon_entropy(host),
                "deception_flags": [],
                "heuristic_risk_boost": 0,
            }

    # 1. IDN / Punycode check
    if "xn--" in host or any(ord(c) > 127 for c in host):
        findings.append("IDN Punycode / Homograph character substitution detected")
        risk_points += 45

    # 2. Brand keyword + Lure combo-squatting
    tokens = set(re.split(r"[-._]", host))
    matched_lures = tokens.intersection(LURE_TOKENS)

    for kw, brand_name in BRAND_KEYWORDS.items():
        if kw in host:
            suspected_brand = brand_name
            findings.append(f"Unauthorized brand keyword '{kw}' targeting {brand_name}")
            risk_points += 40
            break

    if matched_lures:
        findings.append(f"Social engineering lure tokens in domain: {', '.join(matched_lures)}")
        risk_points += 20 if not suspected_brand else 35

    # 3. Fuzzy similarity against official root domains
    root_label = host.split(".")[0]
    for brand, official_domains in PROTECTED_BRANDS.items():
        for official in official_domains:
            off_label = official.split(".")[0]
            ratio = SequenceMatcher(None, root_label, off_label).ratio()
            if 0.78 <= ratio < 1.0 and not suspected_brand:
                suspected_brand = brand
                findings.append(
                    f"Lookalike spelling similarity ({int(ratio * 100)}%) to {official}"
                )
                risk_points += 40

    # 4. Subdomain entropy check
    entropy = calculate_shannon_entropy(host)
    if entropy > 4.1:
        findings.append(f"High hostname entropy ({entropy}) indicative of phishing kit")
        risk_points += 15

    return {
        "is_official_brand_domain": False,
        "suspected_brand": suspected_brand,
        "hostname_entropy": entropy,
        "deception_flags": findings,
        "heuristic_risk_boost": min(risk_points, 85),
    }


async def inspect_dom_exfiltration(target_url: str) -> Dict[str, Any]:
    """Scans raw HTML/JS for Telegram bots, Discord webhooks, and credential traps."""
    indicators: List[str] = []
    risk_boost = 0

    try:
        async with httpx.AsyncClient(
            timeout=5.0, follow_redirects=True, verify=False
        ) as client:
            resp = await client.get(
                target_url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            )
            html = resp.text

            for label, pattern in EXFIL_PATTERNS.items():
                if pattern.search(html):
                    indicators.append(label)
                    risk_boost += 55 if "Exfiltration" in label else 25

            # Detect external form action hijacking
            page_host = urlparse(target_url).hostname or ""
            form_actions = re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.I)
            for action in form_actions:
                if action.startswith("http"):
                    action_host = urlparse(action).hostname or ""
                    if action_host and action_host != page_host:
                        indicators.append(
                            f"Cross-origin form submission to external host ({action_host})"
                        )
                        risk_boost += 35

            # Detect Aadhaar / PAN / OTP input harvesting
            if re.search(r"(aadhaar|pan\s*card|upi\s*pin|cvv|mpin)", html, re.I) and re.search(
                r'type=["\']password["\']|maxlength=["\'][46]["\']', html, re.I
            ):
                indicators.append("Sensitive Indian KYC / OTP / PIN harvesting input fields")
                risk_boost += 30

    except Exception as exc:
        return {
            "dom_threats_detected": False,
            "indicators": [],
            "dom_risk_boost": 0,
            "error": str(exc),
        }

    return {
        "dom_threats_detected": len(indicators) > 0,
        "indicators": indicators,
        "dom_risk_boost": min(risk_boost, 95),
    }


def generate_takedown_notice(
    target_url: str,
    infra_data: Dict[str, Any],
    deception_data: Dict[str, Any],
    dom_data: Dict[str, Any],
) -> Dict[str, str]:
    """Builds a ready-to-send CERT-In and Hosting Abuse takedown report."""
    ip = infra_data.get("resolved_ip") or "Unresolved"
    asn = infra_data.get("asn") or "Unknown ASN"
    isp = infra_data.get("asn_description") or "Hosting Provider"
    brand = deception_data.get("suspected_brand") or "Financial / Enterprise Users"

    evidence_lines = (
        deception_data.get("deception_flags", []) + dom_data.get("indicators", [])
    )
    evidence_str = (
        "\n".join(f"- {item}" for item in evidence_lines)
        if evidence_lines
        else "- Automated heuristic & PKI anomaly flags triggered"
    )

    body = (
        f"URGENT ABUSE & PHISHING TAKEDOWN REQUEST\n\n"
        f"To: Abuse Team ({isp} / ASN {asn}) & CERT-In\n"
        f"Malicious URL: {target_url}\n"
        f"Resolved IP: {ip}\n"
        f"Targeted Organization: {brand}\n\n"
        f"Technical Evidence Summary:\n{evidence_str}\n\n"
        f"Please suspend the offending domain/virtual host and block outbound credential "
        f"exfiltration immediately."
    )

    return {
        "recipient_suggestion": f"incident@cert-in.org.in, abuse@{isp.lower().split()[0]}.com",
        "subject": f"[URGENT] Phishing Takedown Request - {target_url} (IP: {ip})",
        "report_body": body,
    }