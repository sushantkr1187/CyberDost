import urllib.parse
import httpx
from typing import Dict, Any, List

PROTECTED_BRAND_DOMAINS = [
    "onlinesbi.sbi", "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "npci.org.in", "bhimupi.org.in", "paytm.com", "phonepe.com", "razorpay.com",
    "incometax.gov.in", "parivahan.gov.in", "uidai.gov.in", "epfindia.gov.in",
    "tcs.com", "infosys.com", "wipro.com", "google.com", "microsoft.com"
]

HOMOGLYPH_MAP = str.maketrans({
    "0": "o", "1": "l", "!": "i", "@": "a", "$": "s", "3": "e", "5": "s"
})


def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


class WebSecurityScanner:
    def analyze_domain_deception(self, hostname: str) -> Dict[str, Any]:
        hostname = hostname.lower().strip()
        is_punycode = "xn--" in hostname
        try:
            decoded_host = hostname.encode("ascii").decode("idna")
        except Exception:
            decoded_host = hostname

        normalized = decoded_host.translate(HOMOGLYPH_MAP).replace("rn", "m").replace("-", "")
        base_label = hostname.split(".")[0].translate(HOMOGLYPH_MAP).replace("rn", "m")

        impersonated_brand = None
        min_distance = 999
        deception_reasons: List[str] = []

        if is_punycode:
            deception_reasons.append(f"IDN Punycode homograph detected ('{hostname}' renders as '{decoded_host}').")

        for brand in PROTECTED_BRAND_DOMAINS:
            if hostname == brand or hostname.endswith("." + brand):
                return {
                    "is_legitimate_brand": True,
                    "impersonated_brand": None,
                    "deception_reasons": [],
                    "domain_risk_score": 0
                }
            brand_label = brand.split(".")[0]
            dist = levenshtein_distance(base_label, brand_label)
            if brand_label in normalized and hostname != brand:
                impersonated_brand = brand
                deception_reasons.append(
                    f"Deceptive brand keyword inclusion: embeds '{brand_label}' inside external domain '{hostname}'."
                )
            elif 0 < dist <= 2 and len(brand_label) >= 4:
                if dist < min_distance:
                    min_distance = dist
                    impersonated_brand = brand
                deception_reasons.append(
                    f"Typosquatting match against '{brand}' (Levenshtein edit distance = {dist})."
                )

        suspicious_tlds = (".xyz", ".top", ".buzz", ".click", ".loan", ".work", ".gq", ".tk", ".zip")
        if hostname.endswith(suspicious_tlds):
            deception_reasons.append(f"High-abuse TLD detected ({hostname.split('.')[-1]}).")

        if hostname.count(".") >= 3:
            deception_reasons.append(f"Excessive subdomain nesting ({hostname.count('.')} levels) used to mask root domain.")

        risk_score = min(100, len(deception_reasons) * 35 + (30 if impersonated_brand else 0))
        return {
            "is_legitimate_brand": False,
            "decoded_hostname": decoded_host,
            "impersonated_brand": impersonated_brand,
            "deception_reasons": deception_reasons,
            "domain_risk_score": risk_score
        }

    async def audit_http_posture_and_exposures(self, target_url: str) -> Dict[str, Any]:
        parsed = urllib.parse.urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        headers_report = {}
        missing_headers = []
        exposed_paths = []
        posture_risk = 0

        required_headers = {
            "strict-transport-security": ("HSTS", 15),
            "content-security-policy": ("CSP", 20),
            "x-frame-options": ("X-Frame-Options", 15),
            "x-content-type-options": ("X-Content-Type-Options", 10),
            "referrer-policy": ("Referrer-Policy", 5),
        }

        async with httpx.AsyncClient(timeout=7.0, follow_redirects=True, verify=False) as client:
            try:
                resp = await client.get(target_url)
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}

                for hdr_key, (label, weight) in required_headers.items():
                    if hdr_key in resp_headers:
                        headers_report[label] = {"present": True, "value": resp_headers[hdr_key][:120]}
                    else:
                        headers_report[label] = {"present": False, "value": None}
                        missing_headers.append(label)
                        posture_risk += weight

                server_banner = resp_headers.get("server", "Hidden")
                powered_by = resp_headers.get("x-powered-by", "Hidden")

                sensitive_probes = [
                    ("/.env", ["DB_PASSWORD", "APP_KEY", "AWS_SECRET", "SECRET_KEY"]),
                    ("/.git/config", ["[core]", "repositoryformatversion", "[remote"]),
                    ("/phpinfo.php", ["PHP Version", "System", "Build Date"]),
                ]
                for path, signatures in sensitive_probes:
                    try:
                        probe_resp = await client.get(base_url + path, timeout=3.0)
                        if probe_resp.status_code == 200 and any(sig in probe_resp.text for sig in signatures):
                            exposed_paths.append(path)
                            posture_risk += 40
                    except Exception:
                        pass

            except Exception as e:
                return {"error": str(e), "posture_risk_score": 50}

        if posture_risk == 0:
            grade = "A+"
        elif posture_risk <= 15:
            grade = "A"
        elif posture_risk <= 30:
            grade = "B"
        elif posture_risk <= 50:
            grade = "C"
        else:
            grade = "F"

        return {
            "security_grade": grade,
            "headers": headers_report,
            "missing_headers": missing_headers,
            "server_banner": server_banner,
            "x_powered_by": powered_by,
            "exposed_sensitive_paths": exposed_paths,
            "posture_risk_score": min(100, posture_risk)
        }
