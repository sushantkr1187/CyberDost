import ssl
import socket
import math
import datetime
import httpx
from typing import Dict, Any, List
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes

COMPROMISED_INTERMEDIATE_ISSUERS = {
    "EM EV TLS CA – G3B", "EM OV TLS CA – G3B", "EM DV TLS CA – G3B",
    "EM EV TLS CA – G3C", "EM OV TLS CA – G3C", "EM DV TLS CA – G3C",
    "EM OV CS CA – G3B", "EM OV CS CA – G3C",
    "EM EV TLS CA - G3B", "EM OV TLS CA - G3B", "EM DV TLS CA - G3B",
    "EM EV TLS CA - G3C", "EM OV TLS CA - G3C", "EM DV TLS CA - G3C",
}

COMPROMISED_SERIAL_HEX = {
    "c7c41efe92d825f05eae841a4a82c1",
    "6cada367fb1c100088120ea202d568",
    "a4aee678f23362b4c0e460b772f214",
    "8009928a64107601af05fa2f19f109",
    "296926c227a3a1526392b19482a504",
    "588b2e3c2bb8cda13e1a1209254321",
}

SMALL_PRIMES_PRODUCT = math.prod([
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151
])


class PKIAuditor:
    def __init__(self, max_ecc_scalar_check: int = 1024):
        self.max_ecc_scalar_check = max_ecc_scalar_check

    def check_ecc_low_entropy(self, pub_key: ec.EllipticCurvePublicKey) -> Dict[str, Any]:
        numbers = pub_key.public_numbers()
        curve = pub_key.curve
        for d in range(1, self.max_ecc_scalar_check + 1):
            candidate_priv = ec.derive_private_key(d, curve, default_backend())
            cand_nums = candidate_priv.public_key().public_numbers()
            if cand_nums.x == numbers.x and cand_nums.y == numbers.y:
                return {
                    "vulnerable": True,
                    "recovered_scalar": d,
                    "entropy_bits": round(math.log2(max(d, 2)), 2),
                    "reason": f"CRITICAL: Private key recovered via small-scalar search (d={d})."
                }
        return {"vulnerable": False, "entropy_bits": curve.key_size}

    def check_rsa_modulus(self, pub_key: rsa.RSAPublicKey) -> Dict[str, Any]:
        n = pub_key.public_numbers().n
        e = pub_key.public_numbers().e
        key_size = pub_key.key_size
        issues = []

        if key_size < 2048:
            issues.append(f"Weak RSA modulus size ({key_size} bits < 2048 bits).")
        if e < 65537:
            issues.append(f"Suspiciously small RSA public exponent (e={e}).")
        if math.gcd(n, SMALL_PRIMES_PRODUCT) > 1:
            issues.append("CRITICAL: RSA modulus contains trivial small prime factors.")

        return {
            "vulnerable": len(issues) > 0,
            "key_size": key_size,
            "exponent": e,
            "issues": issues
        }

    def inspect_pem_or_der(self, cert_bytes: bytes, is_pem: bool = False) -> Dict[str, Any]:
        cert = (
            x509.load_pem_x509_certificate(cert_bytes, default_backend())
            if is_pem else
            x509.load_der_x509_certificate(cert_bytes, default_backend())
        )

        now = datetime.datetime.now(datetime.timezone.utc)
        serial_hex = format(cert.serial_number, "x").lower()
        fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()

        issuer_cn = ""
        for attr in cert.issuer:
            if attr.oid == x509.NameOID.COMMON_NAME:
                issuer_cn = attr.value

        subject_cn = ""
        for attr in cert.subject:
            if attr.oid == x509.NameOID.COMMON_NAME:
                subject_cn = attr.value

        warnings: List[str] = []
        risk_points = 0

        if issuer_cn in COMPROMISED_INTERMEDIATE_ISSUERS or serial_hex in COMPROMISED_SERIAL_HEX:
            warnings.append(
                f"CRITICAL (CVE-2026-111943): Chains to compromised/revoked CA '{issuer_cn}' (Serial: {serial_hex})."
            )
            risk_points += 90

        days_remaining = (cert.not_valid_after_utc - now).days
        cert_age_days = (now - cert.not_valid_before_utc).days
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            warnings.append("Certificate is expired or not yet valid.")
            risk_points += 50
        elif cert_age_days <= 2:
            warnings.append(f"Newly issued certificate ({cert_age_days} days old) — common in short-lived phishing kits.")
            risk_points += 20

        pub_key = cert.public_key()
        crypto_audit = {}
        if isinstance(pub_key, ec.EllipticCurvePublicKey):
            ecc_check = self.check_ecc_low_entropy(pub_key)
            crypto_audit = {"type": f"ECC-{pub_key.curve.name}", **ecc_check}
            if ecc_check["vulnerable"]:
                warnings.append(ecc_check["reason"])
                risk_points += 100
        elif isinstance(pub_key, rsa.RSAPublicKey):
            rsa_check = self.check_rsa_modulus(pub_key)
            crypto_audit = {"type": f"RSA-{pub_key.key_size}", **rsa_check}
            if rsa_check["vulnerable"]:
                warnings.extend(rsa_check["issues"])
                risk_points += 75

        sans: List[str] = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            warnings.append("Missing SubjectAlternativeName (SAN) extension.")
            risk_points += 25

        return {
            "subject_cn": subject_cn,
            "issuer_cn": issuer_cn,
            "serial_hex": serial_hex,
            "sha256_fingerprint": fingerprint_sha256,
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "days_remaining": days_remaining,
            "sans": sans,
            "crypto_audit": crypto_audit,
            "warnings": warnings,
            "pki_risk_score": min(100, risk_points)
        }

    async def query_ct_logs(self, domain: str) -> Dict[str, Any]:
        url = f"https://crt.sh/?q={domain}&output=json"
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return {"ct_entries_found": 0, "recent_24h_issuances": 0, "status": "UNAVAILABLE"}
                entries = resp.json()
                cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=24)
                recent_count = 0
                issuers = set()
                for item in entries[:100]:
                    issuers.add(item.get("issuer_name", "Unknown"))
                    logged_str = item.get("entry_timestamp", "")
                    if logged_str:
                        try:
                            ts = datetime.datetime.fromisoformat(logged_str.replace("Z", "+00:00"))
                            if ts.tzinfo is None:
                                ts = ts.replace(tzinfo=datetime.timezone.utc)
                            if ts >= cutoff:
                                recent_count += 1
                        except ValueError:
                            pass
                return {
                    "ct_entries_found": len(entries),
                    "recent_24h_issuances": recent_count,
                    "distinct_issuers": list(issuers)[:5],
                    "issuance_spike_detected": recent_count > 10
                }
        except Exception as e:
            return {"ct_entries_found": 0, "error": str(e)}

    async def audit_live_host(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        os_trusted = True
        tls_error = None
        der_cert = None

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
        except ssl.SSLCertVerificationError as e:
            os_trusted = False
            tls_error = str(e)
            ctx_unverified = ssl._create_unverified_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx_unverified.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
        except Exception as e:
            return {"error": f"TLS handshake failed: {str(e)}", "pki_risk_score": 85}

        cert_report = self.inspect_pem_or_der(der_cert, is_pem=False)
        ct_report = await self.query_ct_logs(hostname)

        if not os_trusted:
            cert_report["warnings"].insert(0, f"OS/Browser Trust Store rejected chain: {tls_error}")
            cert_report["pki_risk_score"] = min(100, cert_report["pki_risk_score"] + 60)

        if ct_report.get("issuance_spike_detected"):
            cert_report["warnings"].append(
                f"Anomalous CT Log spike: {ct_report['recent_24h_issuances']} certificates issued in last 24h."
            )
            cert_report["pki_risk_score"] = min(100, cert_report["pki_risk_score"] + 30)

        cert_report["os_trusted"] = os_trusted
        cert_report["ct_log_telemetry"] = ct_report
        return cert_report
