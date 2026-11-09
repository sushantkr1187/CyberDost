import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from module_1_pki_auditor import PKIAuditor
from module_2_web_security import WebSecurityScanner


def generate_weak_scalar_certificate(scalar_d: int = 4) -> bytes:
    weak_private_key = ec.derive_private_key(scalar_d, ec.SECP384R1(), default_backend())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.COMMON_NAME, "accounts.google.com"),
    ])
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.COMMON_NAME, "EM OV TLS CA – G3B"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(weak_private_key.public_key())
        .serial_number(int("c7c41efe92d825f05eae841a4a82c1", 16))
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("accounts.google.com")]),
            critical=False,
        )
        .sign(weak_private_key, hashes.SHA384(), default_backend())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def run_verification_suite():
    print("=== 1. Testing Low-Entropy ECC Key Recovery & CA Audit (CVE-2026-111943) ===")
    auditor = PKIAuditor(max_ecc_scalar_check=512)
    forged_pem = generate_weak_scalar_certificate(scalar_d=4)
    report = auditor.inspect_pem_or_der(forged_pem, is_pem=True)

    assert report["crypto_audit"]["vulnerable"] is True
    assert report["crypto_audit"]["recovered_scalar"] == 4
    assert report["pki_risk_score"] == 100
    print(f"[PASS] Recovered weak ECC private scalar d={report['crypto_audit']['recovered_scalar']}")
    print(f"[PASS] PKI Risk Score: {report['pki_risk_score']}/100 | Warnings: {report['warnings']}\n")

    print("=== 2. Testing Typosquatting & Homoglyph Detection ===")
    scanner = WebSecurityScanner()
    phish_host = "on1inesbi-kyc-update.xyz"
    dom_report = scanner.analyze_domain_deception(phish_host)

    assert dom_report["impersonated_brand"] in ("onlinesbi.sbi", "sbi.co.in")
    assert dom_report["domain_risk_score"] >= 60
    print(f"[PASS] Flagged '{phish_host}' impersonating '{dom_report['impersonated_brand']}'")
    print(f"[PASS] Reasons: {dom_report['deception_reasons']}")


if __name__ == "__main__":
    run_verification_suite()
