import uuid
import datetime
from typing import Dict, Any, List


class ThreatIntelligenceEngine:
    def __init__(self):
        self.community_iocs: List[Dict[str, Any]] = [
            {
                "id": "ioc-001",
                "indicator": "https://sbi-kyc-update-pan.xyz/login",
                "threat_type": "Credential Harvesting / Banking Phishing",
                "issuer_ca": "Let's Encrypt E5 (NRD < 24h)",
                "confidence": 96,
                "upvotes": 42,
                "downvotes": 1,
                "timestamp": "2026-11-08T05:30:00Z"
            },
            {
                "id": "ioc-002",
                "indicator": "https://accounts-google-verify.com",
                "threat_type": "MITM Impersonation via Compromised CA (CVE-2026-111943)",
                "issuer_ca": "EM OV TLS CA – G3B (Weak P-384 Key d=4)",
                "confidence": 100,
                "upvotes": 118,
                "downvotes": 0,
                "timestamp": "2026-11-08T04:15:00Z"
            }
        ]

    def calculate_unified_verdict(
        self,
        url: str,
        pki_report: Dict[str, Any],
        web_report: Dict[str, Any],
        domain_report: Dict[str, Any],
        sandbox_report: Dict[str, Any]
    ) -> Dict[str, Any]:
        pki_score = pki_report.get("pki_risk_score", 0)
        domain_score = domain_report.get("domain_risk_score", 0)
        posture_score = web_report.get("posture_risk_score", 0)
        sandbox_score = sandbox_report.get("sandbox_risk_score", 0)

        if domain_report.get("is_legitimate_brand") and pki_score == 0:
            composite_score = round(posture_score * 0.2)
        else:
            weighted = (
                (pki_score * 0.35) +
                (domain_score * 0.30) +
                (sandbox_score * 0.25) +
                (posture_score * 0.10)
            )
            critical_floor = 0
            if pki_score >= 85:
                critical_floor = max(critical_floor, 92)
            if domain_score >= 60 and sandbox_score >= 40:
                critical_floor = max(critical_floor, 90)
            composite_score = min(100, max(round(weighted), critical_floor))

        if composite_score >= 75:
            verdict = "CRITICAL_THREAT"
        elif composite_score >= 45:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE_VERIFIED"

        return {
            "target_url": url,
            "composite_risk_score": composite_score,
            "verdict": verdict,
            "layer_breakdown": {
                "pki_trust_risk": pki_score,
                "domain_deception_risk": domain_score,
                "sandbox_behavioral_risk": sandbox_score,
                "web_posture_risk": posture_score
            }
        }

    def generate_stix21_bundle(self, url: str, unified_result: Dict[str, Any], pki_report: Dict[str, Any]) -> Dict[str, Any]:
        now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        indicator_id = f"indicator--{uuid.uuid4()}"
        malware_id = f"attack-pattern--{uuid.uuid4()}"
        bundle_id = f"bundle--{uuid.uuid4()}"

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": [
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": indicator_id,
                    "created": now_iso,
                    "modified": now_iso,
                    "name": f"Malicious/Phishing URL Indicator: {url}",
                    "description": (
                        f"Detected by KavachTI with risk score {unified_result['composite_risk_score']}/100 "
                        f"({unified_result['verdict']}). Issuer CA: {pki_report.get('issuer_cn', 'Unknown')}."
                    ),
                    "indicator_types": ["malicious-activity", "phishing"],
                    "pattern": f"[url:value = '{url}']",
                    "pattern_type": "stix",
                    "valid_from": now_iso,
                    "confidence": unified_result["composite_risk_score"],
                    "extensions": {
                        "x-kavachti-pki-telemetry": {
                            "sha256_fingerprint": pki_report.get("sha256_fingerprint"),
                            "serial_hex": pki_report.get("serial_hex"),
                            "crypto_audit": pki_report.get("crypto_audit")
                        }
                    }
                },
                {
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": malware_id,
                    "created": now_iso,
                    "modified": now_iso,
                    "name": "Phishing & Trust Infrastructure Impersonation",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1566.002"},
                        {"source_name": "cve", "external_id": "CVE-2026-111943"}
                    ]
                }
            ]
        }

    def vote_ioc(self, ioc_id: str, vote_type: str) -> Dict[str, Any]:
        for item in self.community_iocs:
            if item["id"] == ioc_id:
                if vote_type == "up":
                    item["upvotes"] += 1
                    item["confidence"] = min(100, item["confidence"] + 2)
                else:
                    item["downvotes"] += 1
                    item["confidence"] = max(0, item["confidence"] - 5)
                return item
        raise KeyError("IOC not found")
