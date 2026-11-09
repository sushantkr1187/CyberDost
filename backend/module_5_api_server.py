import asyncio
import base64
import urllib.parse
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from intelligence import (
    check_urlhaus,
    analyze_screenshot_phash,
    profile_infrastructure,
    analyze_typosquatting_and_idn,
    inspect_dom_exfiltration,
    generate_takedown_notice,
)

from module_1_pki_auditor import PKIAuditor
from module_2_web_security import WebSecurityScanner
from module_3_sandbox_visual import SandboxVisualAnalyzer
from module_4_threat_intel_stix import ThreatIntelligenceEngine

app = FastAPI(
    title="KavachTI Security & PKI Intelligence API",
    version="2.1.0",
    description="Unified Phishing Detection, PKI Entropy Validation & STIX 2.1 Threat Intelligence",
)

# Wildcard CORS with allow_credentials=False ensures strict browser compliance
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

pki_auditor = PKIAuditor()
web_scanner = WebSecurityScanner()
sandbox_analyzer = SandboxVisualAnalyzer()
intel_engine = ThreatIntelligenceEngine()


class URLScanRequest(BaseModel):
    url: str
    run_headless_sandbox: bool = True


class PEMInspectRequest(BaseModel):
    pem_data: str


class IOCSubmission(BaseModel):
    indicator: str
    threat_type: str
    issuer_ca: str = "Unknown"


async def capture_page_screenshot_playwright(url: str) -> bytes | None:
    """Captures a viewport screenshot via headless Chromium for pHash comparison."""
    try:
        from playwright.async_api import async_playwright

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox"],
            )
            page = await browser.new_page(viewport={"width": 1280, "height": 800})
            await page.goto(url, wait_until="domcontentloaded", timeout=10000)
            screenshot_bytes = await page.screenshot(full_page=False)
            await browser.close()
            return screenshot_bytes
    except Exception:
        return None


@app.post("/api/v1/scan")
async def full_url_scan(req: URLScanRequest):
    try:
        raw_url = req.url.strip()
        parsed = urllib.parse.urlparse(
            raw_url if "://" in raw_url else f"https://{raw_url}"
        )
        hostname = parsed.hostname
        if not hostname:
            raise HTTPException(status_code=400, detail="Invalid URL supplied.")

        normalized_url = f"{parsed.scheme}://{hostname}{parsed.path or '/'}"

        # 1. Synchronous heuristic domain & typosquatting analysis
        try:
            domain_report = web_scanner.analyze_domain_deception(hostname)
        except Exception:
            domain_report = {
                "is_legitimate_brand": False,
                "decoded_hostname": hostname,
                "impersonated_brand": None,
                "deception_reasons": [],
                "domain_risk_score": 0,
            }

        advanced_deception = analyze_typosquatting_and_idn(hostname)

        # 2. Concurrent execution with return_exceptions=True so dead domains never crash the API
        feed_task = check_urlhaus(normalized_url)
        infra_task = asyncio.to_thread(profile_infrastructure, hostname)
        pki_task = pki_auditor.audit_live_host(hostname)
        web_task = web_scanner.audit_http_posture_and_exposures(normalized_url)
        dom_exfil_task = inspect_dom_exfiltration(normalized_url)

        default_sandbox = {
            "page_title": "Sandbox Skipped / Offline Host",
            "visual_analysis": {
                "computed_phash": None,
                "closest_brand_template": "None",
                "visual_similarity_pct": 0.0,
                "visual_clone_alert": False,
            },
            "behavioral_flags": [],
            "sandbox_risk_score": 0,
        }

        sandbox_task = (
            sandbox_analyzer.inspect_url_in_sandbox(normalized_url)
            if req.run_headless_sandbox
            else asyncio.sleep(0, result=default_sandbox)
        )

        results = await asyncio.gather(
            feed_task,
            infra_task,
            pki_task,
            web_task,
            dom_exfil_task,
            sandbox_task,
            return_exceptions=True,
        )

        feed_hit = results[0] if isinstance(results[0], dict) else {"is_blacklisted": False}
        infra_data = results[1] if isinstance(results[1], dict) else {"resolved_ip": None, "asn_description": "Unresolved"}
        pki_report = results[2] if isinstance(results[2], dict) else {
            "subject_cn": hostname,
            "issuer_cn": "Unreachable / No TLS",
            "serial_hex": "N/A",
            "os_trusted": False,
            "crypto_audit": {"type": "None", "vulnerable": False, "entropy_bits": 0},
            "warnings": ["Host unreachable for live TLS handshake"],
            "pki_risk_score": 50,
        }
        web_report = results[3] if isinstance(results[3], dict) else {
            "security_grade": "F",
            "server_banner": "Offline / Unreachable",
            "missing_headers": ["CSP", "HSTS", "X-Frame-Options"],
            "exposed_sensitive_paths": [],
            "posture_risk_score": 50,
        }
        dom_exfil_report = results[4] if isinstance(results[4], dict) else {
            "dom_threats_detected": False,
            "indicators": [],
            "dom_risk_boost": 0,
        }
        sandbox_report = results[5] if isinstance(results[5], dict) else default_sandbox

        # 3. Visual Phishing pHash analysis
        visual_data = {
            "visual_phishing_detected": False,
            "page_phash": None,
            "matched_brands": [],
        }
        if req.run_headless_sandbox:
            screenshot_bytes = None
            b64_img = sandbox_report.get("screenshot_b64") or sandbox_report.get("screenshot")
            if isinstance(b64_img, str):
                try:
                    clean_b64 = b64_img.split(",")[-1]
                    screenshot_bytes = base64.b64decode(clean_b64)
                except Exception:
                    screenshot_bytes = None

            if not screenshot_bytes:
                screenshot_bytes = await capture_page_screenshot_playwright(normalized_url)

            if screenshot_bytes:
                visual_data = analyze_screenshot_phash(screenshot_bytes)

        # 4. Generate automated CERT-In / Hosting Provider takedown draft
        takedown_draft = generate_takedown_notice(
            normalized_url, infra_data, advanced_deception, dom_exfil_report
        )

        # Merge advanced heuristic flags into domain & sandbox reports for UI display
        if isinstance(domain_report, dict):
            domain_report["infrastructure_profile"] = infra_data
            domain_report["advanced_deception"] = advanced_deception
            existing_reasons = domain_report.get("deception_reasons", [])
            for flag in advanced_deception.get("deception_flags", []):
                if flag not in existing_reasons:
                    existing_reasons.append(flag)
            domain_report["deception_reasons"] = existing_reasons
            if not domain_report.get("impersonated_brand") and advanced_deception.get("suspected_brand"):
                domain_report["impersonated_brand"] = advanced_deception["suspected_brand"]
            domain_report["domain_risk_score"] = max(
                domain_report.get("domain_risk_score", 0),
                advanced_deception.get("heuristic_risk_boost", 0),
            )

        if isinstance(sandbox_report, dict):
            sandbox_report["visual_phash_analysis"] = visual_data
            sandbox_report["dom_exfiltration_analysis"] = dom_exfil_report
            existing_flags = sandbox_report.get("behavioral_flags", [])
            for ind in dom_exfil_report.get("indicators", []):
                if ind not in existing_flags:
                    existing_flags.append(ind)
            sandbox_report["behavioral_flags"] = existing_flags

        # 5. Calculate unified verdict safely
        try:
            unified = intel_engine.calculate_unified_verdict(
                normalized_url, pki_report, web_report, domain_report, sandbox_report
            )
        except Exception:
            unified = {
                "target_url": normalized_url,
                "composite_risk_score": domain_report.get("domain_risk_score", 50),
                "verdict": "SUSPICIOUS",
                "layer_breakdown": {
                    "pki_trust_risk": pki_report.get("pki_risk_score", 0),
                    "domain_deception_risk": domain_report.get("domain_risk_score", 0),
                    "sandbox_behavioral_risk": sandbox_report.get("sandbox_risk_score", 0),
                    "web_posture_risk": web_report.get("posture_risk_score", 0),
                },
            }

        # Elevate risk score if threat feeds, visual clones, or heuristics trigger
        if isinstance(unified, dict):
            current_score = unified.get(
                "composite_risk_score", unified.get("unified_risk_score", 0)
            )
            heuristic_boost = advanced_deception.get("heuristic_risk_boost", 0)
            dom_boost = dom_exfil_report.get("dom_risk_boost", 0)

            if feed_hit.get("is_blacklisted"):
                current_score = max(current_score, 99)
                unified["verdict"] = "CRITICAL_THREAT"
            elif (
                visual_data.get("visual_phishing_detected")
                or dom_exfil_report.get("dom_threats_detected")
                or heuristic_boost >= 40
            ):
                current_score = min(100, max(current_score, heuristic_boost + dom_boost))
                if current_score >= 75:
                    unified["verdict"] = "CRITICAL_THREAT"
                elif current_score >= 45:
                    unified["verdict"] = "SUSPICIOUS_ACTIVITY"

            unified["composite_risk_score"] = current_score
            unified["unified_risk_score"] = current_score

        try:
            stix_bundle = intel_engine.generate_stix21_bundle(
                normalized_url, unified, pki_report
            )
        except Exception:
            stix_bundle = None

        return {
            "summary": unified,
            "domain_analysis": domain_report,
            "pki_certificate_audit": pki_report,
            "web_security_posture": web_report,
            "sandbox_behavioral_analysis": sandbox_report,
            "stix_2_1_bundle": stix_bundle,
            "threat_intelligence": {
                "feed": feed_hit,
                "infrastructure": infra_data,
                "visual": visual_data,
                "advanced_heuristics": advanced_deception,
                "dom_exfiltration": dom_exfil_report,
                "takedown_notice": takedown_draft,
            },
        }
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"detail": f"Scan error: {str(exc)}"},
            headers={"Access-Control-Allow-Origin": "*"},
        )


@app.get("/")
async def root_health_check():
    return {
        "status": "online",
        "service": "KavachTI Security & PKI Intelligence API",
        "docs": "/docs",
    }


@app.post("/api/v1/pki/inspect-pem")
async def inspect_pem_certificate(req: PEMInspectRequest):
    try:
        return pki_auditor.inspect_pem_or_der(
            req.pem_data.encode("utf-8"), is_pem=True
        )
    except Exception as e:
        raise HTTPException(
            status_code=400, detail=f"Failed to parse PEM certificate: {str(e)}"
        )


@app.get("/api/v1/intel/feed")
async def get_community_feed():
    return {"iocs": intel_engine.community_iocs}


@app.post("/api/v1/intel/vote/{ioc_id}/{direction}")
async def vote_on_ioc(ioc_id: str, direction: str):
    try:
        return intel_engine.vote_ioc(ioc_id, direction)
    except KeyError:
        raise HTTPException(status_code=404, detail="IOC ID not found.")