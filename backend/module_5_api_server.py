import asyncio
import base64
import urllib.parse
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from intelligence import (
    check_urlhaus,
    analyze_screenshot_phash,
    profile_infrastructure,
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
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
    raw_url = req.url.strip()
    parsed = urllib.parse.urlparse(
        raw_url if "://" in raw_url else f"https://{raw_url}"
    )
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid URL supplied.")

    normalized_url = f"{parsed.scheme}://{hostname}{parsed.path or '/'}"

    # 1. Synchronous heuristic domain & typosquatting analysis
    domain_report = web_scanner.analyze_domain_deception(hostname)
    
    # NEW: Advanced typosquatting, IDN homograph, and keyword checks
    advanced_deception = analyze_typosquatting_and_idn(hostname)

    # 2. Concurrent execution of all async & I/O-bound intelligence modules
    feed_task = check_urlhaus(normalized_url)
    infra_task = asyncio.to_thread(profile_infrastructure, hostname)
    pki_task = pki_auditor.audit_live_host(hostname)
    web_task = web_scanner.audit_http_posture_and_exposures(normalized_url)
    
    # NEW: Scan HTML/JS for Telegram bots, Discord webhooks, and OTP input traps
    dom_exfil_task = inspect_dom_exfiltration(normalized_url)

    sandbox_task = (
        sandbox_analyzer.inspect_url_in_sandbox(normalized_url)
        if req.run_headless_sandbox
        else asyncio.sleep(0, result={"sandbox_risk_score": 0})
    )

    (
        feed_hit,
        infra_data,
        pki_report,
        web_report,
        dom_exfil_report,  # <--- Collect new task result
        sandbox_report,
    ) = await asyncio.gather(
        feed_task, infra_task, pki_task, web_task, dom_exfil_task, sandbox_task
    )

    # 3. Visual Phishing pHash analysis
    visual_data = {
        "visual_phishing_detected": False,
        "page_phash": None,
        "matched_brands": [],
    }
    if req.run_headless_sandbox:
        screenshot_bytes = None
        b64_img = (
            sandbox_report.get("screenshot_b64")
            or sandbox_report.get("screenshot")
            if isinstance(sandbox_report, dict)
            else None
        )
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

    # NEW: Generate automated CERT-In / Hosting Provider takedown draft
    takedown_draft = generate_takedown_notice(
        normalized_url, infra_data, advanced_deception, dom_exfil_report
    )

    # Enrich reports with new intelligence telemetry
    if isinstance(domain_report, dict):
        domain_report["infrastructure_profile"] = infra_data
        domain_report["advanced_deception"] = advanced_deception
    if isinstance(sandbox_report, dict):
        sandbox_report["visual_phash_analysis"] = visual_data
        sandbox_report["dom_exfiltration_analysis"] = dom_exfil_report

    # Calculate unified verdict across all modules
    unified = intel_engine.calculate_unified_verdict(
        normalized_url, pki_report, web_report, domain_report, sandbox_report
    )

    # Elevate risk score if threat feeds, visual clones, or exfiltration scripts trigger
    if isinstance(unified, dict):
        current_score = unified.get("unified_risk_score", unified.get("risk_score", 0))
        if feed_hit.get("is_blacklisted"):
            current_score = max(current_score, 99)
            unified["unified_risk_score"] = current_score
            unified["threat_level"] = "CRITICAL"
        elif visual_data.get("visual_phishing_detected") or dom_exfil_report.get("dom_threats_detected"):
            boost = advanced_deception.get("heuristic_risk_boost", 0) + dom_exfil_report.get("dom_risk_boost", 0)
            current_score = min(100, current_score + max(boost, 50))
            unified["unified_risk_score"] = current_score
            unified["threat_level"] = "HIGH"

    stix_bundle = intel_engine.generate_stix21_bundle(
        normalized_url, unified, pki_report
    )

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
            "takedown_notice": takedown_draft,  # <--- Returns ready-to-send takedown letter to frontend
        },
    }


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