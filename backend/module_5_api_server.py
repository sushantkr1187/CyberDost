import asyncio
import urllib.parse
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from module_1_pki_auditor import PKIAuditor
from module_2_web_security import WebSecurityScanner
from module_3_sandbox_visual import SandboxVisualAnalyzer
from module_4_threat_intel_stix import ThreatIntelligenceEngine

app = FastAPI(
    title="KavachTI Security & PKI Intelligence API",
    version="2.1.0",
    description="Unified Phishing Detection, PKI Entropy Validation & STIX 2.1 Threat Intelligence"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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


@app.post("/api/v1/scan")
async def full_url_scan(req: URLScanRequest):
    parsed = urllib.parse.urlparse(req.url if "://" in req.url else f"https://{req.url}")
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid URL supplied.")

    normalized_url = f"{parsed.scheme}://{hostname}{parsed.path or '/'}"

    domain_report = web_scanner.analyze_domain_deception(hostname)
    pki_task = pki_auditor.audit_live_host(hostname)
    web_task = web_scanner.audit_http_posture_and_exposures(normalized_url)
    sandbox_task = (
        sandbox_analyzer.inspect_url_in_sandbox(normalized_url)
        if req.run_headless_sandbox else asyncio.sleep(0, result={"sandbox_risk_score": 0})
    )

    pki_report, web_report, sandbox_report = await asyncio.gather(pki_task, web_task, sandbox_task)

    unified = intel_engine.calculate_unified_verdict(
        normalized_url, pki_report, web_report, domain_report, sandbox_report
    )
    stix_bundle = intel_engine.generate_stix21_bundle(normalized_url, unified, pki_report)

    return {
        "summary": unified,
        "domain_analysis": domain_report,
        "pki_certificate_audit": pki_report,
        "web_security_posture": web_report,
        "sandbox_behavioral_analysis": sandbox_report,
        "stix_2_1_bundle": stix_bundle
    }


@app.post("/api/v1/pki/inspect-pem")
async def inspect_pem_certificate(req: PEMInspectRequest):
    try:
        return pki_auditor.inspect_pem_or_der(req.pem_data.encode("utf-8"), is_pem=True)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse PEM certificate: {str(e)}")


@app.get("/api/v1/intel/feed")
async def get_community_feed():
    return {"iocs": intel_engine.community_iocs}


@app.post("/api/v1/intel/vote/{ioc_id}/{direction}")
async def vote_on_ioc(ioc_id: str, direction: str):
    try:
        return intel_engine.vote_ioc(ioc_id, direction)
    except KeyError:
        raise HTTPException(status_code=404, detail="IOC ID not found.")
