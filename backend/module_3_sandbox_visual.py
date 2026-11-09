import io
import urllib.parse
from typing import Dict, Any, List
from PIL import Image
import imagehash
from playwright.async_api import async_playwright

BRAND_VISUAL_PHASH_DB = {
    "SBI NetBanking Portal": "f0e8c8d8b2a69496",
    "HDFC Bank NetBanking": "e4c69a9a8ec66963",
    "ICICI Bank Login": "c3999966669999c3",
    "NPCI UPI Payment Gateway": "9966669999666699",
    "TCS NextStep Recruitment Portal": "d4b29696b2d4c8e0",
    "Google Workspace Sign-In": "f8f8f0e0c0808000"
}


class SandboxVisualAnalyzer:
    def compute_visual_similarity(self, screenshot_bytes: bytes) -> Dict[str, Any]:
        img = Image.open(io.BytesIO(screenshot_bytes))
        page_phash = imagehash.phash(img)
        best_match_brand = None
        highest_similarity = 0.0

        for brand_name, ref_hex in BRAND_VISUAL_PHASH_DB.items():
            ref_hash = imagehash.hex_to_hash(ref_hex)
            hamming_dist = page_phash - ref_hash
            similarity_pct = round(max(0.0, (64 - hamming_dist) / 64.0) * 100, 2)
            if similarity_pct > highest_similarity:
                highest_similarity = similarity_pct
                best_match_brand = brand_name

        return {
            "computed_phash": str(page_phash),
            "closest_brand_template": best_match_brand,
            "visual_similarity_pct": highest_similarity,
            "visual_clone_alert": highest_similarity >= 82.0
        }

    async def inspect_url_in_sandbox(self, target_url: str) -> Dict[str, Any]:
        parsed_target = urllib.parse.urlparse(target_url)
        target_host = parsed_target.hostname or ""

        suspicious_network_requests: List[str] = []
        behavioral_flags: List[str] = []
        sandbox_risk = 0

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
            )
            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36"
            )
            page = await context.new_page()

            def handle_request(request):
                req_url = request.url.lower()
                if "api.telegram.org/bot" in req_url:
                    suspicious_network_requests.append(f"Telegram Bot Exfiltration Endpoint: {request.url[:80]}")
                elif "discord.com/api/webhooks" in req_url:
                    suspicious_network_requests.append(f"Discord Webhook Exfiltration: {request.url[:80]}")
                elif request.method == "POST" and target_host not in req_url:
                    suspicious_network_requests.append(f"Cross-Origin POST Exfiltration: {request.url[:80]}")

            page.on("request", handle_request)

            try:
                await page.goto(target_url, wait_until="networkidle", timeout=12000)
            except Exception as e:
                await browser.close()
                return {"error": f"Sandbox navigation failed: {str(e)}", "sandbox_risk_score": 40}

            dom_telemetry = await page.evaluate(
                """() => {
                    const passwordInputs = document.querySelectorAll('input[type="password"]').length;
                    const otpOrPinInputs = document.querySelectorAll(
                        'input[name*="otp" i], input[name*="pin" i], input[name*="cvv" i], input[name*="card" i]'
                    ).length;
                    const forms = Array.from(document.querySelectorAll('form'));
                    const externalFormActions = forms
                        .map(f => f.action)
                        .filter(a => a && a.startsWith('http') && !a.includes(window.location.hostname));
                    const hiddenIframes = Array.from(document.querySelectorAll('iframe')).filter(
                        el => el.offsetWidth === 0 || el.offsetHeight === 0 || el.style.display === 'none'
                    ).length;
                    const rightClickDisabled = document.body.getAttribute('oncontextmenu')?.includes('false') || false;

                    return {
                        title: document.title,
                        passwordInputs,
                        otpOrPinInputs,
                        externalFormActions,
                        hiddenIframes,
                        rightClickDisabled
                    };
                }"""
            )

            screenshot_bytes = await page.screenshot(full_page=False)
            await browser.close()

        visual_analysis = self.compute_visual_similarity(screenshot_bytes)

        if dom_telemetry["passwordInputs"] > 0:
            behavioral_flags.append(f"Contains {dom_telemetry['passwordInputs']} password input field(s).")
            sandbox_risk += 20

        if dom_telemetry["otpOrPinInputs"] > 0:
            behavioral_flags.append(f"Harvests sensitive financial/OTP fields ({dom_telemetry['otpOrPinInputs']} inputs).")
            sandbox_risk += 30

        if dom_telemetry["externalFormActions"]:
            behavioral_flags.append(
                f"Form submits credentials to external host: {dom_telemetry['externalFormActions'][0]}"
            )
            sandbox_risk += 45

        if dom_telemetry["rightClickDisabled"]:
            behavioral_flags.append("Disables context menu (oncontextmenu=false) to hinder source inspection.")
            sandbox_risk += 15

        if suspicious_network_requests:
            behavioral_flags.extend(suspicious_network_requests)
            sandbox_risk += 50

        if visual_analysis["visual_clone_alert"]:
            behavioral_flags.append(
                f"High visual similarity ({visual_analysis['visual_similarity_pct']}%) to {visual_analysis['closest_brand_template']}."
            )
            sandbox_risk += 40

        return {
            "page_title": dom_telemetry["title"],
            "dom_telemetry": dom_telemetry,
            "visual_analysis": visual_analysis,
            "behavioral_flags": behavioral_flags,
            "sandbox_risk_score": min(100, sandbox_risk)
        }
