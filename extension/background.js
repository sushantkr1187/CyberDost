const API_ENDPOINT = "http://localhost:8000/api/v1/scan";
const scanCache = new Map();

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0 || !details.url.startsWith("http")) return;

  const url = details.url;
  const cached = scanCache.get(url);
  if (cached && Date.now() - cached.timestamp < 300000) {
    if (cached.result.summary.composite_risk_score >= 75) {
      injectBlockBanner(details.tabId, cached.result);
    }
    return;
  }

  try {
    const response = await fetch(API_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, run_headless_sandbox: false })
    });

    if (!response.ok) return;
    const result = await response.json();
    scanCache.set(url, { timestamp: Date.now(), result });

    if (result.summary.composite_risk_score >= 75) {
      injectBlockBanner(details.tabId, result);
    }
  } catch (err) {
    console.error("[CyberDost Guard] Backend unreachable:", err);
  }
});

function injectBlockBanner(tabId, scanData) {
  chrome.scripting.executeScript({
    target: { tabId },
    func: renderZeroTrustBlockScreen,
    args: [scanData]
  });
}

function renderZeroTrustBlockScreen(scanData) {
  if (document.getElementById("CyberDost-zero-trust-overlay")) return;

  const score = scanData.summary.composite_risk_score;
  const issuer = scanData.pki_certificate_audit?.issuer_cn || "Untrusted / Unknown CA";
  const reasons = [
    ...(scanData.domain_analysis?.deception_reasons || []),
    ...(scanData.pki_certificate_audit?.warnings || [])
  ];

  const overlay = document.createElement("div");
  overlay.id = "CyberDost-zero-trust-overlay";
  overlay.style.cssText = `
    position: fixed; inset: 0; z-index: 2147483647;
    background: #090d16; color: #f8fafc; font-family: system-ui, sans-serif;
    display: flex; align-items: center; justify-content: center; padding: 24px;
  `;

  overlay.innerHTML = `
    <div style="max-width: 640px; width: 100%; background: #111827; border: 2px solid #ef4444; border-radius: 12px; padding: 32px; box-shadow: 0 25px 50px -12px rgba(239, 68, 68, 0.35);">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
        <span style="background: #ef4444; color: #fff; font-weight: 700; font-size: 12px; padding: 4px 10px; border-radius: 999px; letter-spacing: 0.05em;">
          CyberDost ZERO-TRUST INTERCEPT
        </span>
        <span style="font-family: monospace; font-size: 18px; color: #f87171; font-weight: 700;">
          Risk Score: ${score}/100
        </span>
      </div>
      <h1 style="font-size: 24px; font-weight: 800; margin: 0 0 12px; color: #ffffff;">
        Deceptive Website or Compromised TLS Certificate Blocked
      </h1>
      <p style="color: #94a3b8; font-size: 14px; line-height: 1.6; margin-bottom: 20px;">
        CyberDost prevented connection to <strong style="color: #f8fafc; word-break: break-all;">${scanData.summary.target_url}</strong> because it exhibits high-confidence phishing or cryptographic trust-chain anomalies.
      </p>
      <div style="background: #1f2937; border-radius: 8px; padding: 16px; margin-bottom: 24px; font-size: 13px;">
        <div style="color: #cbd5e1; margin-bottom: 8px;"><strong>Detected Certificate Issuer:</strong> ${issuer}</div>
        <ul style="margin: 0; padding-left: 18px; color: #fca5a5;">
          ${reasons.map(r => `<li style="margin-bottom: 4px;">${r}</li>`).join("")}
        </ul>
      </div>
      <div style="display: flex; gap: 12px;">
        <button id="CyberDost-leave-btn" style="flex: 1; background: #10b981; color: #052e16; border: none; padding: 12px; border-radius: 8px; font-weight: 700; cursor: pointer;">
          Return to Safety
        </button>
        <button id="CyberDost-proceed-btn" style="background: transparent; color: #64748b; border: 1px solid #334155; padding: 12px 16px; border-radius: 8px; cursor: pointer;">
          Ignore Risk (SOC Override)
        </button>
      </div>
    </div>
  `;

  document.documentElement.appendChild(overlay);
  document.getElementById("CyberDost-leave-btn").onclick = () => {
    window.location.href = "about:blank";
  };
  document.getElementById("CyberDost-proceed-btn").onclick = () => {
    overlay.remove();
  };
}
