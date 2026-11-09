/**
 * TrustMatrix Frontend Application Logic
 * Modern UI/UX with Google Icons, Animated Telemetry, Micro-Interactions,
 * and Real-Time Threat Intelligence.
 */

let currentScanData = null;
let cachedIocs = [];
let cachedReports = [];

document.addEventListener('DOMContentLoaded', () => {
  loadStats();
  loadAdvisories();
  loadIocs();
  loadCommunityReports();
  loadBrands();
});

// ==========================================================================
// Toast Notification System
// ==========================================================================
function showToast(message, icon = 'info') {
  const toast = document.getElementById('toast-notice');
  const msgEl = document.getElementById('toast-message');
  const iconEl = document.getElementById('toast-icon');

  if (!toast) return;

  msgEl.textContent = message;
  iconEl.textContent = icon;
  toast.classList.add('show');

  setTimeout(() => {
    toast.classList.remove('show');
  }, 3200);
}

function copyToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => {
      showToast('Copied to clipboard!', 'content_copy');
    }).catch(() => {
      fallbackCopy(text);
    });
  } else {
    fallbackCopy(text);
  }
}

function fallbackCopy(text) {
  const ta = document.createElement('textarea');
  ta.value = text;
  document.body.appendChild(ta);
  ta.select();
  document.execCommand('copy');
  document.body.removeChild(ta);
  showToast('Copied to clipboard!', 'content_copy');
}

// ==========================================================================
// Navigation & Tab Switching
// ==========================================================================
function switchTab(tabId) {
  document.querySelectorAll('.nav-link').forEach(btn => {
    const isTarget = btn.getAttribute('onclick')?.includes(tabId);
    btn.classList.toggle('active', isTarget);
  });

  document.querySelectorAll('.tab-pane').forEach(pane => {
    pane.classList.remove('active');
  });

  const activePane = document.getElementById(`tab-${tabId}`);
  if (activePane) {
    activePane.classList.add('active');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
}

function switchDetailTab(panelId) {
  document.querySelectorAll('.subtab-trigger').forEach(btn => {
    const isTarget = btn.getAttribute('onclick')?.includes(panelId);
    btn.classList.toggle('active', isTarget);
  });

  document.querySelectorAll('.subtab-panel').forEach(panel => {
    panel.classList.remove('active');
  });

  const activePanel = document.getElementById(`detail-panel-${panelId}`);
  if (activePanel) {
    activePanel.classList.add('active');
  }
}

// ==========================================================================
// Live Scan Execution & Animated Telemetry
// ==========================================================================
function quickFillAndScan(url) {
  switchTab('scanner');
  document.getElementById('scan-url-input').value = url;
  executeScan(url);
}

function handleScanSubmit(event) {
  event.preventDefault();
  const url = document.getElementById('scan-url-input').value.trim();
  if (url) {
    executeScan(url);
  }
}

async function executeScan(url) {
  const btn = document.getElementById('btn-run-scan');
  const spinner = document.getElementById('scan-btn-spinner');
  const btnIcon = document.getElementById('scan-btn-icon');
  const btnText = document.getElementById('scan-btn-text');
  const ticker = document.getElementById('scan-telemetry-ticker');
  const stepText = document.getElementById('telemetry-step-text');

  btn.disabled = true;
  spinner.style.display = 'inline-block';
  btnIcon.style.display = 'none';
  btnText.textContent = 'INSPECTING...';
  ticker.style.display = 'block';

  // Step-by-step telemetry ticker simulation
  const steps = [
    'Resolving DNS trust, MX mail exchangers & strict CAA policies...',
    'Performing TLS 1.3 socket handshake & peer certificate chain extraction...',
    'Conducting cryptographic health audit: ROCA prime residue & eMudhra check...',
    'Executing DOM heuristics: inspecting password & credit card exfiltration...',
    'Cross-matching active indicators in Threat Intelligence Hub...',
    'Generating composite risk index & remediation playbook...'
  ];

  let currentStep = 0;
  stepText.textContent = steps[0];
  const tickerInterval = setInterval(() => {
    currentStep = (currentStep + 1) % steps.length;
    stepText.textContent = steps[currentStep];
  }, 450);

  const startTime = Date.now();

  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      throw new Error(`Scan request failed with status ${response.status}`);
    }

    const data = await response.json();
    currentScanData = data;
    renderScanResults(data, Date.now() - startTime);
    showToast(`Inspection complete: ${data.domain}`, 'verified');
  } catch (err) {
    alert(`Scan error: ${err.message}`);
    showToast(`Scan failed: ${err.message}`, 'error');
  } finally {
    clearInterval(tickerInterval);
    ticker.style.display = 'none';
    btn.disabled = false;
    spinner.style.display = 'none';
    btnIcon.style.display = 'inline-block';
    btnText.textContent = 'INSPECT TARGET';
  }
}

// ==========================================================================
// Scan Results Rendering & Gauge Animation
// ==========================================================================
function renderScanResults(data, elapsedMs = 45) {
  const container = document.getElementById('scan-result-container');
  container.style.display = 'block';

  const score = data.composite.compositeScore;
  const severity = data.composite.severity;
  const badgeColor = data.composite.badgeColor;

  // Header card metadata
  document.getElementById('res-target-domain').textContent = data.domain;
  document.getElementById('res-summary-text').textContent = data.composite.summary;
  document.getElementById('res-scan-id').textContent = data.scanId;
  document.getElementById('res-scanned-at').textContent = new Date(data.scannedAt).toLocaleTimeString();
  document.getElementById('res-status-code').textContent = `${data.pageStatusCode || 200} OK`;
  document.getElementById('res-duration').textContent = `${data.durationMs || elapsedMs}ms`;

  // Dynamic Severity Tag
  const tag = document.getElementById('res-severity-tag');
  tag.className = `severity-pill ${badgeColor}`;
  tag.innerHTML = `
    <span class="material-symbols-outlined" style="font-size:16px">${badgeColor === 'rose' ? 'error' : badgeColor === 'amber' ? 'warning' : 'check_circle'}</span>
    <span>${severity.replace(/_/g, ' ')}</span>
  `;

  // Color selection
  let strokeColor = 'var(--rose)';
  if (score < 25) strokeColor = 'var(--emerald-bright)';
  else if (score < 50) strokeColor = 'var(--cyan-bright)';
  else if (score < 70) strokeColor = 'var(--amber-bright)';
  else if (score < 90) strokeColor = 'var(--amber)';

  // Animate Gauge Speedometer
  const circle = document.getElementById('gauge-progress');
  const circumference = 2 * Math.PI * 42;
  const offset = circumference - (score / 100) * circumference;
  circle.style.strokeDasharray = `${circumference} ${circumference}`;
  circle.style.stroke = strokeColor;
  circle.style.strokeDashoffset = offset;

  // Number count-up animation
  animateScoreCounter(score, strokeColor);

  // Border highlight on master card
  document.getElementById('result-master-card').style.setProperty('--status-color', strokeColor);

  // 4-Pillar Score Cards
  const sub = data.composite.subscores;

  // Pillar 1: Threat Heuristics
  document.getElementById('pillar-threat-score').textContent = `${sub.threatHeuristics}/100`;
  document.getElementById('pillar-threat-score').style.color = sub.threatHeuristics >= 70 ? 'var(--rose)' : 'var(--emerald-bright)';
  document.getElementById('pillar-threat-bar').style.width = `${sub.threatHeuristics}%`;
  document.getElementById('pillar-threat-bar').style.background = sub.threatHeuristics >= 70 ? 'var(--rose)' : 'var(--emerald-bright)';
  document.getElementById('pillar-threat-label').textContent = data.threatAnalysis.threatCategory.replace(/_/g, ' ');

  // Pillar 2: Certificate Risk
  document.getElementById('pillar-cert-score').textContent = `${sub.certificateTrust}/100`;
  document.getElementById('pillar-cert-score').style.color = sub.certificateTrust >= 50 ? 'var(--amber-bright)' : 'var(--cyan-bright)';
  document.getElementById('pillar-cert-bar').style.width = `${sub.certificateTrust}%`;
  document.getElementById('pillar-cert-bar').style.background = sub.certificateTrust >= 50 ? 'var(--amber-bright)' : 'var(--cyan-bright)';
  document.getElementById('pillar-cert-label').textContent = data.certAnalysis.hasCert
    ? `Cert Age: ${data.certAnalysis.ageInDays || 0}d (${data.certAnalysis.keyAudit?.asymmetricKeyType?.toUpperCase() || 'RSA'})`
    : 'No Valid Certificate';

  // Pillar 3: Web App Posture
  document.getElementById('pillar-web-score').textContent = `Grade ${data.securityPosture.grade}`;
  document.getElementById('pillar-web-score').style.color = (data.securityPosture.grade === 'A+' || data.securityPosture.grade === 'A') ? 'var(--emerald-bright)' : 'var(--rose)';
  document.getElementById('pillar-web-bar').style.width = `${data.securityPosture.securityScore}%`;
  document.getElementById('pillar-web-bar').style.background = (data.securityPosture.grade === 'A+' || data.securityPosture.grade === 'A') ? 'var(--emerald-bright)' : 'var(--rose)';
  document.getElementById('pillar-web-label').textContent = `Security Score: ${data.securityPosture.securityScore}/100`;

  // Pillar 4: Collaborative Intel Match
  const isMalicious = data.threatIntelligence.isKnownMalicious;
  document.getElementById('pillar-intel-score').textContent = isMalicious ? 'MATCH' : 'CLEAN';
  document.getElementById('pillar-intel-score').style.color = isMalicious ? 'var(--rose)' : 'var(--emerald-bright)';
  document.getElementById('pillar-intel-bar').style.width = isMalicious ? '100%' : '15%';
  document.getElementById('pillar-intel-bar').style.background = isMalicious ? 'var(--rose)' : 'var(--emerald-bright)';
  document.getElementById('pillar-intel-label').textContent = isMalicious
    ? `${data.threatIntelligence.matchedCategory || 'Known IOC Match'}`
    : 'No malicious IOC found';

  // Detail Sub-Tab 1: Threat Signals & Flags
  const threatFlags = data.threatAnalysis.redFlags || [];
  document.getElementById('count-threat-flags').textContent = threatFlags.length;

  const flagsContainer = document.getElementById('threat-flags-list');
  flagsContainer.innerHTML = '';

  if (threatFlags.length === 0) {
    flagsContainer.innerHTML = `
      <div style="display:flex; align-items:center; gap:0.6rem; color:var(--emerald-bright); font-size:0.95rem; padding:1rem 0">
        <span class="material-symbols-outlined" style="font-size:24px">check_circle</span>
        <span>Clean Profile: No deceptive brand impersonation or credential harvesting patterns identified.</span>
      </div>
    `;
  } else {
    for (const flag of threatFlags) {
      const banner = document.createElement('div');
      banner.className = `flag-banner ${flag.severity}`;
      banner.innerHTML = `
        <div class="flag-title-row">
          <div class="flag-rule-name">
            <span class="material-symbols-outlined" style="font-size:18px; color:${flag.severity === 'CRITICAL' ? 'var(--rose)' : flag.severity === 'HIGH' ? 'var(--amber)' : 'var(--cyan-bright)'}">
              ${flag.severity === 'CRITICAL' ? 'error' : flag.severity === 'HIGH' ? 'warning' : 'info'}
            </span>
            <span>${escapeHtml(flag.rule)}</span>
          </div>
          <span class="severity-pill ${flag.severity === 'CRITICAL' ? 'rose' : flag.severity === 'HIGH' ? 'amber' : 'blue'}">
            ${flag.severity}
          </span>
        </div>
        <div class="flag-explanation">${escapeHtml(flag.description)}</div>
      `;
      flagsContainer.appendChild(banner);
    }
  }

  // Telemetry attributes
  document.getElementById('telemetry-apex').textContent = data.apexDomain || 'N/A';
  document.getElementById('telemetry-entropy').innerHTML = `${data.threatAnalysis.lexical?.domainEntropy || '0'} ${data.threatAnalysis.lexical?.domainEntropy > 3.75 ? '<span class="severity-pill rose" style="font-size:0.7rem; padding:0.15rem 0.5rem">High / DGA</span>' : ''}`;
  document.getElementById('telemetry-homoglyphs').innerHTML = data.threatAnalysis.lexical?.homoglyphAnalysis?.hasMixedScripts
    ? `<span class="severity-pill rose">Lookalikes Detected (${data.threatAnalysis.lexical.homoglyphAnalysis.homoglyphsFound.length})</span>`
    : '<span style="color:var(--emerald-bright)">None (Clean ASCII)</span>';
  document.getElementById('telemetry-subdomains').textContent = data.threatAnalysis.lexical?.subdomains || '(none)';
  document.getElementById('telemetry-brand').innerHTML = data.threatAnalysis.lexical?.matchedBrand
    ? `<strong style="color:#fff">${escapeHtml(data.threatAnalysis.lexical.matchedBrand.brand)}</strong> <span class="severity-pill ${data.threatAnalysis.lexical.matchedBrand.isOfficial ? 'emerald' : 'rose'}">${data.threatAnalysis.lexical.matchedBrand.isOfficial ? 'OFFICIAL' : 'IMPERSONATED'}</span>`
    : 'None';
  document.getElementById('telemetry-inputs').innerHTML = data.threatAnalysis.content?.hasPasswordField
    ? '<span class="severity-pill rose">Password Input Field Detected</span>'
    : '<span style="color:var(--text-muted)">None</span>';

  // Detail Sub-Tab 2: Certificate & PKI Audit
  const cert = data.certAnalysis;
  const certFlagsContainer = document.getElementById('cert-flags-list');
  certFlagsContainer.innerHTML = '';

  if (cert.certFlags && cert.certFlags.length > 0) {
    for (const flag of cert.certFlags) {
      const banner = document.createElement('div');
      banner.className = `flag-banner ${flag.severity}`;
      banner.innerHTML = `
        <div class="flag-title-row">
          <div class="flag-rule-name">
            <span class="material-symbols-outlined" style="font-size:18px; color:var(--amber)">vpn_key_alert</span>
            <span>${escapeHtml(flag.rule)}</span>
          </div>
          <span class="severity-pill ${flag.severity === 'CRITICAL' ? 'rose' : 'amber'}">${flag.severity}</span>
        </div>
        <div class="flag-explanation">${escapeHtml(flag.description)}</div>
      `;
      certFlagsContainer.appendChild(banner);
    }
  }

  document.getElementById('cert-subject').textContent = cert.subjectCommonName || cert.subject || 'N/A';
  document.getElementById('cert-issuer').textContent = cert.issuer || 'N/A';
  document.getElementById('cert-validity').textContent = `${cert.validFrom || '-'} to ${cert.validTo || '-'}`;
  document.getElementById('cert-age-details').textContent = `${cert.ageInDays || 0} days old (Lifespan: ${cert.lifespanInDays || 0} days)`;
  document.getElementById('res-cert-age-badge').textContent = `Age: ${cert.ageInDays || 0} days`;

  // Key and ROCA
  const keyType = cert.keyAudit?.asymmetricKeyType?.toUpperCase() || 'RSA';
  const keyLen = cert.keyAudit?.modulusLength || 2048;
  document.getElementById('cert-key-details').textContent = `${keyType} (${keyLen} bits, Exponent: ${cert.keyAudit?.publicExponent || '65537'})`;

  // ROCA test
  const rocaEl = document.getElementById('cert-roca-status');
  if (cert.rocaTest?.isVulnerable) {
    rocaEl.innerHTML = '<span class="severity-pill rose"><span class="material-symbols-outlined" style="font-size:14px">error</span> CRITICAL: VULNERABLE (CVE-2017-15361)</span>';
  } else {
    rocaEl.innerHTML = '<span class="severity-pill emerald"><span class="material-symbols-outlined" style="font-size:14px">check_circle</span> PASS (ROCA Clean)</span>';
  }

  // eMudhra Incident Audit
  const emudhraEl = document.getElementById('cert-emudhra-status');
  if (cert.caAudit?.eMudhraAnalysis?.isEMudhraCA) {
    emudhraEl.innerHTML = `<span class="severity-pill amber"><span class="material-symbols-outlined" style="font-size:14px">warning</span> AUDIT WARNING: eMudhra CA Hierarchy (${cert.caAudit.eMudhraAnalysis.auditStatus})</span>`;
  } else {
    emudhraEl.innerHTML = '<span class="severity-pill emerald"><span class="material-symbols-outlined" style="font-size:14px">verified</span> Standard Root Program CA</span>';
  }

  // CT presence
  document.getElementById('cert-ct-status').innerHTML = cert.hasCertificateTransparency
    ? '<span class="severity-pill emerald"><span class="material-symbols-outlined" style="font-size:14px">verified</span> CT SCT Proofs Verified</span>'
    : '<span class="severity-pill amber"><span class="material-symbols-outlined" style="font-size:14px">history_toggle_off</span> No CT Proofs Attached</span>';

  document.getElementById('cert-sigalg').textContent = cert.signatureAlgorithm || 'N/A';
  document.getElementById('cert-sans').textContent = (cert.subjectAltNames || []).join(', ') || 'None';
  document.getElementById('cert-fingerprint').innerHTML = `
    <span>${cert.fingerprint256 || 'N/A'}</span>
    <button class="btn-copy" style="margin-left:0.5rem" onclick="copyToClipboard('${cert.fingerprint256 || ''}')">
      <span class="material-symbols-outlined" style="font-size:14px">content_copy</span>
    </button>
  `;

  // Detail Sub-Tab 3: Security Headers
  const gradeBadge = document.getElementById('res-security-grade-badge');
  gradeBadge.textContent = `Grade: ${data.securityPosture.grade} (${data.securityPosture.securityScore}/100)`;
  gradeBadge.className = `severity-pill ${(data.securityPosture.grade === 'A+' || data.securityPosture.grade === 'A') ? 'emerald' : data.securityPosture.grade === 'B' ? 'blue' : 'rose'}`;

  const secTbody = document.getElementById('security-headers-tbody');
  secTbody.innerHTML = '';

  for (const h of data.securityPosture.headerAudits || []) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong style="color:#fff; font-family:var(--font-display)">${escapeHtml(h.displayName)}</strong></td>
      <td>
        <span class="severity-pill ${h.present ? 'emerald' : 'rose'}">
          <span class="material-symbols-outlined" style="font-size:14px">${h.present ? 'check_circle' : 'cancel'}</span>
          <span>${h.present ? 'CONFIGURED' : 'MISSING'}</span>
        </span>
      </td>
      <td class="mono-cell" style="max-width:350px; overflow-wrap:break-word; color:var(--text-secondary)">${escapeHtml(h.value || 'Not Configured')}</td>
      <td style="font-size:0.82rem; color:var(--text-muted)">${escapeHtml(h.recommendation || 'Standard protection enabled')}</td>
    `;
    secTbody.appendChild(tr);
  }

  document.getElementById('sec-server-banner').textContent = data.securityPosture.serverBanner;
  document.getElementById('sec-powered-by').textContent = data.securityPosture.poweredBy;

  // Detail Sub-Tab 4: DNS Trust
  const dns = data.dnsTrust;
  document.getElementById('res-dns-score-badge').textContent = `DNS Trust: ${dns.score}/100`;
  document.getElementById('dns-ipv4').textContent = (dns.ipv4Addresses || []).join(', ') || 'No A record';
  document.getElementById('dns-mx').textContent = dns.hasMx ? `${dns.mxRecords.length} mail servers configured` : 'None';
  document.getElementById('dns-spf').textContent = dns.spfRecord || 'No SPF record';
  document.getElementById('dns-dmarc').textContent = dns.dmarcRecord || 'No DMARC record';
  document.getElementById('dns-caa').textContent = dns.hasCaa
    ? dns.caaRecords.map(c => `${c.tag} "${c.value}"`).join(', ')
    : 'No CAA records (Unrestricted CA Issuance)';

  document.getElementById('dns-spoof-eval').innerHTML = dns.emailSpoofingProtection === 'STRONG_ENFORCED'
    ? '<span class="severity-pill emerald"><span class="material-symbols-outlined" style="font-size:14px">security</span> STRICT ENFORCEMENT (p=reject)</span>'
    : '<span class="severity-pill rose"><span class="material-symbols-outlined" style="font-size:14px">warning</span> VULNERABLE TO SENDER SPOOFING</span>';

  document.getElementById('dns-caa-eval').innerHTML = dns.caaProtection === 'STRICT_CAA_ENFORCED'
    ? '<span class="severity-pill emerald"><span class="material-symbols-outlined" style="font-size:14px">verified</span> STRICT CAA ENFORCEMENT</span>'
    : '<span class="severity-pill amber"><span class="material-symbols-outlined" style="font-size:14px">warning</span> UNPROTECTED (Any CA Can Issue)</span>';

  // Detail Sub-Tab 5: Threat Intel Match
  const intelContent = document.getElementById('intel-details-content');
  const intelBadge = document.getElementById('intel-verdict-badge');
  intelBadge.textContent = isMalicious ? 'KNOWN THREAT MATCH' : 'CLEAN REPUTATION';
  intelBadge.className = `severity-pill ${isMalicious ? 'rose' : 'emerald'}`;

  if (isMalicious) {
    intelContent.innerHTML = `
      <div style="background:linear-gradient(90deg, rgba(244,63,94,0.1), transparent); border:1px solid rgba(244,63,94,0.3); border-radius:12px; padding:1.5rem">
        <h4 style="color:#fda4af; font-family:var(--font-display); font-size:1.1rem; margin-bottom:0.5rem; display:flex; align-items:center; gap:0.5rem">
          <span class="material-symbols-outlined" style="font-size:24px">crisis_alert</span>
          <span>Verified Active Indicator of Compromise (IOC)</span>
        </h4>
        <p style="color:var(--text-secondary); font-size:0.95rem; line-height:1.6; margin-bottom:1rem">
          This domain is actively tracked across decentralized threat intelligence feeds targeting <strong>${escapeHtml(data.threatIntelligence.targetBrand || 'Multiple Organizations')}</strong>.
        </p>
        <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:1rem; font-size:0.875rem">
          <div><strong style="color:var(--text-muted)">Category:</strong> <div>${escapeHtml(data.threatIntelligence.matchedCategory || 'Phishing')}</div></div>
          <div><strong style="color:var(--text-muted)">Feed Confidence:</strong> <div>${data.threatIntelligence.confidence}%</div></div>
          <div><strong style="color:var(--text-muted)">Consensus:</strong> <div>${data.threatIntelligence.verifiedReportsCount} Verified Reports</div></div>
        </div>
      </div>
    `;
  } else {
    intelContent.innerHTML = `
      <div style="background:linear-gradient(90deg, rgba(16,185,129,0.08), transparent); border:1px solid rgba(16,185,129,0.25); border-radius:12px; padding:1.5rem">
        <h4 style="color:#6ee7b7; font-family:var(--font-display); font-size:1.1rem; margin-bottom:0.5rem; display:flex; align-items:center; gap:0.5rem">
          <span class="material-symbols-outlined" style="font-size:24px">verified_user</span>
          <span>Clean Threat Intelligence Reputation</span>
        </h4>
        <p style="color:var(--text-secondary); font-size:0.95rem">
          No malicious indicators of compromise or pending community fraud reports exist for domain <code>${escapeHtml(data.domain)}</code>.
        </p>
      </div>
    `;
  }

  // Detail Sub-Tab 6: Remediation Playbook
  const recContainer = document.getElementById('remediation-list');
  recContainer.innerHTML = '';

  if (data.composite.recommendations.length === 0) {
    recContainer.innerHTML = `
      <div style="display:flex; align-items:center; gap:0.6rem; color:var(--emerald-bright); font-size:0.95rem; padding:1rem 0">
        <span class="material-symbols-outlined" style="font-size:24px">check_circle</span>
        <span>No immediate remediations required. Website satisfies established security and cryptographic baselines.</span>
      </div>
    `;
  } else {
    for (const rec of data.composite.recommendations) {
      const banner = document.createElement('div');
      banner.className = `flag-banner ${rec.priority === 'CRITICAL' ? 'CRITICAL' : rec.priority === 'HIGH' ? 'HIGH' : 'MEDIUM'}`;
      banner.innerHTML = `
        <div class="flag-title-row">
          <div class="flag-rule-name">
            <span class="material-symbols-outlined" style="font-size:18px">task_alt</span>
            <span>${escapeHtml(rec.title)}</span>
          </div>
          <span class="severity-pill ${rec.priority === 'CRITICAL' ? 'rose' : 'amber'}">${rec.priority}</span>
        </div>
        <div class="flag-explanation">${escapeHtml(rec.action)}</div>
      `;
      recContainer.appendChild(banner);
    }
  }

  // Smooth scroll down to view results
  container.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function animateScoreCounter(targetScore, color) {
  const numberEl = document.getElementById('res-score-number');
  let current = 0;
  numberEl.style.color = color;

  const stepTime = 12;
  const increment = Math.max(1, Math.round(targetScore / 40));

  const timer = setInterval(() => {
    current += increment;
    if (current >= targetScore) {
      current = targetScore;
      clearInterval(timer);
    }
    numberEl.textContent = current;
  }, stepTime);
}

function exportCurrentReportJson() {
  if (!currentScanData) return;
  const blob = new Blob([JSON.stringify(currentScanData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `trustmatrix-${currentScanData.domain}-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast('Exported scan report as JSON', 'download');
}

// ==========================================================================
// Collaborative Intel, Reports & Consensus Voting
// ==========================================================================
async function loadStats() {
  try {
    const res = await fetch('/api/stats');
    const data = await res.json();
    document.getElementById('stat-total-iocs').textContent = data.totalIocs || 0;
    document.getElementById('stat-total-reports').textContent = data.totalReports || 0;
    document.getElementById('stat-verified-reports').textContent = data.verifiedReports || 0;
    document.getElementById('stat-monitored-brands').textContent = data.monitoredBrands || 0;
  } catch (err) {
    console.error('Failed to load stats:', err);
  }
}

async function loadIocs() {
  try {
    const res = await fetch('/api/iocs');
    const data = await res.json();
    cachedIocs = data.iocs || [];
    renderIocsTable(cachedIocs);
  } catch (err) {
    console.error('Failed to load IOCs:', err);
  }
}

function renderIocsTable(iocs) {
  const tbody = document.getElementById('iocs-tbody');
  tbody.innerHTML = '';

  for (const ioc of iocs) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="severity-pill ${ioc.ioc_type === 'DOMAIN' ? 'blue' : 'amber'}">${escapeHtml(ioc.ioc_type)}</span></td>
      <td class="mono-cell"><strong style="color:#fff">${escapeHtml(ioc.value)}</strong></td>
      <td>${escapeHtml(ioc.threat_category)}</td>
      <td><strong style="color:var(--text-primary)">${escapeHtml(ioc.target_brand || 'Multiple')}</strong></td>
      <td><span class="severity-pill ${ioc.severity === 'CRITICAL' ? 'rose' : 'amber'}">${ioc.severity}</span></td>
      <td style="font-size:0.78rem; color:var(--text-muted)">${escapeHtml(ioc.source)}</td>
      <td><span class="mono-cell">${ioc.confidence}%</span></td>
      <td style="font-size:0.8rem; color:var(--text-muted)">${new Date(ioc.last_seen).toLocaleDateString()}</td>
    `;
    tbody.appendChild(tr);
  }
}

function filterIocs(searchTerm) {
  const term = searchTerm.toLowerCase();
  const filtered = cachedIocs.filter(i =>
    i.value.toLowerCase().includes(term) ||
    (i.target_brand && i.target_brand.toLowerCase().includes(term)) ||
    i.threat_category.toLowerCase().includes(term)
  );
  renderIocsTable(filtered);
}

async function loadCommunityReports() {
  try {
    const res = await fetch('/api/reports');
    const data = await res.json();
    cachedReports = data.reports || [];
    renderCommunityReports(cachedReports);
  } catch (err) {
    console.error('Failed to load reports:', err);
  }
}

function renderCommunityReports(reports) {
  const tbody = document.getElementById('community-reports-tbody');
  tbody.innerHTML = '';

  for (const r of reports) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>
        <strong class="mono-cell" style="color:var(--cyan-bright)">${escapeHtml(r.domain)}</strong>
        <div class="mono-cell" style="font-size:0.75rem; color:var(--text-muted)">${escapeHtml(r.url)}</div>
      </td>
      <td>${escapeHtml(r.category)}</td>
      <td><strong style="color:#fff">${escapeHtml(r.target_brand || 'General')}</strong></td>
      <td>
        <strong>${escapeHtml(r.reporter_name)}</strong>
        <div style="font-size:0.75rem; color:var(--text-muted)">${escapeHtml(r.reporter_role || 'Contributor')}</div>
      </td>
      <td>
        <span style="color:var(--emerald-bright); font-weight:700">▲ ${r.upvotes || 0}</span>
        <span style="color:var(--rose-bright); font-weight:700; margin-left:0.5rem">▼ ${r.downvotes || 0}</span>
      </td>
      <td>
        <span class="severity-pill ${r.status === 'VERIFIED' ? 'rose' : r.status === 'FALSE_POSITIVE' ? 'emerald' : 'amber'}">
          ${r.status}
        </span>
      </td>
      <td>
        <div style="display:flex; gap:0.4rem">
          <button class="scenario-chip safe" onclick="voteReport('${r.id}', 'UPVOTE')">
            <span class="material-symbols-outlined" style="font-size:14px">thumb_up</span>
            <span>Confirm</span>
          </button>
          <button class="scenario-chip danger" onclick="voteReport('${r.id}', 'DOWNVOTE')">
            <span class="material-symbols-outlined" style="font-size:14px">thumb_down</span>
            <span>Dispute</span>
          </button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  }
}

async function voteReport(reportId, voteType) {
  const voterId = `analyst_${Math.floor(Math.random() * 1000)}`;
  try {
    const res = await fetch(`/api/reports/${reportId}/vote`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ voter_id: voterId, vote_type: voteType, comment: 'Analyst peer review verified' })
    });
    const result = await res.json();
    if (result.success) {
      loadCommunityReports();
      loadStats();
      loadIocs();
      showToast(`Vote recorded: ${voteType === 'UPVOTE' ? 'Confirmed Threat' : 'Disputed Threat'}`, 'how_to_vote');
    }
  } catch (err) {
    alert(`Voting error: ${err.message}`);
  }
}

function openReportModal() {
  document.getElementById('report-modal').style.display = 'flex';
}

function closeReportModal() {
  document.getElementById('report-modal').style.display = 'none';
}

async function handleReportSubmit(e) {
  e.preventDefault();
  const payload = {
    url: document.getElementById('rep-url').value,
    category: document.getElementById('rep-category').value,
    target_brand: document.getElementById('rep-brand').value,
    reporter_name: document.getElementById('rep-name').value,
    reporter_role: document.getElementById('rep-role').value,
    evidence: document.getElementById('rep-evidence').value,
    notes: document.getElementById('rep-notes').value
  };

  try {
    const res = await fetch('/api/reports', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const result = await res.json();
    if (result.success) {
      closeReportModal();
      document.getElementById('incident-form').reset();
      loadCommunityReports();
      loadStats();
      showToast('Threat report queued for analyst review!', 'verified');
    }
  } catch (err) {
    alert(`Failed to submit report: ${err.message}`);
  }
}

function exportSTIX() {
  window.open('/api/iocs/export/stix', '_blank');
  showToast('Downloading STIX 2.1 Threat Bundle', 'download');
}

// ==========================================================================
// CA Advisories & eMudhra Incident Knowledge Base
// ==========================================================================
async function loadAdvisories() {
  try {
    const res = await fetch('/api/advisories');
    const data = await res.json();
    const tbody = document.getElementById('advisories-tbody');
    tbody.innerHTML = '';

    for (const a of data.advisories || []) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong style="color:#fff; font-family:var(--font-display)">${escapeHtml(a.title)}</strong></td>
        <td><span class="severity-pill ${a.severity === 'CRITICAL' ? 'rose' : a.severity === 'HIGH' ? 'amber' : 'blue'}">${a.severity}</span></td>
        <td style="font-size:0.875rem; color:var(--text-secondary); max-width:380px; line-height:1.6">${escapeHtml(a.details)}</td>
        <td style="font-size:0.875rem; color:var(--cyan-bright); max-width:380px; line-height:1.6">${escapeHtml(a.recommendation)}</td>
        <td class="mono-cell" style="font-size:0.8rem">${escapeHtml(a.cve || 'N/A')}</td>
      `;
      tbody.appendChild(tr);
    }
  } catch (err) {
    console.error('Failed to load advisories:', err);
  }
}

// ==========================================================================
// Brand Surveillance & Homoglyphs Playground
// ==========================================================================
async function loadBrands() {
  try {
    const res = await fetch('/api/brands');
    const data = await res.json();
    const grid = document.getElementById('brands-grid');
    grid.innerHTML = '';

    for (const b of data.monitored || []) {
      const card = document.createElement('div');
      card.className = 'pillar-stat-card';
      card.innerHTML = `
        <div style="font-size:0.75rem; color:var(--cyan-bright); text-transform:uppercase; font-weight:700">${escapeHtml(b.category)}</div>
        <h4 style="font-family:var(--font-display); font-size:1.15rem; margin:0.4rem 0 0.2rem; color:#fff">${escapeHtml(b.brand_name)}</h4>
        <div class="mono-cell" style="color:var(--text-muted); font-size:0.85rem">${escapeHtml(b.official_domain)}</div>
        <div style="margin-top:0.85rem; font-size:0.75rem; color:var(--emerald-bright); display:flex; align-items:center; gap:0.4rem; font-weight:600">
          <span class="pulse-ring" style="width:6px; height:6px"></span>
          <span>Active Surveillance</span>
        </div>
      `;
      grid.appendChild(card);
    }
  } catch (err) {
    console.error('Failed to load brands:', err);
  }
}

function testHomoglyphSim() {
  const input = document.getElementById('homoglyph-test-input').value.trim();
  const out = document.getElementById('homoglyph-sim-output');

  if (!input) {
    out.textContent = 'Please enter a domain name above to analyze.';
    return;
  }

  // Shannon Entropy calculation
  const clean = input.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
  const freqs = {};
  for (const ch of clean) freqs[ch] = (freqs[ch] || 0) + 1;
  let entropy = 0;
  for (const ch in freqs) {
    const p = freqs[ch] / clean.length;
    entropy -= p * Math.log2(p);
  }

  const isHighEntropy = entropy > 3.75;
  const cyrillicSpoof = input
    .replace(/a/g, 'а')
    .replace(/o/g, 'о')
    .replace(/e/g, 'е')
    .replace(/p/g, 'р')
    .replace(/c/g, 'с');

  out.innerHTML = `
    <div style="margin-bottom:0.4rem"><strong>Analyzed String:</strong> <span style="color:#fff">${escapeHtml(input)}</span></div>
    <div style="margin-bottom:0.4rem">
      <strong>Shannon Entropy:</strong> <span style="color:${isHighEntropy ? 'var(--rose-bright)' : 'var(--emerald-bright)'}">${entropy.toFixed(3)}</span>
      ${isHighEntropy ? '<span class="severity-pill rose" style="font-size:0.7rem; padding:0.15rem 0.5rem; margin-left:0.5rem">High Entropy / DGA Candidate</span>' : '<span class="severity-pill emerald" style="font-size:0.7rem; padding:0.15rem 0.5rem; margin-left:0.5rem">Normal Human Pattern</span>'}
    </div>
    <div style="margin-bottom:0.4rem"><strong>Punycode Mapping:</strong> <code style="color:var(--cyan-bright)">xn--${encodeURIComponent(input).replace(/%/g, '')}</code></div>
    <div><strong>Simulated Cyrillic Homoglyph:</strong> <code style="color:var(--rose-bright)">${escapeHtml(cyrillicSpoof)}</code> <span class="severity-pill rose" style="font-size:0.7rem; padding:0.15rem 0.5rem; margin-left:0.5rem">IDN Homograph Threat</span></div>
  `;
}

// Utility: HTML escape
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
