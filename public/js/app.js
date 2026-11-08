/**
 * TrustMatrix Frontend Application Logic
 * Manages tab switching, real-time scanning telemetry, gauge animations,
 * community voting, and STIX exports.
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
// Tab Switching
// ==========================================================================
function switchTab(tabId) {
  // Update header nav buttons
  document.querySelectorAll('.nav-link').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('onclick')?.includes(tabId));
  });

  // Update tab sections
  document.querySelectorAll('.tab-pane').forEach(pane => {
    pane.classList.remove('active');
  });

  const activePane = document.getElementById(`tab-${tabId}`);
  if (activePane) {
    activePane.classList.add('active');
  }
}

function switchDetailTab(panelId) {
  document.querySelectorAll('.detail-tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('onclick')?.includes(panelId));
  });

  document.querySelectorAll('.detail-panel').forEach(panel => {
    panel.classList.remove('active');
  });

  const activePanel = document.getElementById(`detail-panel-${panelId}`);
  if (activePanel) {
    activePanel.classList.add('active');
  }
}

// ==========================================================================
// Live Scan Submission & Rendering
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
  const btnText = document.getElementById('scan-btn-text');

  btn.disabled = true;
  spinner.style.display = 'inline-block';
  btnText.textContent = 'SCANNING...';

  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      throw new Error(`Scan request failed with HTTP ${response.status}`);
    }

    const data = await response.json();
    currentScanData = data;
    renderScanResults(data);
  } catch (err) {
    alert(`Scan error: ${err.message}`);
  } finally {
    btn.disabled = false;
    spinner.style.display = 'none';
    btnText.textContent = 'INSPECT TARGET';
  }
}

function renderScanResults(data) {
  const container = document.getElementById('scan-result-container');
  container.style.display = 'block';

  // 1. Header Overview & Gauge
  const score = data.composite.compositeScore;
  const severity = data.composite.severity;
  const badgeColor = data.composite.badgeColor;

  document.getElementById('res-target-domain').textContent = data.domain;
  document.getElementById('res-score-number').textContent = score;
  document.getElementById('res-summary-text').textContent = data.composite.summary;
  document.getElementById('res-scan-id').textContent = data.scanId;
  document.getElementById('res-scanned-at').textContent = new Date(data.scannedAt).toLocaleTimeString();
  document.getElementById('res-status-code').textContent = `${data.pageStatusCode || 200} OK`;

  // Severity Tag
  const tag = document.getElementById('res-severity-tag');
  tag.className = `severity-tag ${badgeColor}`;
  tag.textContent = severity.replace('_', ' ');

  // SVG Gauge Animation (Radius 42, Circumference ~264)
  const circle = document.getElementById('gauge-progress');
  const circumference = 2 * Math.PI * 42;
  const offset = circumference - (score / 100) * circumference;
  circle.style.strokeDasharray = `${circumference} ${circumference}`;
  circle.style.strokeDashoffset = offset;

  let strokeColor = 'var(--status-rose)';
  if (score < 25) strokeColor = 'var(--status-emerald)';
  else if (score < 50) strokeColor = 'var(--accent-cyan)';
  else if (score < 70) strokeColor = 'var(--status-yellow)';
  else if (score < 90) strokeColor = 'var(--status-amber)';
  circle.style.stroke = strokeColor;
  document.getElementById('res-score-number').style.color = strokeColor;

  // 2. 4-Pillar Score Cards
  const sub = data.composite.subscores;

  // Pillar 1: Threat Heuristics
  document.getElementById('pillar-threat-score').textContent = `${sub.threatHeuristics}/100`;
  document.getElementById('pillar-threat-bar').style.width = `${sub.threatHeuristics}%`;
  document.getElementById('pillar-threat-label').textContent = data.threatAnalysis.threatCategory.replace(/_/g, ' ');

  // Pillar 2: Certificate Risk
  document.getElementById('pillar-cert-score').textContent = `${sub.certificateTrust}/100`;
  document.getElementById('pillar-cert-bar').style.width = `${sub.certificateTrust}%`;
  document.getElementById('pillar-cert-label').textContent = data.certAnalysis.hasCert
    ? `Cert Age: ${data.certAnalysis.ageInDays || 0}d (${data.certAnalysis.keyAudit?.asymmetricKeyType?.toUpperCase() || 'RSA'})`
    : 'No Valid Certificate';

  // Pillar 3: Web App Posture
  document.getElementById('pillar-web-score').textContent = `Grade ${data.securityPosture.grade}`;
  document.getElementById('pillar-web-bar').style.width = `${data.securityPosture.securityScore}%`;
  document.getElementById('pillar-web-label').textContent = `Score: ${data.securityPosture.securityScore}/100`;

  // Pillar 4: Collaborative Intel
  const isMalicious = data.threatIntelligence.isKnownMalicious;
  document.getElementById('pillar-intel-score').textContent = isMalicious ? 'MATCH' : 'CLEAN';
  document.getElementById('pillar-intel-score').style.color = isMalicious ? 'var(--status-rose)' : 'var(--status-emerald)';
  document.getElementById('pillar-intel-bar').style.width = isMalicious ? '100%' : '15%';
  document.getElementById('pillar-intel-bar').style.backgroundColor = isMalicious ? 'var(--status-rose)' : 'var(--status-emerald)';
  document.getElementById('pillar-intel-label').textContent = isMalicious
    ? `${data.threatIntelligence.matchedCategory || 'Known IOC'}`
    : 'No active IOC match';

  // 3. Detail Sub-Tabs Content

  // Detail Tab 1: Threat Flags & Telemetry
  const threatFlags = data.threatAnalysis.redFlags || [];
  document.getElementById('count-threat-flags').textContent = threatFlags.length;

  const flagsContainer = document.getElementById('threat-flags-list');
  flagsContainer.innerHTML = '';

  if (threatFlags.length === 0) {
    flagsContainer.innerHTML = '<div style="color:var(--status-emerald); font-size:0.9rem">✅ No deceptive or malicious behavioral patterns detected.</div>';
  } else {
    for (const flag of threatFlags) {
      const item = document.createElement('div');
      item.className = `flag-item ${flag.severity}`;
      item.innerHTML = `
        <div class="flag-header">
          <span>${escapeHtml(flag.rule)}</span>
          <span class="severity-tag ${flag.severity === 'CRITICAL' ? 'rose' : flag.severity === 'HIGH' ? 'amber' : 'yellow'}">${flag.severity}</span>
        </div>
        <div class="flag-desc">${escapeHtml(flag.description)}</div>
      `;
      flagsContainer.appendChild(item);
    }
  }

  // Telemetry items
  document.getElementById('telemetry-apex').textContent = data.apexDomain || 'N/A';
  document.getElementById('telemetry-entropy').textContent = data.threatAnalysis.lexical?.domainEntropy || '0';
  document.getElementById('telemetry-homoglyphs').textContent = data.threatAnalysis.lexical?.homoglyphAnalysis?.hasMixedScripts
    ? `⚠️ Lookalikes (${data.threatAnalysis.lexical.homoglyphAnalysis.homoglyphsFound.length})`
    : 'None (Clean)';
  document.getElementById('telemetry-subdomains').textContent = data.threatAnalysis.lexical?.subdomains || '(none)';
  document.getElementById('telemetry-brand').textContent = data.threatAnalysis.lexical?.matchedBrand
    ? `${data.threatAnalysis.lexical.matchedBrand.brand} (${data.threatAnalysis.lexical.matchedBrand.isOfficial ? 'OFFICIAL' : 'IMPERSONATION'})`
    : 'None';
  document.getElementById('telemetry-inputs').textContent = data.threatAnalysis.content?.hasPasswordField ? 'Password Form Detected' : 'None';

  // Detail Tab 2: Certificate & PKI Audit
  const cert = data.certAnalysis;
  const certFlagsContainer = document.getElementById('cert-flags-list');
  certFlagsContainer.innerHTML = '';

  if (cert.certFlags && cert.certFlags.length > 0) {
    for (const flag of cert.certFlags) {
      const item = document.createElement('div');
      item.className = `flag-item ${flag.severity}`;
      item.innerHTML = `
        <div class="flag-header">
          <span>${escapeHtml(flag.rule)}</span>
          <span class="severity-tag ${flag.severity === 'CRITICAL' ? 'rose' : 'amber'}">${flag.severity}</span>
        </div>
        <div class="flag-desc">${escapeHtml(flag.description)}</div>
      `;
      certFlagsContainer.appendChild(item);
    }
  }

  document.getElementById('cert-subject').textContent = cert.subjectCommonName || cert.subject || 'N/A';
  document.getElementById('cert-issuer').textContent = cert.issuer || 'N/A';
  document.getElementById('cert-validity').textContent = `${cert.validFrom || '-'} to ${cert.validTo || '-'}`;
  document.getElementById('cert-age-details').textContent = `${cert.ageInDays || 0} days old (Lifespan: ${cert.lifespanInDays || 0} days)`;
  document.getElementById('res-cert-age-badge').textContent = `Age: ${cert.ageInDays || 0} days`;

  // Key & Modulus
  const keyType = cert.keyAudit?.asymmetricKeyType?.toUpperCase() || 'RSA';
  const keyLen = cert.keyAudit?.modulusLength || 2048;
  document.getElementById('cert-key-details').textContent = `${keyType} (${keyLen} bits, Exponent: ${cert.keyAudit?.publicExponent || '65537'})`;

  // ROCA status
  const rocaEl = document.getElementById('cert-roca-status');
  if (cert.rocaTest?.isVulnerable) {
    rocaEl.innerHTML = '<span class="severity-tag rose">CRITICAL VULNERABLE (CVE-2017-15361)</span>';
  } else {
    rocaEl.innerHTML = '<span class="severity-tag emerald">PASS (ROCA Clean)</span>';
  }

  // eMudhra status
  const emudhraEl = document.getElementById('cert-emudhra-status');
  if (cert.caAudit?.eMudhraAnalysis?.isEMudhraCA) {
    emudhraEl.innerHTML = `<span class="severity-tag amber">AUDIT WARNING: eMudhra CA Profile (${cert.caAudit.eMudhraAnalysis.auditStatus})</span>`;
  } else {
    emudhraEl.innerHTML = '<span class="severity-tag emerald">Standard Root CA</span>';
  }

  // CT status
  document.getElementById('cert-ct-status').innerHTML = cert.hasCertificateTransparency
    ? '<span class="severity-tag emerald">CT SCTs Present</span>'
    : '<span class="severity-tag amber">No CT Proof Detected</span>';

  document.getElementById('cert-sigalg').textContent = cert.signatureAlgorithm || 'N/A';
  document.getElementById('cert-sans').textContent = (cert.subjectAltNames || []).join(', ') || 'None';
  document.getElementById('cert-fingerprint').textContent = cert.fingerprint256 || 'N/A';

  // Detail Tab 3: Security Headers
  document.getElementById('res-security-grade-badge').textContent = `Grade: ${data.securityPosture.grade} (${data.securityPosture.securityScore}/100)`;
  document.getElementById('res-security-grade-badge').className = `severity-tag ${data.securityPosture.grade === 'A+' || data.securityPosture.grade === 'A' ? 'emerald' : data.securityPosture.grade === 'B' ? 'blue' : 'rose'}`;

  const secTbody = document.getElementById('security-headers-tbody');
  secTbody.innerHTML = '';

  for (const h of data.securityPosture.headerAudits || []) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${escapeHtml(h.displayName)}</strong></td>
      <td>
        <span class="severity-tag ${h.present ? 'emerald' : 'rose'}">
          ${h.present ? 'CONFIGURED' : 'MISSING'}
        </span>
      </td>
      <td class="code-font" style="max-width:350px; overflow-wrap:break-word">${escapeHtml(h.value || 'Not Set')}</td>
      <td style="font-size:0.8rem; color:var(--text-muted)">${escapeHtml(h.recommendation || 'Standard protection enabled')}</td>
    `;
    secTbody.appendChild(tr);
  }

  document.getElementById('sec-server-banner').textContent = data.securityPosture.serverBanner;
  document.getElementById('sec-powered-by').textContent = data.securityPosture.poweredBy;

  // Detail Tab 4: DNS Trust
  const dns = data.dnsTrust;
  document.getElementById('res-dns-score-badge').textContent = `DNS Trust: ${dns.score}/100`;
  document.getElementById('dns-ipv4').textContent = (dns.ipv4Addresses || []).join(', ') || 'No A record';
  document.getElementById('dns-mx').textContent = dns.hasMx ? `${dns.mxRecords.length} mail servers` : 'None';
  document.getElementById('dns-spf').textContent = dns.spfRecord || 'No SPF record';
  document.getElementById('dns-dmarc').textContent = dns.dmarcRecord || 'No DMARC record';
  document.getElementById('dns-caa').textContent = dns.hasCaa
    ? dns.caaRecords.map(c => `${c.tag} "${c.value}"`).join(', ')
    : 'No CAA records';

  document.getElementById('dns-spoof-eval').innerHTML = dns.emailSpoofingProtection === 'STRONG_ENFORCED'
    ? '<span class="severity-tag emerald">STRICTLY PROTECTED (p=reject)</span>'
    : '<span class="severity-tag rose">VULNERABLE TO EMAIL SPOOFING</span>';

  document.getElementById('dns-caa-eval').innerHTML = dns.caaProtection === 'STRICT_CAA_ENFORCED'
    ? '<span class="severity-tag emerald">RESTRICTED CA ISSUANCE</span>'
    : '<span class="severity-tag yellow">UNRESTRICTED (Any CA can issue)</span>';

  // Detail Tab 5: Collaborative Intel
  const intelContent = document.getElementById('intel-details-content');
  intelContent.innerHTML = '';

  const intelBadge = document.getElementById('intel-verdict-badge');
  intelBadge.textContent = isMalicious ? 'KNOWN THREAT' : 'CLEAN REPUTATION';
  intelBadge.className = `severity-tag ${isMalicious ? 'rose' : 'emerald'}`;

  if (isMalicious) {
    intelContent.innerHTML = `
      <div style="background-color:rgba(244,63,94,0.1); border:1px solid rgba(244,63,94,0.3); border-radius:8px; padding:1.25rem; margin-bottom:1rem">
        <h4 style="color:#fda4af; margin-bottom:0.5rem">⚠️ Verified Malicious Indicator</h4>
        <p style="font-size:0.9rem; color:var(--text-muted); margin-bottom:0.75rem">
          This domain is actively tracked in our distributed Threat Intelligence feed targeting <strong>${escapeHtml(data.threatIntelligence.targetBrand || 'Multiple Organizations')}</strong>.
        </p>
        <div style="font-size:0.85rem">
          <strong>Category:</strong> ${escapeHtml(data.threatIntelligence.matchedCategory || 'Phishing')}<br>
          <strong>Feed Confidence:</strong> ${data.threatIntelligence.confidence}%<br>
          <strong>Community Consensus:</strong> ${data.threatIntelligence.verifiedReportsCount} verified reports
        </div>
      </div>
    `;
  } else {
    intelContent.innerHTML = `
      <div style="background-color:rgba(16,185,129,0.08); border:1px solid rgba(16,185,129,0.25); border-radius:8px; padding:1.25rem">
        <h4 style="color:#6ee7b7; margin-bottom:0.5rem">✅ Clean Threat Intelligence Record</h4>
        <p style="font-size:0.9rem; color:var(--text-muted)">
          No active indicators of compromise (IOCs) or pending community incident reports were identified for domain <code>${escapeHtml(data.domain)}</code>.
        </p>
      </div>
    `;
  }

  // Detail Tab 6: Remediation Guidance
  const recContainer = document.getElementById('remediation-list');
  recContainer.innerHTML = '';

  if (data.composite.recommendations.length === 0) {
    recContainer.innerHTML = '<div style="color:var(--status-emerald)">No urgent security remediations required. All parameters comply with baseline standards.</div>';
  } else {
    for (const rec of data.composite.recommendations) {
      const item = document.createElement('div');
      item.className = `flag-item ${rec.priority === 'CRITICAL' ? 'CRITICAL' : rec.priority === 'HIGH' ? 'HIGH' : 'MEDIUM'}`;
      item.innerHTML = `
        <div class="flag-header">
          <span>${escapeHtml(rec.title)}</span>
          <span class="severity-tag ${rec.priority === 'CRITICAL' ? 'rose' : 'amber'}">${rec.priority}</span>
        </div>
        <div class="flag-desc">${escapeHtml(rec.action)}</div>
      `;
      recContainer.appendChild(item);
    }
  }

  // Smooth scroll down to results
  container.scrollIntoView({ behavior: 'smooth', block: 'start' });
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
}

// ==========================================================================
// Collaborative Intel, Reports & Voting
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
      <td><span class="severity-tag ${ioc.ioc_type === 'DOMAIN' ? 'blue' : 'amber'}">${escapeHtml(ioc.ioc_type)}</span></td>
      <td class="code-font"><strong>${escapeHtml(ioc.value)}</strong></td>
      <td>${escapeHtml(ioc.threat_category)}</td>
      <td><strong style="color:var(--text-main)">${escapeHtml(ioc.target_brand || 'Multiple')}</strong></td>
      <td><span class="severity-tag ${ioc.severity === 'CRITICAL' ? 'rose' : 'amber'}">${ioc.severity}</span></td>
      <td style="font-size:0.75rem; color:var(--text-dim)">${escapeHtml(ioc.source)}</td>
      <td>${ioc.confidence}%</td>
      <td style="font-size:0.8rem; color:var(--text-dim)">${new Date(ioc.last_seen).toLocaleDateString()}</td>
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
        <strong class="code-font" style="color:var(--accent-cyan)">${escapeHtml(r.domain)}</strong>
        <div style="font-size:0.75rem; color:var(--text-dim)">${escapeHtml(r.url)}</div>
      </td>
      <td>${escapeHtml(r.category)}</td>
      <td>${escapeHtml(r.target_brand || 'General')}</td>
      <td>
        <strong>${escapeHtml(r.reporter_name)}</strong>
        <div style="font-size:0.75rem; color:var(--text-dim)">${escapeHtml(r.reporter_role || 'Contributor')}</div>
      </td>
      <td>
        <span style="color:var(--status-emerald); font-weight:700">▲ ${r.upvotes || 0}</span>
        <span style="color:var(--status-rose); font-weight:700; margin-left:0.5rem">▼ ${r.downvotes || 0}</span>
      </td>
      <td>
        <span class="severity-tag ${r.status === 'VERIFIED' ? 'rose' : r.status === 'FALSE_POSITIVE' ? 'emerald' : 'yellow'}">
          ${r.status}
        </span>
      </td>
      <td>
        <div style="display:flex; gap:0.4rem">
          <button class="pill-sample safe" onclick="voteReport('${r.id}', 'UPVOTE')">▲ Confirm</button>
          <button class="pill-sample danger" onclick="voteReport('${r.id}', 'DOWNVOTE')">▼ Dispute</button>
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
      alert('Threat report submitted successfully! It has been added to the analyst peer review queue.');
    }
  } catch (err) {
    alert(`Failed to submit report: ${err.message}`);
  }
}

function exportSTIX() {
  window.open('/api/iocs/export/stix', '_blank');
}

// ==========================================================================
// CA Advisories & eMudhra Registry
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
        <td><strong style="color:var(--text-main)">${escapeHtml(a.title)}</strong></td>
        <td><span class="severity-tag ${a.severity === 'CRITICAL' ? 'rose' : a.severity === 'HIGH' ? 'amber' : 'yellow'}">${a.severity}</span></td>
        <td style="font-size:0.85rem; color:var(--text-muted); max-width:350px">${escapeHtml(a.details)}</td>
        <td style="font-size:0.85rem; color:var(--accent-cyan); max-width:350px">${escapeHtml(a.recommendation)}</td>
        <td class="code-font" style="font-size:0.8rem">${escapeHtml(a.cve || 'N/A')}</td>
      `;
      tbody.appendChild(tr);
    }
  } catch (err) {
    console.error('Failed to load advisories:', err);
  }
}

// ==========================================================================
// Brand Surveillance & Homoglyphs
// ==========================================================================
async function loadBrands() {
  try {
    const res = await fetch('/api/brands');
    const data = await res.json();
    const grid = document.getElementById('brands-grid');
    grid.innerHTML = '';

    for (const b of data.monitored || []) {
      const card = document.createElement('div');
      card.className = 'pillar-card';
      card.innerHTML = `
        <div style="font-size:0.75rem; color:var(--accent-cyan); text-transform:uppercase; font-weight:700">${escapeHtml(b.category)}</div>
        <h4 style="font-size:1.05rem; margin:0.35rem 0 0.2rem">${escapeHtml(b.brand_name)}</h4>
        <div class="code-font" style="color:var(--text-muted); font-size:0.85rem">${escapeHtml(b.official_domain)}</div>
        <div style="margin-top:0.75rem; font-size:0.75rem; color:var(--status-emerald); display:flex; align-items:center; gap:0.4rem">
          <span class="pulse-dot" style="width:6px; height:6px"></span>
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
    out.textContent = 'Please enter a domain name.';
    return;
  }

  // Calculate Shannon Entropy
  const clean = input.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
  const freqs = {};
  for (const ch of clean) freqs[ch] = (freqs[ch] || 0) + 1;
  let entropy = 0;
  for (const ch in freqs) {
    const p = freqs[ch] / clean.length;
    entropy -= p * Math.log2(p);
  }

  out.innerHTML = `
    <div><strong>Target Domain:</strong> ${escapeHtml(input)}</div>
    <div><strong>Character Entropy:</strong> ${entropy.toFixed(3)} ${entropy > 3.8 ? '<span class="severity-tag rose">High / DGA Pattern</span>' : '<span class="severity-tag emerald">Normal</span>'}</div>
    <div><strong>Punycode Encoded:</strong> xn--${encodeURIComponent(input).replace(/%/g, '')}</div>
    <div style="margin-top:0.4rem"><strong>Simulated Cyrillic Homoglyph:</strong> ${escapeHtml(input.replace(/a/g, 'а').replace(/o/g, 'о').replace(/e/g, 'е'))} <span class="severity-tag rose">IDN SPOOF</span></div>
  `;
}

// Utility: escape HTML
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
