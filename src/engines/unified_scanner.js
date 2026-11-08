/**
 * Unified Security & Threat Scanner Coordinator
 * Orchestrates multi-dimensional inspection across:
 * 1. Threat Heuristics & Lexical Impersonation
 * 2. TLS Certificate & Cryptographic Trust Validation (eMudhra / ROCA)
 * 3. Web Application Security Posture & Headers
 * 4. DNS Trust & Anti-Spoofing Records
 * 5. Collaborative Threat Intelligence & Community IOCs
 */

const { URL } = require('node:url');
const crypto = require('node:crypto');
const db = require('../database/db.js');
const { analyzeThreat, parseDomainParts } = require('./threat_analyzer.js');
const { validateWebsiteCertificate, parseCertificateDetails } = require('./cert_validator.js');
const { auditWebSecurity } = require('./sec_auditor.js');
const { auditDnsRecords } = require('./dns_auditor.js');
const { queryDomainIntel } = require('../threat_intel/feed_manager.js');
const { calculateCompositeScore } = require('./scoring_engine.js');
const { getMockTarget } = require('../sandbox/mock_targets.js');

/**
 * Executes a full multi-dimensional security scan on a given URL
 */
async function scanWebsite(rawUrl, options = {}) {
  const startTime = Date.now();

  let formattedUrl = rawUrl.trim();
  if (!formattedUrl.startsWith('http://') && !formattedUrl.startsWith('https://')) {
    formattedUrl = `https://${formattedUrl}`;
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(formattedUrl);
  } catch (err) {
    throw new Error(`Invalid URL format: ${rawUrl}`);
  }

  const hostname = parsedUrl.hostname.toLowerCase();
  const { apexDomain } = parseDomainParts(hostname);
  const scanId = `scan-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

  // Check if mock target available (enables robust testing without external network dependencies)
  const mockTarget = getMockTarget(formattedUrl);

  let pageHtml = '';
  let pageHeaders = {};
  let pageStatusCode = 200;
  let pageTitle = '';
  let certResult = null;
  let dnsResult = null;

  if (mockTarget && (!options.forceLive)) {
    // High-fidelity preconfigured scenario
    pageHtml = mockTarget.html;
    pageHeaders = mockTarget.headers;
    pageStatusCode = mockTarget.statusCode;

    // Extract title
    const titleMatch = pageHtml.match(/<title>([^<]+)<\/title>/i);
    pageTitle = titleMatch ? titleMatch[1] : '';

    // Certificate
    certResult = {
      status: 'SUCCESS',
      protocol: 'TLSv1.3',
      cipher: { name: 'TLS_AES_256_GCM_SHA384', standardName: 'TLS_AES_256_GCM_SHA384' },
      authorized: true,
      ...parseCertificateDetails(mockTarget.cert, { hostname })
    };

    // DNS
    dnsResult = {
      domain: hostname,
      score: 80,
      dnsFlags: [],
      ...mockTarget.dns
    };
  } else {
    // Live Network Scanning
    // 1. DNS Audit
    try {
      dnsResult = await auditDnsRecords(hostname);
    } catch {
      dnsResult = { domain: hostname, score: 20, dnsFlags: [], error: 'DNS lookup failed' };
    }

    // 2. TLS Certificate Validation
    try {
      certResult = await validateWebsiteCertificate(hostname, { timeout: 6000 });
    } catch (err) {
      certResult = {
        status: 'TLS_CONNECTION_FAILED',
        error: err.message,
        certRiskScore: 40,
        certFlags: [{ rule: 'TLS_ERROR', severity: 'HIGH', description: err.message }]
      };
    }

    // 3. Page Fetch (HTML & Headers)
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 7000);

      const response = await fetch(formattedUrl, {
        signal: controller.signal,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) TrustMatrix/1.0 SecurityScanner'
        },
        redirect: 'follow'
      });

      clearTimeout(timeoutId);
      pageStatusCode = response.status;

      // Extract headers
      for (const [key, value] of response.headers.entries()) {
        pageHeaders[key.toLowerCase()] = value;
      }

      pageHtml = await response.text();
      const titleMatch = pageHtml.match(/<title>([^<]+)<\/title>/i);
      pageTitle = titleMatch ? titleMatch[1] : '';
    } catch (err) {
      pageHeaders = {};
      pageHtml = '';
    }
  }

  // 4. Threat Heuristics Analysis
  const threatResult = analyzeThreat(formattedUrl, pageHtml, {
    title: pageTitle,
    headers: pageHeaders
  });

  // 5. Web Application Security Audit
  const secResult = auditWebSecurity(pageHeaders, pageHtml, formattedUrl);

  // 6. Collaborative Threat Intelligence Lookup
  const intelResult = queryDomainIntel(apexDomain || hostname, formattedUrl);

  // 7. Composite Risk Scoring & Recommendations
  const compositeResult = calculateCompositeScore(threatResult, certResult, secResult, intelResult);

  const durationMs = Date.now() - startTime;

  const finalReport = {
    scanId,
    targetUrl: formattedUrl,
    domain: hostname,
    apexDomain,
    pageTitle: pageTitle || 'N/A',
    pageStatusCode,
    durationMs,
    scannedAt: new Date().toISOString(),
    composite: compositeResult,
    threatAnalysis: threatResult,
    certAnalysis: certResult,
    securityPosture: secResult,
    dnsTrust: dnsResult,
    threatIntelligence: intelResult
  };

  // Persist to SQLite Database
  try {
    const insertScan = db.prepare(`
      INSERT INTO scans (
        id, url, domain, risk_score, severity,
        threat_analysis, cert_analysis, security_analysis, dns_analysis,
        collaborative_intel, summary, created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `);

    insertScan.run(
      scanId,
      formattedUrl,
      hostname,
      compositeResult.compositeScore,
      compositeResult.severity,
      JSON.stringify(threatResult),
      JSON.stringify(certResult),
      JSON.stringify(secResult),
      JSON.stringify(dnsResult),
      JSON.stringify(intelResult),
      compositeResult.summary
    );
  } catch (err) {
    console.error('[Scanner] Failed to save scan to SQLite:', err.message);
  }

  return finalReport;
}

/**
 * Returns recent scan history
 */
function getScanHistory(limit = 20) {
  const rows = db.prepare(`
    SELECT id, url, domain, risk_score, severity, summary, created_at
    FROM scans
    ORDER BY created_at DESC
    LIMIT ?
  `).all(limit);

  return rows;
}

/**
 * Retrieves a single scan by ID
 */
function getScanById(scanId) {
  const row = db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId);
  if (!row) return null;

  return {
    scanId: row.id,
    targetUrl: row.url,
    domain: row.domain,
    riskScore: row.risk_score,
    severity: row.severity,
    summary: row.summary,
    scannedAt: row.created_at,
    threatAnalysis: JSON.parse(row.threat_analysis),
    certAnalysis: JSON.parse(row.cert_analysis),
    securityPosture: JSON.parse(row.security_analysis),
    dnsTrust: JSON.parse(row.dns_analysis),
    threatIntelligence: JSON.parse(row.collaborative_intel)
  };
}

module.exports = {
  scanWebsite,
  getScanHistory,
  getScanById
};
