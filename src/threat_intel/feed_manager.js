/**
 * Threat Intelligence Feed Manager & IOC Repository
 * Handles IOC lookups, threat feed synchronization, and STIX 2.1 export.
 */

const db = require('../database/db.js');
const crypto = require('node:crypto');

function queryDomainIntel(domain, rawUrl = '') {
  const matchingIocs = [];
  let isKnownMalicious = false;
  let maxConfidence = 0;
  let matchedCategory = null;
  let targetBrand = null;

  // 1. Check DOMAIN match
  const domainIoc = db.prepare("SELECT * FROM threat_iocs WHERE ioc_type = 'DOMAIN' AND value = ? AND active = 1").get(domain.toLowerCase());
  if (domainIoc) {
    matchingIocs.push(domainIoc);
    isKnownMalicious = true;
    maxConfidence = Math.max(maxConfidence, domainIoc.confidence);
    matchedCategory = domainIoc.threat_category;
    targetBrand = domainIoc.target_brand;
  }

  // 2. Check full URL match if provided
  if (rawUrl) {
    const urlIoc = db.prepare("SELECT * FROM threat_iocs WHERE ioc_type = 'URL' AND value = ? AND active = 1").get(rawUrl);
    if (urlIoc) {
      matchingIocs.push(urlIoc);
      isKnownMalicious = true;
      maxConfidence = Math.max(maxConfidence, urlIoc.confidence);
      matchedCategory = urlIoc.threat_category;
      targetBrand = urlIoc.target_brand;
    }
  }

  // 3. Check Community Threat Reports
  const communityReports = db.prepare('SELECT * FROM threat_reports WHERE domain = ? ORDER BY upvotes DESC').all(domain.toLowerCase());
  const verifiedReports = communityReports.filter(r => r.status === 'VERIFIED');

  if (verifiedReports.length > 0) {
    isKnownMalicious = true;
    maxConfidence = Math.max(maxConfidence, verifiedReports[0].confidence);
    matchedCategory = matchedCategory || verifiedReports[0].category;
    targetBrand = targetBrand || verifiedReports[0].target_brand;
  }

  // Calculate Intel Risk Score
  let intelRiskScore = 0;
  if (isKnownMalicious) {
    intelRiskScore = Math.min(Math.round(maxConfidence * 1.05), 100);
  } else if (communityReports.length > 0) {
    // Has pending reports
    intelRiskScore = 40;
  }

  return {
    domain,
    isKnownMalicious,
    intelRiskScore,
    matchedCategory,
    targetBrand,
    confidence: maxConfidence,
    matchingIocs,
    communityReports,
    verifiedReportsCount: verifiedReports.length,
    pendingReportsCount: communityReports.length - verifiedReports.length
  };
}

/**
 * Exports current IOC database as standardized STIX 2.1 JSON Bundle
 */
function exportSTIX21Bundle() {
  const iocs = db.prepare('SELECT * FROM threat_iocs WHERE active = 1').all();
  const now = new Date().toISOString();

  const bundleObjects = [
    {
      type: 'identity',
      spec_version: '2.1',
      id: 'identity--b7e2832e-5f8e-4a6c-b26a-9b43d2c3e101',
      name: 'TrustMatrix Threat Intelligence Platform',
      identity_class: 'organization',
      created: now,
      modified: now
    }
  ];

  for (const ioc of iocs) {
    let pattern = '';
    let name = '';

    if (ioc.ioc_type === 'DOMAIN') {
      pattern = `[domain-name:value = '${ioc.value}']`;
      name = `Malicious Domain: ${ioc.value}`;
    } else if (ioc.ioc_type === 'URL') {
      pattern = `[url:value = '${ioc.value}']`;
      name = `Phishing URL: ${ioc.value}`;
    } else if (ioc.ioc_type === 'IP') {
      pattern = `[ipv4-addr:value = '${ioc.value}']`;
      name = `Malicious Host IP: ${ioc.value}`;
    } else if (ioc.ioc_type === 'CERT_SHA256') {
      pattern = `[x509-certificate:hashes.'SHA-256' = '${ioc.value}']`;
      name = `Compromised / Flawed Certificate: ${ioc.value}`;
    }

    bundleObjects.push({
      type: 'indicator',
      spec_version: '2.1',
      id: `indicator--${crypto.randomUUID()}`,
      created: ioc.first_seen || now,
      modified: ioc.last_seen || now,
      name,
      description: `Indicator identified by ${ioc.source} targeting ${ioc.target_brand || 'General Victims'} - ${ioc.threat_category}`,
      indicator_types: ['malicious-activity', 'attribution'],
      pattern,
      pattern_type: 'stix',
      pattern_version: '2.1',
      valid_from: ioc.first_seen || now,
      confidence: ioc.confidence || 80
    });
  }

  return {
    type: 'bundle',
    id: `bundle--${crypto.randomUUID()}`,
    spec_version: '2.1',
    objects: bundleObjects
  };
}

/**
 * Returns summary statistics of threat intelligence feeds
 */
function getIntelStatistics() {
  const totalIocs = db.prepare('SELECT COUNT(*) as count FROM threat_iocs WHERE active = 1').get().count;
  const totalReports = db.prepare('SELECT COUNT(*) as count FROM threat_reports').get().count;
  const verifiedReports = db.prepare("SELECT COUNT(*) as count FROM threat_reports WHERE status = 'VERIFIED'").get().count;
  const monitoredBrands = db.prepare('SELECT COUNT(*) as count FROM monitored_brands WHERE active = 1').get().count;

  const topCategories = db.prepare(`
    SELECT threat_category, COUNT(*) as count
    FROM threat_iocs
    GROUP BY threat_category
    ORDER BY count DESC
    LIMIT 5
  `).all();

  const recentIocs = db.prepare(`
    SELECT id, ioc_type, value, threat_category, target_brand, severity, source, confidence, last_seen
    FROM threat_iocs
    ORDER BY last_seen DESC
    LIMIT 10
  `).all();

  return {
    totalIocs,
    totalReports,
    verifiedReports,
    monitoredBrands,
    topCategories,
    recentIocs
  };
}

module.exports = {
  queryDomainIntel,
  exportSTIX21Bundle,
  getIntelStatistics
};
