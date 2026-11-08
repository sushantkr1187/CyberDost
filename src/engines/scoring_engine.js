/**
 * Composite Threat Scoring & Recommendation Engine
 * Combines multi-dimensional signals:
 * - Threat Heuristics (35%)
 * - Certificate & Cryptographic Trust (25%)
 * - Web Application Security (20%)
 * - Collaborative Community Threat Intel (20%)
 */

function calculateCompositeScore(threatRes, certRes, secRes, intelRes) {
  // Threat heuristics score (0 - 100, where 100 is most dangerous)
  const threatScore = threatRes.compositeThreatScore || 0;

  // Certificate risk score (0 - 100, where 100 is most dangerous)
  const certScore = certRes.certRiskScore || 0;

  // Web security inverted: secRes.securityScore is 0-100 where 100 is best security,
  // so risk is (100 - securityScore)
  const webSecurityScore = typeof secRes.securityScore === 'number' ? secRes.securityScore : 50;
  const webRiskScore = Math.max(0, 100 - webSecurityScore);

  // Collaborative Intel risk score (0 - 100)
  const intelScore = intelRes.intelRiskScore || 0;

  // Weighted calculation
  let composite = Math.round(
    threatScore * 0.35 +
    certScore * 0.25 +
    webRiskScore * 0.20 +
    intelScore * 0.20
  );

  // Critical Overrides:
  // 1. If verified in Community IOC as active phishing, minimum score is 90
  if (intelRes.isKnownMalicious) {
    composite = Math.max(composite, 92);
  }

  // 2. If ROCA vulnerable or Distrusted CA, minimum score is 88
  if (certRes.rocaTest?.isVulnerable || certRes.caAudit?.isDistrusted) {
    composite = Math.max(composite, 88);
  }

  // 3. If Brand Impersonation detected with password exfiltration webhook, minimum score is 95
  if (threatRes.lexical?.matchedBrand && !threatRes.lexical.matchedBrand.isOfficial && threatRes.content?.hasSuspiciousAction) {
    composite = Math.max(composite, 95);
  }

  // Clamp 0 - 100
  composite = Math.min(Math.max(composite, 0), 100);

  // Determine Severity Tier
  let severity = 'SAFE';
  let badgeColor = 'emerald';

  if (composite >= 90) {
    severity = 'CRITICAL_MALICIOUS';
    badgeColor = 'rose';
  } else if (composite >= 70) {
    severity = 'HIGH_RISK';
    badgeColor = 'amber';
  } else if (composite >= 45) {
    severity = 'SUSPICIOUS';
    badgeColor = 'yellow';
  } else if (composite >= 25) {
    severity = 'LOW_RISK';
    badgeColor = 'blue';
  } else {
    severity = 'SAFE';
    badgeColor = 'emerald';
  }

  // Generate Executive Summary
  let summary = '';
  if (severity === 'CRITICAL_MALICIOUS') {
    summary = `CRITICAL THREAT DETECTED: This website exhibits verified characteristics of an active deceptive cyber threat. Immediate blocking recommended.`;
  } else if (severity === 'HIGH_RISK') {
    summary = `HIGH RISK WARNING: Significant phishing markers, brand spoofing, or compromised cryptographic trust parameters were identified. Exercise extreme caution.`;
  } else if (severity === 'SUSPICIOUS') {
    summary = `SUSPICIOUS BEHAVIOR: Multiple heuristic indicators or missing security safeguards warrant elevated scrutiny before entering credentials.`;
  } else if (severity === 'LOW_RISK') {
    summary = `LOW RISK: Standard website with minor configuration oversights, but no active phishing or identity spoofing detected.`;
  } else {
    summary = `VERIFIED SAFE: Website conforms to strict security standards, valid cryptographic trust hierarchy, and clean threat intelligence reputation.`;
  }

  // Generate Remediation & User Guidance
  const recommendations = [];

  if (threatRes.lexical?.matchedBrand && !threatRes.lexical.matchedBrand.isOfficial) {
    recommendations.push({
      priority: 'CRITICAL',
      title: 'Brand Impersonation Alert',
      action: `Do NOT submit passwords or personal information. The real service is hosted at ${threatRes.lexical.matchedBrand.brand}.`
    });
  }

  if (certRes.caAudit?.eMudhraAnalysis?.isEMudhraCA) {
    recommendations.push({
      priority: 'HIGH',
      title: 'eMudhra CA Key Generation Audit Advisory',
      action: 'Ensure subscriber key uses verified >= 2048-bit RSA with clean CT log inclusion and strict CAA records to prevent unauthorized sub-CA issuance.'
    });
  }

  if (certRes.rocaTest?.isVulnerable) {
    recommendations.push({
      priority: 'CRITICAL',
      title: 'Revoke and Reissue Key (ROCA Vulnerability)',
      action: 'The RSA public key matches the Infineon ROCA factorization flaw. Immediately regenerate keypair using a certified secure hardware module or OpenSSL.'
    });
  }

  if (secRes.grade === 'F' || secRes.grade === 'D') {
    recommendations.push({
      priority: 'MEDIUM',
      title: 'Harden Web Application Security Headers',
      action: 'Deploy strict Content-Security-Policy (CSP), HSTS (Strict-Transport-Security), and X-Frame-Options to protect users from XSS and clickjacking.'
    });
  }

  if (intelRes.isKnownMalicious) {
    recommendations.push({
      priority: 'CRITICAL',
      title: 'Domain Listed in Community IOC Threat Database',
      action: 'Domain has been flagged by security researchers and verified by community consensus. Submit an incident notice to the hosting provider and domain registrar.'
    });
  }

  return {
    compositeScore: composite,
    severity,
    badgeColor,
    summary,
    subscores: {
      threatHeuristics: threatScore,
      certificateTrust: certScore,
      webSecurityScore: webSecurityScore,
      webRiskScore: webRiskScore,
      collaborativeIntelRisk: intelScore
    },
    recommendations
  };
}

module.exports = {
  calculateCompositeScore
};
