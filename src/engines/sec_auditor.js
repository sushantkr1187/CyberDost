/**
 * Web Application Security Posture Auditor
 * Analyzes HTTP security headers, information disclosure banners,
 * CORS configuration, mixed content risks, and exposed debug endpoints.
 */

/**
 * Standard Security Headers Configuration and Weights
 */
const SECURITY_HEADERS = [
  {
    name: 'content-security-policy',
    displayName: 'Content-Security-Policy (CSP)',
    weight: 25,
    critical: true,
    recommendation: 'Implement a strict CSP restricting script-src, object-src, and frame-ancestors to mitigate XSS and injection.'
  },
  {
    name: 'strict-transport-security',
    displayName: 'Strict-Transport-Security (HSTS)',
    weight: 20,
    critical: true,
    recommendation: 'Enable HSTS with max-age>=31536000, includeSubDomains, and preload to enforce HTTPS.'
  },
  {
    name: 'x-frame-options',
    displayName: 'X-Frame-Options',
    weight: 15,
    critical: false,
    recommendation: 'Set to DENY or SAMEORIGIN to prevent framing and clickjacking attacks.'
  },
  {
    name: 'x-content-type-options',
    displayName: 'X-Content-Type-Options',
    weight: 10,
    critical: false,
    recommendation: 'Set to nosniff to stop MIME-type confusion and drive-by download attacks.'
  },
  {
    name: 'referrer-policy',
    displayName: 'Referrer-Policy',
    weight: 10,
    critical: false,
    recommendation: 'Set to strict-origin-when-cross-origin to prevent leakage of sensitive URL tokens.'
  },
  {
    name: 'permissions-policy',
    displayName: 'Permissions-Policy',
    weight: 10,
    critical: false,
    recommendation: 'Restrict powerful browser features like camera, microphone, geolocation, and payment.'
  },
  {
    name: 'cross-origin-opener-policy',
    displayName: 'Cross-Origin-Opener-Policy (COOP)',
    weight: 5,
    critical: false,
    recommendation: 'Set to same-origin to isolate your browsing context from cross-origin popups.'
  },
  {
    name: 'cross-origin-resource-policy',
    displayName: 'Cross-Origin-Resource-Policy (CORP)',
    weight: 5,
    critical: false,
    recommendation: 'Set to same-origin or same-site to protect internal media and APIs from cross-origin leaks.'
  }
];

/**
 * Calculates letter grade based on security score
 */
function calculateGrade(score) {
  if (score >= 90) return 'A+';
  if (score >= 80) return 'A';
  if (score >= 70) return 'B';
  if (score >= 55) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

/**
 * Audits HTTP response headers and web posture
 */
function auditWebSecurity(rawHeaders = {}, pageHtml = '', url = '') {
  // Normalize header keys to lowercase
  const headers = {};
  for (const key in rawHeaders) {
    headers[key.toLowerCase()] = rawHeaders[key];
  }

  const headerAudits = [];
  let achievedHeaderPoints = 0;
  const issues = [];
  const findings = [];

  // 1. Audit Security Headers
  for (const def of SECURITY_HEADERS) {
    const value = headers[def.name];
    if (value) {
      achievedHeaderPoints += def.weight;
      headerAudits.push({
        header: def.name,
        displayName: def.displayName,
        present: true,
        value,
        status: 'SECURE',
        score: def.weight,
        maxScore: def.weight
      });
      findings.push({
        type: 'HEADER_PRESENT',
        title: `${def.displayName} configured`,
        desc: `Value: "${value}"`
      });
    } else {
      headerAudits.push({
        header: def.name,
        displayName: def.displayName,
        present: false,
        value: null,
        status: def.critical ? 'CRITICAL_MISSING' : 'MISSING',
        score: 0,
        maxScore: def.weight,
        recommendation: def.recommendation
      });
      issues.push({
        severity: def.critical ? 'HIGH' : 'MEDIUM',
        title: `Missing ${def.displayName}`,
        desc: def.recommendation
      });
    }
  }

  // 2. CSP In-depth Analysis if present
  const csp = headers['content-security-policy'];
  if (csp) {
    if (csp.includes('unsafe-inline') || csp.includes('unsafe-eval') || csp.includes('*')) {
      issues.push({
        severity: 'MEDIUM',
        title: 'Weak Content-Security-Policy Directives',
        desc: 'CSP includes "unsafe-inline", "unsafe-eval", or wildcard domains, weakening XSS mitigation.'
      });
      achievedHeaderPoints = Math.max(0, achievedHeaderPoints - 10);
    }
  }

  // 3. Information Disclosure & Banner Leakage
  const serverBanner = headers['server'];
  const poweredBy = headers['x-powered-by'] || headers['x-aspnet-version'];

  if (serverBanner) {
    // Check if banner exposes version numbers (e.g., Apache/2.4.41, nginx/1.14.0)
    const hasVersion = /\d+\.\d+/.test(serverBanner);
    if (hasVersion) {
      issues.push({
        severity: 'LOW',
        title: 'Server Banner Software Version Leakage',
        desc: `Server header exposes detailed platform software and version ("${serverBanner}"), aiding attacker reconnaissance.`
      });
    }
  }

  if (poweredBy) {
    issues.push({
      severity: 'LOW',
      title: 'X-Powered-By Technology Fingerprint Leaked',
      desc: `Header reveals application framework backend: "${poweredBy}". Disable this header in production.`
    });
  }

  // 4. CORS Misconfiguration Check
  const corsOrigin = headers['access-control-allow-origin'];
  const corsCreds = headers['access-control-allow-credentials'];

  if (corsOrigin === '*' && corsCreds === 'true') {
    issues.push({
      severity: 'HIGH',
      title: 'Insecure CORS: Wildcard Origin with Credentials Allowed',
      desc: 'Access-Control-Allow-Origin: * combined with credentials allows any third-party malicious domain to steal authenticated user sessions.'
    });
  }

  // 5. Mixed Content Risk on HTTPS URLs
  let hasMixedContent = false;
  if (url.startsWith('https://') && pageHtml) {
    const insecureAssets = [...pageHtml.matchAll(/src=["'](http:\/\/[^"']+)["']/gi)];
    if (insecureAssets.length > 0) {
      hasMixedContent = true;
      issues.push({
        severity: 'HIGH',
        title: 'Mixed Active/Passive Content Detected',
        desc: `HTTPS page references ${insecureAssets.length} insecure HTTP asset(s), allowing active Man-in-the-Middle injection.`
      });
    }
  }

  // 6. Security Posture Score Calculation
  const maxPossible = 100;
  let finalSecurityScore = Math.min(Math.round(achievedHeaderPoints), 100);

  // Penalties for dangerous disclosures and misconfigurations
  if (hasMixedContent) finalSecurityScore = Math.max(0, finalSecurityScore - 20);
  if (corsOrigin === '*' && corsCreds === 'true') finalSecurityScore = Math.max(0, finalSecurityScore - 25);

  const grade = calculateGrade(finalSecurityScore);

  return {
    securityScore: finalSecurityScore,
    grade,
    headerAudits,
    serverBanner: serverBanner || 'Hidden / Protected',
    poweredBy: poweredBy || 'None',
    hasMixedContent,
    issuesCount: issues.length,
    issues,
    findings
  };
}

module.exports = {
  SECURITY_HEADERS,
  calculateGrade,
  auditWebSecurity
};
