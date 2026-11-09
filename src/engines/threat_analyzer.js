/**
 * Intelligent Threat Detection & Phishing Analysis Engine
 * Evaluates lexical properties, homoglyphs, typosquatting, brand impersonation,
 * and malicious page content / credential harvesting heuristics.
 */

const { URL } = require('node:url');
const { TARGET_BRANDS, SUSPICIOUS_URL_KEYWORDS, HIGH_RISK_TLDS } = require('../utils/brands.js');
const {
  analyzeHomoglyphs,
  damerauLevenshteinDistance,
  calculateShannonEntropy,
  toUnicodeDomain
} = require('../utils/homoglyphs.js');

/**
 * Parses and extracts apex domain and subdomains
 */
function parseDomainParts(hostname) {
  if (!hostname) return { apexDomain: '', subdomains: '', tld: '' };

  const parts = hostname.split('.');
  if (parts.length <= 1) {
    return { apexDomain: hostname, subdomains: '', tld: '' };
  }

  // Handle common two-part TLDs (e.g. .co.in, .gov.in, .co.uk, .com.au)
  const isTwoPartTld = parts.length > 2 &&
    ['co.in', 'gov.in', 'ac.in', 'co.uk', 'com.au', 'com.br', 'gov.us'].includes(
      parts.slice(-2).join('.').toLowerCase()
    );

  const tldParts = isTwoPartTld ? parts.slice(-2) : parts.slice(-1);
  const domainNamePart = isTwoPartTld ? parts[parts.length - 3] : parts[parts.length - 2];
  const subdomainParts = isTwoPartTld ? parts.slice(0, -3) : parts.slice(0, -2);

  const apexDomain = `${domainNamePart}.${tldParts.join('.')}`.toLowerCase();
  const subdomains = subdomainParts.join('.').toLowerCase();
  const tld = `.${tldParts.join('.')}`.toLowerCase();

  return { apexDomain, subdomains, tld, domainNamePart: domainNamePart.toLowerCase() };
}

/**
 * Checks if a hostname is an IP address
 */
function isIpAddress(hostname) {
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Pattern = /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$/;
  return ipv4Pattern.test(hostname) || ipv6Pattern.test(hostname);
}

/**
 * 1. Lexical and Domain Analysis
 */
function analyzeUrlLexical(rawUrl) {
  let urlObj;
  try {
    const formattedUrl = rawUrl.startsWith('http://') || rawUrl.startsWith('https://')
      ? rawUrl
      : `https://${rawUrl}`;
    urlObj = new URL(formattedUrl);
  } catch (err) {
    return {
      error: 'Invalid URL format',
      lexicalScore: 100,
      flags: ['Malformed URL structure']
    };
  }

  const hostname = urlObj.hostname.toLowerCase();
  const fullPath = (urlObj.pathname + urlObj.search + urlObj.hash).toLowerCase();
  const { apexDomain, subdomains, tld, domainNamePart } = parseDomainParts(hostname);

  const redFlags = [];
  let riskScore = 0; // 0 to 100

  // 1. IP Hostname check
  const isIp = isIpAddress(hostname);
  if (isIp) {
    redFlags.push({
      rule: 'IP_BASED_URL',
      severity: 'HIGH',
      description: 'URL uses raw IP address instead of registered domain name, often used to evade domain reputation filters.'
    });
    riskScore += 35;
  }

  // 2. High-Risk TLD check
  const isHighRiskTld = HIGH_RISK_TLDS.some(t => hostname.endsWith(t));
  if (isHighRiskTld) {
    redFlags.push({
      rule: 'HIGH_RISK_TLD',
      severity: 'MEDIUM',
      description: `Domain uses top-level domain (${tld}) frequently associated with disposable phishing campaigns.`
    });
    riskScore += 20;
  }

  // 3. Shannon Entropy Check (Algorithmic / DGA domains)
  const domainEntropy = calculateShannonEntropy(domainNamePart || hostname);
  if (domainEntropy > 3.75) {
    redFlags.push({
      rule: 'HIGH_DOMAIN_ENTROPY',
      severity: 'MEDIUM',
      description: `Domain name has unusually high character entropy (${domainEntropy}), indicating potential Domain Generation Algorithm (DGA) or disposable pattern.`
    });
    riskScore += 20;
  }

  // 4. Homoglyphs & Punycode Analysis
  const homoglyphAnalysis = analyzeHomoglyphs(hostname);
  if (homoglyphAnalysis.isPunycode || homoglyphAnalysis.hasMixedScripts) {
    redFlags.push({
      rule: 'IDN_HOMOGRAPH_ATTACK',
      severity: 'CRITICAL',
      description: `Internationalized Domain Name (IDN) homoglyph detected: ${homoglyphAnalysis.unicodeDomain} mimics Latin letters using lookalike Cyrillic or Greek characters.`
    });
    riskScore += 45;
  }

  // 5. Excessive Subdomain Nesting
  const subdomainCount = subdomains ? subdomains.split('.').length : 0;
  if (subdomainCount >= 3) {
    redFlags.push({
      rule: 'EXCESSIVE_SUBDOMAINS',
      severity: 'MEDIUM',
      description: `Domain contains ${subdomainCount} levels of subdomains (${subdomains}), a tactic often used to obscure apex domain.`
    });
    riskScore += 15;
  }

  // 6. Suspicious Phishing Keywords in URL
  const foundKeywords = [];
  for (const kw of SUSPICIOUS_URL_KEYWORDS) {
    if (hostname.includes(kw) || fullPath.includes(kw)) {
      foundKeywords.push(kw);
    }
  }

  if (foundKeywords.length > 0) {
    const weight = Math.min(foundKeywords.length * 8, 30);
    redFlags.push({
      rule: 'SUSPICIOUS_KEYWORDS',
      severity: foundKeywords.length >= 2 ? 'HIGH' : 'LOW',
      description: `URL contains deceptive security/authentication keywords: [${foundKeywords.slice(0, 5).join(', ')}]`
    });
    riskScore += weight;
  }

  // 7. Brand Impersonation & Typosquatting in Domain
  let matchedBrand = null;
  let typosquatTarget = null;

  for (const brand of TARGET_BRANDS) {
    // Check if official domain
    const isOfficial = brand.primaryDomains.some(d => d.toLowerCase() === apexDomain);

    if (isOfficial) {
      matchedBrand = { brand: brand.name, isOfficial: true };
      break;
    }

    // Check typosquatting distance first on apex domain name
    let isTypo = false;
    for (const officialDomain of brand.primaryDomains) {
      const offName = officialDomain.split('.')[0];
      const dist = damerauLevenshteinDistance(domainNamePart, offName);
      if (dist === 1 || (dist === 2 && domainNamePart.length > 6)) {
        redFlags.push({
          rule: 'TYPOSQUATTING_DETECTED',
          severity: 'CRITICAL',
          description: `Domain name "${domainNamePart}" has an edit distance of ${dist} from authentic brand domain "${officialDomain}" (${brand.name}).`
        });
        typosquatTarget = { brand: brand.name, targetDomain: officialDomain, distance: dist };
        riskScore += 50;
        isTypo = true;
        break;
      }
    }

    if (isTypo) break;

    // Check if brand name appears in subdomains or apex name (Subdomain Brand Stuffing / Keyword Stuffing)
    const brandInSubdomain = brand.keywords.some(k => subdomains.includes(k.replace(/\s+/g, '')));
    const brandInApex = brand.keywords.some(k => domainNamePart.includes(k.replace(/\s+/g, '')));

    if (brandInSubdomain || brandInApex) {
      redFlags.push({
        rule: 'BRAND_IMPERSONATION',
        severity: 'CRITICAL',
        description: `High-value brand "${brand.name}" is present in hostname (${hostname}), but the apex domain is NOT an authorized domain for ${brand.name}.`
      });
      matchedBrand = { brand: brand.name, isOfficial: false, lure: 'Subdomain or domain keyword stuffing' };
      riskScore += 50;
      break;
    }
  }

  return {
    url: rawUrl,
    normalizedUrl: urlObj.href,
    protocol: urlObj.protocol.replace(':', ''),
    hostname,
    apexDomain,
    subdomains,
    tld,
    isIp,
    domainEntropy,
    homoglyphAnalysis,
    foundKeywords,
    matchedBrand,
    typosquatTarget,
    redFlags,
    riskScore: Math.min(riskScore, 100)
  };
}

/**
 * 2. Page Content, Forms, and Behavioral Heuristics Analysis
 */
function analyzePageContent(htmlContent = '', pageMetadata = {}, urlAnalysis = {}) {
  const redFlags = [];
  let contentRiskScore = 0;

  if (!htmlContent || typeof htmlContent !== 'string') {
    return {
      analyzed: false,
      contentRiskScore: 0,
      flags: []
    };
  }

  const lowerHtml = htmlContent.toLowerCase();

  // 1. Password Field & Form Action Inspection
  const hasPasswordField = /<input[^>]+type=["']?password["']?/i.test(htmlContent);
  const formActionMatches = [...htmlContent.matchAll(/<form[^>]+action=["']([^"']+)["']/gi)];

  let hasExternalFormAction = false;
  let hasInsecureFormAction = false;
  let hasSuspiciousAction = false;

  for (const match of formActionMatches) {
    const actionUrl = match[1].trim();
    if (actionUrl.startsWith('http://')) {
      hasInsecureFormAction = true;
    }
    if (actionUrl.includes('telegram.org') || actionUrl.includes('discord.com/api/webhooks') || actionUrl.startsWith('mailto:')) {
      hasSuspiciousAction = true;
    }
    if (actionUrl.startsWith('http://') || actionUrl.startsWith('https://')) {
      try {
        const parsedAction = new URL(actionUrl);
        if (urlAnalysis.apexDomain && !parsedAction.hostname.includes(urlAnalysis.apexDomain)) {
          hasExternalFormAction = true;
        }
      } catch {
        // invalid URL
      }
    }
  }

  if (hasPasswordField) {
    if (hasSuspiciousAction) {
      redFlags.push({
        rule: 'FORM_ACTION_EXFILTRATION',
        severity: 'CRITICAL',
        description: 'Login form submits credentials directly to unauthorized third-party exfiltration webhook (Telegram / Discord / Mailto).'
      });
      contentRiskScore += 60;
    } else if (hasExternalFormAction) {
      redFlags.push({
        rule: 'EXTERNAL_FORM_SUBMISSION',
        severity: 'HIGH',
        description: 'Login form action points to an external third-party domain that differs from current website host.'
      });
      contentRiskScore += 40;
    } else if (hasInsecureFormAction) {
      redFlags.push({
        rule: 'INSECURE_FORM_ACTION',
        severity: 'HIGH',
        description: 'Form transmits authentication credentials over unencrypted HTTP protocol.'
      });
      contentRiskScore += 35;
    }
  }

  // 2. Sensitive Financial & Identity Inputs (Credit Card, CVV, SSN, Aadhaar, PAN)
  const ccMatches = /name=["']?(cc|card_number|cardnumber|creditcard|cvv|cvc|exp_date)["']?/i.test(htmlContent);
  const idMatches = /name=["']?(ssn|aadhaar|pan_card|tax_id|identity_number)["']?/i.test(htmlContent);

  if (ccMatches || idMatches) {
    redFlags.push({
      rule: 'SENSITIVE_DATA_HARVESTING',
      severity: 'HIGH',
      description: 'Page contains sensitive financial payment (Card/CVV) or government identity (SSN/Aadhaar/PAN) input fields.'
    });
    contentRiskScore += 30;
  }

  // 3. Social Engineering & Urgency Prompts
  const urgencyKeywords = [
    'account suspended', 'unauthorized transaction', 'kyc expired', 'pan card locked',
    'deactivated within 24 hours', 'action required immediately', 'refund pending approval',
    'security alert: suspicious activity', 'verify identity now or lose access'
  ];

  const foundUrgency = urgencyKeywords.filter(phrase => lowerHtml.includes(phrase));
  if (foundUrgency.length > 0) {
    redFlags.push({
      rule: 'URGENCY_SOCIAL_ENGINEERING',
      severity: 'HIGH',
      description: `High-pressure psychological manipulation lures detected: "${foundUrgency[0]}"`
    });
    contentRiskScore += 25;
  }

  // 4. Evasion & Obfuscation Heuristics
  const disablesContextMenu = /oncontextmenu\s*=\s*["']?return\s+false["']?/i.test(htmlContent) ||
    /addEventListener\(["']contextmenu["']\s*,\s*e\s*=>\s*e\.preventDefault\(\)\)/i.test(htmlContent);

  const hasDebuggerTrap = /debugger;/i.test(htmlContent) && /setInterval/i.test(htmlContent);
  const hasObfuscatedScript = /eval\(function\(p,a,c,k,e,d\)/i.test(htmlContent) || /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/i.test(htmlContent);

  if (disablesContextMenu) {
    redFlags.push({
      rule: 'ANTI_ANALYSIS_CONTEXT_MENU_DISABLED',
      severity: 'MEDIUM',
      description: 'Page script disables right-click context menu to hinder page inspection and threat analyst triage.'
    });
    contentRiskScore += 15;
  }

  if (hasDebuggerTrap) {
    redFlags.push({
      rule: 'ANTI_TAMPER_DEBUGGER_TRAP',
      severity: 'HIGH',
      description: 'Page includes active JavaScript debugger traps designed to freeze browser DevTools inspection.'
    });
    contentRiskScore += 25;
  }

  if (hasObfuscatedScript) {
    redFlags.push({
      rule: 'OBFUSCATED_JAVASCRIPT_PAYLOAD',
      severity: 'HIGH',
      description: 'Packed or hex-encoded JavaScript payload detected, commonly used in malicious exploit kits or phishing drop-scripts.'
    });
    contentRiskScore += 25;
  }

  // 5. Brand Title Mismatch
  if (pageMetadata.title) {
    const titleLower = pageMetadata.title.toLowerCase();
    for (const brand of TARGET_BRANDS) {
      const brandInTitle = brand.keywords.some(k => titleLower.includes(k));
      if (brandInTitle && urlAnalysis.apexDomain && !brand.primaryDomains.includes(urlAnalysis.apexDomain)) {
        redFlags.push({
          rule: 'TITLE_BRAND_MISMATCH',
          severity: 'CRITICAL',
          description: `Page title displays "${pageMetadata.title}" referencing brand "${brand.name}", but host is an unauthorized domain.`
        });
        contentRiskScore += 45;
        break;
      }
    }
  }

  return {
    analyzed: true,
    hasPasswordField,
    hasExternalFormAction,
    hasSuspiciousAction,
    foundUrgency,
    contentRiskScore: Math.min(contentRiskScore, 100),
    redFlags
  };
}

/**
 * Combined Threat Analysis Function
 */
function analyzeThreat(rawUrl, htmlContent = '', pageMetadata = {}) {
  const lexical = analyzeUrlLexical(rawUrl);
  const content = analyzePageContent(htmlContent, pageMetadata, lexical);

  // Combine scores with heuristic weights
  let combinedScore = Math.round(lexical.riskScore * 0.5 + content.contentRiskScore * 0.5);
  if (content.contentRiskScore >= 60) {
    combinedScore = Math.max(combinedScore, Math.round(content.contentRiskScore * 0.85));
  }
  combinedScore = Math.min(combinedScore, 100);

  const allRedFlags = [...(lexical.redFlags || []), ...(content.redFlags || [])];

  let threatCategory = 'BENIGN';
  if (combinedScore >= 70) {
    threatCategory = lexical.matchedBrand ? 'BRAND_IMPERSONATION_PHISHING' : 'MALICIOUS_SITE';
  } else if (combinedScore >= 40) {
    threatCategory = 'SUSPICIOUS_SITE';
  }

  return {
    url: rawUrl,
    compositeThreatScore: combinedScore,
    threatCategory,
    lexical,
    content,
    flagsCount: allRedFlags.length,
    redFlags: allRedFlags
  };
}

module.exports = {
  analyzeThreat,
  analyzeUrlLexical,
  analyzePageContent,
  parseDomainParts
};
