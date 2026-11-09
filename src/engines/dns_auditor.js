/**
 * DNS & Domain Trust Infrastructure Auditor
 * Audits DNS A/AAAA resolution, MX records, SPF/DMARC anti-spoofing enforcement,
 * and CAA (Certification Authority Authorization) records.
 */

const dns = require('node:dns').promises;

/**
 * Resolves and audits DNS trust records for a domain
 */
async function auditDnsRecords(domain) {
  const result = {
    domain,
    hasA: false,
    ipv4Addresses: [],
    ipv6Addresses: [],
    hasMx: false,
    mxRecords: [],
    hasSpf: false,
    spfRecord: null,
    hasDmarc: false,
    dmarcRecord: null,
    dmarcPolicy: 'none',
    hasCaa: false,
    caaRecords: [],
    emailSpoofingProtection: 'NONE',
    caaProtection: 'NONE',
    dnsFlags: [],
    score: 0
  };

  // 1. Resolve A / IPv4
  try {
    const aRecords = await dns.resolve4(domain);
    result.hasA = aRecords.length > 0;
    result.ipv4Addresses = aRecords;
  } catch {
    // No A record
  }

  // 2. Resolve AAAA / IPv6
  try {
    const aaaaRecords = await dns.resolve6(domain);
    result.ipv6Addresses = aaaaRecords;
  } catch {
    // No AAAA record
  }

  // 3. Resolve MX
  try {
    const mx = await dns.resolveMx(domain);
    result.hasMx = mx.length > 0;
    result.mxRecords = mx;
  } catch {
    // No MX record
  }

  // 4. Resolve TXT (SPF)
  try {
    const txtRecords = await dns.resolveTxt(domain);
    const flatTxt = txtRecords.map(chunk => chunk.join('')).filter(Boolean);
    const spf = flatTxt.find(t => t.startsWith('v=spf1'));
    if (spf) {
      result.hasSpf = true;
      result.spfRecord = spf;
    }
  } catch {
    // No TXT
  }

  // 5. Resolve DMARC (_dmarc.domain)
  try {
    const dmarcRecords = await dns.resolveTxt(`_dmarc.${domain}`);
    const flatDmarc = dmarcRecords.map(chunk => chunk.join('')).filter(Boolean);
    const dmarc = flatDmarc.find(t => t.startsWith('v=DMARC1'));
    if (dmarc) {
      result.hasDmarc = true;
      result.dmarcRecord = dmarc;

      // Extract policy p=reject / quarantine / none
      const pMatch = dmarc.match(/p\s*=\s*(reject|quarantine|none)/i);
      result.dmarcPolicy = pMatch ? pMatch[1].toLowerCase() : 'none';
    }
  } catch {
    // No DMARC
  }

  // 6. Resolve CAA (Certification Authority Authorization)
  try {
    const caa = await dns.resolveCaa(domain);
    if (caa && caa.length > 0) {
      result.hasCaa = true;
      result.caaRecords = caa;
    }
  } catch {
    // No CAA
  }

  // Evaluate Email Spoofing Defense
  if (result.hasDmarc && (result.dmarcPolicy === 'reject' || result.dmarcPolicy === 'quarantine') && result.hasSpf) {
    result.emailSpoofingProtection = 'STRONG_ENFORCED';
  } else if (result.hasSpf || result.hasDmarc) {
    result.emailSpoofingProtection = 'PARTIAL_MONITORING';
    result.dnsFlags.push({
      rule: 'WEAK_EMAIL_PROTECTION',
      severity: 'MEDIUM',
      description: 'Domain lacks strict DMARC rejection policy (p=reject), making it susceptible to email sender spoofing.'
    });
  } else {
    result.emailSpoofingProtection = 'VULNERABLE_TO_SPOOFING';
    result.dnsFlags.push({
      rule: 'NO_EMAIL_SPOOFING_DEFENSE',
      severity: 'HIGH',
      description: 'Domain has no SPF or DMARC records. Threat actors can trivially forge emails pretending to come from this domain.'
    });
  }

  // Evaluate CAA Protection against Rogue CA Issuance
  if (result.hasCaa) {
    result.caaProtection = 'STRICT_CAA_ENFORCED';
  } else {
    result.caaProtection = 'UNPROTECTED_CAA';
    result.dnsFlags.push({
      rule: 'MISSING_CAA_RECORDS',
      severity: 'LOW',
      description: 'Domain has no CAA DNS records. Any public Certificate Authority can issue certificates without restriction.'
    });
  }

  // Calculate DNS security score (0 - 100)
  let dnsScore = 30; // base for domain resolving
  if (result.hasA) dnsScore += 20;
  if (result.hasSpf) dnsScore += 15;
  if (result.hasDmarc && result.dmarcPolicy !== 'none') dnsScore += 20;
  if (result.hasCaa) dnsScore += 15;

  result.score = Math.min(dnsScore, 100);
  return result;
}

module.exports = {
  auditDnsRecords
};
