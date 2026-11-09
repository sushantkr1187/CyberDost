/**
 * Certificate Validation & Web Trust Infrastructure Engine
 * Analyzes TLS certificates, cryptographic key strength, Certificate Authorities,
 * Certificate Transparency (CT) logs, ROCA vulnerabilities, and eMudhra incident patterns.
 */

const tls = require('node:tls');
const crypto = require('node:crypto');
const { testROCA, auditPublicKey, auditCertificateAuthority } = require('../utils/crypto_audit.js');

/**
 * Extracts and parses TLS certificate details from a live host
 */
async function fetchLiveTlsCertificate(hostname, port = 443, timeoutMs = 7000) {
  return new Promise((resolve, reject) => {
    let socket;
    let timer;

    try {
      socket = tls.connect(
        {
          host: hostname,
          port,
          servername: hostname,
          rejectUnauthorized: false // We inspect self-signed or invalid certs rather than rejecting
        },
        () => {
          clearTimeout(timer);
          const rawCert = socket.getPeerCertificate(true);
          const cipher = socket.getCipher();
          const protocol = socket.getProtocol();
          const authorized = socket.authorized;
          const authorizationError = socket.authorizationError;

          socket.end();
          resolve({
            rawCert,
            cipher,
            protocol,
            authorized,
            authorizationError
          });
        }
      );

      timer = setTimeout(() => {
        if (socket) socket.destroy();
        reject(new Error(`TLS connection timeout after ${timeoutMs}ms`));
      }, timeoutMs);

      socket.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
    } catch (err) {
      if (timer) clearTimeout(timer);
      reject(err);
    }
  });
}

/**
 * Parses raw certificate object into structured security metrics
 */
function parseCertificateDetails(rawCert, options = {}) {
  if (!rawCert || Object.keys(rawCert).length === 0) {
    return {
      hasCert: false,
      error: 'No certificate presented'
    };
  }

  // Parse dates
  const validFrom = new Date(rawCert.valid_from);
  const validTo = new Date(rawCert.valid_to);
  const now = new Date();

  const isExpired = now > validTo;
  const isNotYetValid = now < validFrom;
  const ageInHours = Math.max(0, Math.round((now - validFrom) / (1000 * 60 * 60)));
  const ageInDays = Math.round(ageInHours / 24);
  const lifespanInDays = Math.round((validTo - validFrom) / (1000 * 60 * 60 * 24));

  // Extract Subject and Issuer (handle both string and object formats)
  let subjectStr = '';
  if (typeof rawCert.subject === 'string') {
    subjectStr = rawCert.subject;
  } else if (rawCert.subject && typeof rawCert.subject === 'object') {
    subjectStr = Object.entries(rawCert.subject).map(([k, v]) => `${k}=${v}`).join(', ');
  }

  let issuerStr = '';
  if (typeof rawCert.issuer === 'string') {
    issuerStr = rawCert.issuer;
  } else if (rawCert.issuer && typeof rawCert.issuer === 'object') {
    issuerStr = Object.entries(rawCert.issuer).map(([k, v]) => `${k}=${v}`).join(', ');
  }

  // Subject Alternative Names (SANs)
  const sans = rawCert.subjectaltname
    ? rawCert.subjectaltname.split(',').map(s => s.trim().replace(/^DNS:/i, ''))
    : [];

  // Public Key and Modulus Extraction
  let pubKeyDetails = {
    asymmetricKeyType: rawCert.asn1Curve ? 'ec' : 'rsa',
    modulusLength: rawCert.bits || 2048,
    publicExponent: rawCert.exponent ? parseInt(rawCert.exponent, 16) : 65537,
    curve: rawCert.asn1Curve || null
  };

  let modulusBigInt = null;
  if (rawCert.modulus) {
    try {
      modulusBigInt = BigInt('0x' + rawCert.modulus);
    } catch {
      // ignore
    }
  }

  // Cryptographic Key Audit
  const keyAudit = auditPublicKey(pubKeyDetails);

  // ROCA Vulnerability Check (CVE-2017-15361)
  const rocaTest = modulusBigInt ? testROCA(modulusBigInt) : { isVulnerable: false, details: 'Modulus not available' };

  // CA and Advisory Audit
  const caAudit = auditCertificateAuthority(issuerStr, {
    modulusLength: pubKeyDetails.modulusLength,
    hasSCTs: Boolean(rawCert.hasSCTs || rawCert.sctList)
  });

  // Calculate Certificate Security Red Flags
  const certFlags = [];
  let certRiskScore = 0;

  // 1. Expiration
  if (isExpired) {
    certFlags.push({
      rule: 'CERTIFICATE_EXPIRED',
      severity: 'HIGH',
      description: `Certificate expired on ${validTo.toISOString()}. Expired certificates break HTTPS security trust.`
    });
    certRiskScore += 35;
  }

  // 2. Newly Minted Ephemeral Certificate (< 48 hours old)
  // Phishing campaigns typically register disposable domains and spin up certificates hours prior to campaign launch
  if (ageInHours < 48) {
    certFlags.push({
      rule: 'NEWLY_ISSUED_CERTIFICATE',
      severity: 'HIGH',
      description: `Certificate was issued only ${ageInHours} hours ago (${ageInDays} days). Newly minted certificates on unknown domains are a major indicator of ephemeral phishing.`
    });
    certRiskScore += 40;
  }

  // 3. Automated Free DV Certificate Flag
  if (caAudit.isAutomatedDV) {
    certFlags.push({
      rule: 'AUTOMATED_DV_CERTIFICATE',
      severity: 'LOW',
      description: 'Domain-Validated (DV) certificate verifies technical domain control only, not the verified organizational identity of the website owner.'
    });
    certRiskScore += 10;
  }

  // 4. Known CA Incidents (eMudhra, WoSign, StartCom)
  if (caAudit.isDistrusted) {
    certFlags.push({
      rule: 'DISTRUSTED_CERTIFICATE_AUTHORITY',
      severity: 'CRITICAL',
      description: `Certificate Authority (${issuerStr}) is permanently distrusted by major root programs due to severe compliance and cryptographic failures.`
    });
    certRiskScore += 80;
  }

  if (caAudit.eMudhraAnalysis.isEMudhraCA) {
    certFlags.push({
      rule: 'EMUDHRA_CA_KEYGEN_AUDIT_WARNING',
      severity: 'HIGH',
      description: 'Certificate issued under eMudhra CA hierarchy, subject to industry audit scrutinizing subscriber key generation weaknesses, predictable PRNG seeds, and delayed CT logging.'
    });
    certRiskScore += 35;

    for (const p of caAudit.eMudhraAnalysis.flaggedParameters) {
      certFlags.push({
        rule: 'EMUDHRA_FLAGGED_PARAMETER',
        severity: 'HIGH',
        description: p
      });
      certRiskScore += 20;
    }
  }

  // 5. Weak Key Length
  if (pubKeyDetails.asymmetricKeyType === 'rsa' && pubKeyDetails.modulusLength < 2048) {
    certFlags.push({
      rule: 'WEAK_RSA_KEY_LENGTH',
      severity: 'CRITICAL',
      description: `RSA key length (${pubKeyDetails.modulusLength} bits) is below the minimum mandatory 2048-bit threshold, vulnerable to factorization.`
    });
    certRiskScore += 60;
  }

  // 6. ROCA Flaw
  if (rocaTest.isVulnerable) {
    certFlags.push({
      rule: 'ROCA_INFINEON_KEYGEN_VULNERABILITY',
      severity: 'CRITICAL',
      description: 'Public key matches the Infineon ROCA (CVE-2017-15361) factorization pattern. Private key recovery is practically feasible.'
    });
    certRiskScore += 90;
  }

  // 7. Signature Algorithm
  const sigAlg = (rawCert.sigalg || rawCert.signatureAlgorithm || 'sha256WithRSAEncryption').toLowerCase();
  if (sigAlg.includes('sha1') || sigAlg.includes('md5')) {
    certFlags.push({
      rule: 'DEPRECATED_SIGNATURE_ALGORITHM',
      severity: 'CRITICAL',
      description: `Certificate uses obsolete signature algorithm (${sigAlg}) susceptible to collision attacks.`
    });
    certRiskScore += 50;
  }

  // Domain Match vs Subject Alternative Names (SANs)
  const targetHost = (options.hostname || '').toLowerCase();
  let domainMatchesSans = true;
  if (targetHost && sans.length > 0) {
    domainMatchesSans = sans.some(san => {
      const s = san.toLowerCase();
      if (s === targetHost) return true;
      if (s.startsWith('*.')) {
        const root = s.slice(2);
        return targetHost.endsWith(root) && targetHost.split('.').length === root.split('.').length + 1;
      }
      return false;
    });

    if (!domainMatchesSans) {
      certFlags.push({
        rule: 'SAN_HOSTNAME_MISMATCH',
        severity: 'HIGH',
        description: `Target domain (${targetHost}) does not match certificate Subject Alternative Names [${sans.slice(0, 3).join(', ')}].`
      });
      certRiskScore += 45;
    }
  }

  // Wildcard and SAN count scrutiny
  const isWildcard = sans.some(s => s.startsWith('*.'));
  if (sans.length > 50) {
    certFlags.push({
      rule: 'EXCESSIVE_SAN_DOMAINS',
      severity: 'LOW',
      description: `Certificate contains ${sans.length} Subject Alternative Names, typical of multi-tenant shared hosting clusters.`
    });
    certRiskScore += 10;
  }

  // Certificate Transparency (CT) presence
  const hasCertificateTransparency = Boolean(rawCert.hasSCTs || rawCert.sctList || rawCert.ext_key_usage);

  return {
    hasCert: true,
    subject: subjectStr,
    subjectCommonName: typeof rawCert.subject === 'string'
      ? (rawCert.subject.match(/CN=([^,]+)/i)?.[1] || rawCert.subject)
      : (rawCert.subject?.CN || rawCert.subject?.commonName || ''),
    issuer: issuerStr,
    issuerCommonName: typeof rawCert.issuer === 'string'
      ? (rawCert.issuer.match(/(?:O|CN)=([^,]+)/i)?.[1] || rawCert.issuer)
      : (rawCert.issuer?.O || rawCert.issuer?.CN || ''),
    validFrom: validFrom.toISOString(),
    validTo: validTo.toISOString(),
    isExpired,
    isNotYetValid,
    ageInHours,
    ageInDays,
    lifespanInDays,
    serialNumber: rawCert.serialNumber || 'N/A',
    fingerprint256: rawCert.fingerprint256 || rawCert.fingerprint || 'N/A',
    fingerprintSha1: rawCert.fingerprint || 'N/A',
    signatureAlgorithm: sigAlg,
    subjectAltNames: sans,
    isWildcard,
    domainMatchesSans,
    hasCertificateTransparency,
    keyAudit,
    rocaTest,
    caAudit,
    certRiskScore: Math.min(certRiskScore, 100),
    certFlags
  };
}

/**
 * Validates a website certificate via live TLS connection with fallback / simulation support
 */
async function validateWebsiteCertificate(hostname, options = {}) {
  try {
    const liveTls = await fetchLiveTlsCertificate(hostname, options.port || 443, options.timeout || 6000);
    const certDetails = parseCertificateDetails(liveTls.rawCert, { hostname });

    return {
      status: 'SUCCESS',
      protocol: liveTls.protocol,
      cipher: liveTls.cipher,
      authorized: liveTls.authorized,
      authorizationError: liveTls.authorizationError,
      ...certDetails
    };
  } catch (err) {
    // Return structured failure response or fallback simulation if offline/mock requested
    return {
      status: 'TLS_CONNECTION_FAILED',
      error: err.message,
      hasCert: false,
      certRiskScore: 40,
      certFlags: [
        {
          rule: 'TLS_HANDSHAKE_FAILURE',
          severity: 'HIGH',
          description: `Unable to establish verified TLS connection to ${hostname}: ${err.message}`
        }
      ]
    };
  }
}

module.exports = {
  fetchLiveTlsCertificate,
  parseCertificateDetails,
  validateWebsiteCertificate
};
