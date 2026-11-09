/**
 * REST API & HTTP Route Integration Tests
 * Uses in-memory request/response mocking to test the complete application HTTP router
 * and REST endpoints without requiring external network socket permissions.
 */

const assert = require('node:assert');
const { EventEmitter } = require('node:events');
const { handleRequest } = require('../src/app.js');
const { seedDatabase } = require('../src/database/seed.js');

function simulateHttpRequest(method, urlPath, body = null) {
  return new Promise((resolve, reject) => {
    const req = new EventEmitter();
    req.method = method;
    req.url = urlPath;
    req.headers = { host: 'localhost:3000' };

    const res = {
      statusCode: 200,
      headers: {},
      body: '',
      writeHead(code, headers = {}) {
        this.statusCode = code;
        this.headers = { ...this.headers, ...headers };
      },
      end(chunk) {
        if (chunk) this.body += chunk.toString();
        resolve({
          status: this.statusCode,
          headers: this.headers,
          text: () => Promise.resolve(this.body),
          json: () => Promise.resolve(JSON.parse(this.body))
        });
      }
    };

    // Execute route handler
    handleRequest(req, res).catch(reject);

    // Stream body if present
    process.nextTick(() => {
      if (body) {
        const bodyStr = typeof body === 'string' ? body : JSON.stringify(body);
        req.emit('data', Buffer.from(bodyStr));
      }
      req.emit('end');
    });
  });
}

async function runApiTests() {
  console.log('\n======================================================');
  console.log('   RUNNING CYBERDOST REST API & ROUTER TESTS          ');
  console.log('======================================================\n');

  seedDatabase();

  let passed = 0;
  let failed = 0;

  async function testRoute(name, fn) {
    try {
      await fn();
      console.log(`  [PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`  [FAIL] ${name}: ${err.message}`);
      failed++;
    }
  }

  // 1. Static HTML Root
  await testRoute('GET / returns HTML dashboard', async () => {
    const res = await simulateHttpRequest('GET', '/');
    assert.strictEqual(res.status, 200);
    const text = await res.text();
    assert.ok(text.includes('CyberDost'), 'HTML should contain CyberDost');
    assert.ok(text.includes('Live URL Scanner'), 'HTML should contain Live URL Scanner');
  });

  // 2. Static CSS
  await testRoute('GET /css/styles.css returns CSS styles', async () => {
    const res = await simulateHttpRequest('GET', '/css/styles.css');
    assert.strictEqual(res.status, 200);
    const text = await res.text();
    assert.ok(text.includes('--accent-cyan'), 'CSS should contain color variables');
  });

  // 3. Static JS
  await testRoute('GET /js/app.js returns client JS logic', async () => {
    const res = await simulateHttpRequest('GET', '/js/app.js');
    assert.strictEqual(res.status, 200);
    const text = await res.text();
    assert.ok(text.includes('renderScanResults'), 'JS should contain renderScanResults');
  });

  // 4. POST /api/scan (Chase Phishing)
  await testRoute('POST /api/scan inspects Chase phishing scenario', async () => {
    const res = await simulateHttpRequest('POST', '/api/scan', {
      url: 'https://chase-secure-login-portal.xyz/verify'
    });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.domain, 'chase-secure-login-portal.xyz');
    assert.strictEqual(data.composite.severity, 'CRITICAL_MALICIOUS');
    assert.ok(data.composite.compositeScore >= 90);
    assert.ok(data.threatAnalysis.redFlags.length >= 4);
  });

  // 5. POST /api/scan (eMudhra CA incident)
  await testRoute('POST /api/scan inspects eMudhra CA keygen flaw', async () => {
    const res = await simulateHttpRequest('POST', '/api/scan', {
      url: 'https://suspicious-emudhra-issued-portal.com'
    });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.domain, 'suspicious-emudhra-issued-portal.com');
    assert.strictEqual(data.certAnalysis.caAudit.eMudhraAnalysis.isEMudhraCA, true);
    assert.ok(data.certAnalysis.certRiskScore >= 80);
  });

  // 6. GET /api/iocs
  await testRoute('GET /api/iocs returns active IOC list', async () => {
    const res = await simulateHttpRequest('GET', '/api/iocs');
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.ok(Array.isArray(data.iocs), 'Should return iocs array');
    assert.ok(data.iocs.length >= 5, 'Should return at least 5 IOCs');
  });

  // 7. GET /api/iocs/export/stix
  await testRoute('GET /api/iocs/export/stix exports valid STIX 2.1 JSON bundle', async () => {
    const res = await simulateHttpRequest('GET', '/api/iocs/export/stix');
    assert.strictEqual(res.status, 200);
    const bundle = await res.json();
    assert.strictEqual(bundle.type, 'bundle');
    assert.strictEqual(bundle.spec_version, '2.1');
    assert.ok(bundle.objects.some(o => o.type === 'indicator'));
  });

  // 8. POST /api/reports & POST /api/reports/:id/vote
  await testRoute('POST /api/reports & POST /api/reports/:id/vote workflow', async () => {
    const reportRes = await simulateHttpRequest('POST', '/api/reports', {
      url: 'https://fake-recruitment-test-job.com/apply',
      category: 'Fake Recruitment',
      target_brand: 'LinkedIn Jobs',
      reporter_name: 'Threat Hunter Max',
      reporter_role: 'Security Researcher',
      evidence: 'Requests $100 processing fee',
      notes: 'Circulating on job boards'
    });
    assert.strictEqual(reportRes.status, 201);
    const reportData = await reportRes.json();
    assert.strictEqual(reportData.success, true);
    assert.ok(reportData.reportId);

    // Vote on the report
    const voteRes = await simulateHttpRequest('POST', `/api/reports/${reportData.reportId}/vote`, {
      voter_id: 'analyst_99',
      vote_type: 'UPVOTE',
      comment: 'Verified fake fee demand'
    });
    assert.strictEqual(voteRes.status, 200);
    const voteData = await voteRes.json();
    assert.strictEqual(voteData.success, true);
    assert.strictEqual(voteData.upvotes, 2);
  });

  // 9. GET /api/stats
  await testRoute('GET /api/stats returns threat statistics', async () => {
    const res = await simulateHttpRequest('GET', '/api/stats');
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.ok(data.totalIocs > 0);
    assert.ok(data.totalReports > 0);
  });

  // 10. GET /api/advisories
  await testRoute('GET /api/advisories returns CA advisories including eMudhra', async () => {
    const res = await simulateHttpRequest('GET', '/api/advisories');
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.ok(data.advisories.some(a => a.id === 'emudhra-incident'));
  });

  // 11. GET /api/mock-targets
  await testRoute('GET /api/mock-targets returns preconfigured test scenarios', async () => {
    const res = await simulateHttpRequest('GET', '/api/mock-targets');
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.ok(data.mockTargets.length >= 5);
  });

  console.log('\n======================================================');
  console.log(` API TEST SUMMARY: ${passed} PASSED, ${failed} FAILED `);
  console.log('======================================================\n');

  if (failed > 0) process.exit(1);
}

if (require.main === module) {
  runApiTests().catch(err => {
    console.error('Fatal API test error:', err);
    process.exit(1);
  });
}

module.exports = { runApiTests };
