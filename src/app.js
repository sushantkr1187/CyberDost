/**
 * Application Router, REST API & Static File Server
 * Zero external dependencies, pure Node.js standard library.
 */

const http = require('node:http');
const path = require('node:path');
const fs = require('node:fs');
const { URL } = require('node:url');

const { scanWebsite, getScanHistory, getScanById } = require('./engines/unified_scanner.js');
const { queryDomainIntel, exportSTIX21Bundle, getIntelStatistics } = require('./threat_intel/feed_manager.js');
const { submitThreatReport, castAnalystVote, getCommunityReports } = require('./threat_intel/community.js');
const { CA_ADVISORIES } = require('./utils/crypto_audit.js');
const { TARGET_BRANDS } = require('./utils/brands.js');
const { MOCK_TARGETS } = require('./sandbox/mock_targets.js');
const db = require('./database/db.js');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');

const MIME_TYPES = {
  '.html': 'text/html; charset=UTF-8',
  '.css': 'text/css; charset=UTF-8',
  '.js': 'application/javascript; charset=UTF-8',
  '.json': 'application/json; charset=UTF-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=UTF-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  });
  res.end(JSON.stringify(data, null, 2));
}

function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
      if (body.length > 10 * 1024 * 1024) {
        reject(new Error('Request payload too large'));
      }
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (err) {
        reject(new Error('Invalid JSON payload'));
      }
    });
    req.on('error', reject);
  });
}

function serveStaticFile(req, res, pathname) {
  let filePath = path.join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname);
  filePath = path.normalize(filePath);

  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      // Fallback to index.html for SPA-style routing
      const indexPath = path.join(PUBLIC_DIR, 'index.html');
      fs.readFile(indexPath, (readErr, content) => {
        if (readErr) {
          res.writeHead(404);
          return res.end('Not Found');
        }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=UTF-8' });
        res.end(content);
      });
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    fs.readFile(filePath, (readErr, content) => {
      if (readErr) {
        res.writeHead(500);
        return res.end('Internal Server Error');
      }
      res.writeHead(200, {
        'Content-Type': contentType,
        'Cache-Control': 'no-cache'
      });
      res.end(content);
    });
  });
}

/**
 * Main Request Handler
 */
async function handleRequest(req, res) {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;
  const method = req.method;

  // Handle CORS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
    return res.end();
  }

  try {
    // API Route: Scan Website
    if (pathname === '/api/scan' && method === 'POST') {
      const body = await parseJsonBody(req);
      if (!body.url) {
        return sendJson(res, 400, { error: 'Target URL is required' });
      }
      const scanResult = await scanWebsite(body.url, { forceLive: Boolean(body.forceLive) });
      return sendJson(res, 200, scanResult);
    }

    // API Route: Get Recent Scans
    if (pathname === '/api/scans' && method === 'GET') {
      const limit = parseInt(parsedUrl.searchParams.get('limit') || '20', 10);
      const history = getScanHistory(limit);
      return sendJson(res, 200, { scans: history });
    }

    // API Route: Get Specific Scan by ID
    if (pathname.startsWith('/api/scans/') && method === 'GET') {
      const scanId = pathname.replace('/api/scans/', '');
      const scan = getScanById(scanId);
      if (!scan) {
        return sendJson(res, 404, { error: 'Scan not found' });
      }
      return sendJson(res, 200, scan);
    }

    // API Route: Threat IOCs List & Search
    if (pathname === '/api/iocs' && method === 'GET') {
      const search = parsedUrl.searchParams.get('q') || '';
      const category = parsedUrl.searchParams.get('category') || '';

      let query = 'SELECT * FROM threat_iocs WHERE active = 1';
      const params = [];

      if (search) {
        query += ' AND (value LIKE ? OR target_brand LIKE ?)';
        params.push(`%${search}%`, `%${search}%`);
      }
      if (category) {
        query += ' AND threat_category = ?';
        params.push(category);
      }

      query += ' ORDER BY last_seen DESC LIMIT 100';
      const iocs = db.prepare(query).all(...params);
      return sendJson(res, 200, { iocs });
    }

    // API Route: STIX 2.1 IOC Bundle Export
    if (pathname === '/api/iocs/export/stix' && method === 'GET') {
      const stixBundle = exportSTIX21Bundle();
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Content-Disposition': 'attachment; filename="cyberdost-stix-bundle.json"'
      });
      return res.end(JSON.stringify(stixBundle, null, 2));
    }

    // API Route: Community Reports List
    if (pathname === '/api/reports' && method === 'GET') {
      const status = parsedUrl.searchParams.get('status') || '';
      const domain = parsedUrl.searchParams.get('domain') || '';
      const reports = getCommunityReports({ status, domain });
      return sendJson(res, 200, { reports });
    }

    // API Route: Submit Community Report
    if (pathname === '/api/reports' && method === 'POST') {
      const body = await parseJsonBody(req);
      const result = submitThreatReport(body);
      return sendJson(res, 201, result);
    }

    // API Route: Analyst Vote on Report
    if (pathname.match(/^\/api\/reports\/[^/]+\/vote$/) && method === 'POST') {
      const reportId = pathname.split('/')[3];
      const body = await parseJsonBody(req);
      const result = castAnalystVote(reportId, body.voter_id || 'anonymous_analyst', body.vote_type, body.comment);
      return sendJson(res, 200, result);
    }

    // API Route: Dashboard Statistics
    if (pathname === '/api/stats' && method === 'GET') {
      const stats = getIntelStatistics();
      return sendJson(res, 200, stats);
    }

    // API Route: Monitored Brands
    if (pathname === '/api/brands' && method === 'GET') {
      const monitored = db.prepare('SELECT * FROM monitored_brands WHERE active = 1').all();
      return sendJson(res, 200, {
        monitored,
        allTargetBrands: TARGET_BRANDS
      });
    }

    // API Route: CA Advisories & eMudhra Incident Knowledge Base
    if (pathname === '/api/advisories' && method === 'GET') {
      return sendJson(res, 200, {
        advisories: CA_ADVISORIES.map(a => ({
          id: a.id,
          title: a.title,
          severity: a.severity,
          details: a.details,
          recommendation: a.recommendation,
          cve: a.cve
        }))
      });
    }

    // API Route: Sandbox Mock Targets
    if (pathname === '/api/mock-targets' && method === 'GET') {
      const targets = Object.keys(MOCK_TARGETS).map(key => ({
        url: key,
        domain: MOCK_TARGETS[key].domain,
        title: MOCK_TARGETS[key].html.match(/<title>([^<]+)<\/title>/i)?.[1] || 'Scenario',
        hasCert: Boolean(MOCK_TARGETS[key].cert),
        issuer: MOCK_TARGETS[key].cert?.issuer || 'N/A'
      }));
      return sendJson(res, 200, { mockTargets: targets });
    }

    // Fallback: Serve Static Files
    serveStaticFile(req, res, pathname);
  } catch (err) {
    console.error(`[API Error] ${method} ${pathname}:`, err);
    sendJson(res, 500, { error: err.message || 'Internal Server Error' });
  }
}

module.exports = { handleRequest };
