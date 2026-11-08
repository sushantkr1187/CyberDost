/**
 * Collaborative Community Threat Intelligence & Analyst Consensus
 * Enables crowdsourced reporting, analyst verification, and consensus-driven IOC promotion.
 */

const db = require('../database/db.js');
const crypto = require('node:crypto');
const { parseDomainParts } = require('../engines/threat_analyzer.js');

/**
 * Submits a new threat report from a user or security researcher
 */
function submitThreatReport(reportData) {
  const { url, category, target_brand, reporter_name, reporter_role, evidence, notes } = reportData;

  if (!url || !category || !reporter_name) {
    throw new Error('Missing mandatory fields: url, category, and reporter_name are required.');
  }

  let domain = '';
  try {
    const formatted = url.startsWith('http://') || url.startsWith('https://') ? url : `https://${url}`;
    const parsed = new URL(formatted);
    domain = parsed.hostname.toLowerCase();
  } catch {
    domain = url.split('/')[0].toLowerCase();
  }

  const id = `rep-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  const now = new Date().toISOString();

  const insert = db.prepare(`
    INSERT INTO threat_reports (
      id, url, domain, category, target_brand, reporter_name, reporter_role,
      evidence, notes, status, upvotes, downvotes, confidence, created_at, updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', 1, 0, 75, ?, ?)
  `);

  insert.run(
    id,
    url,
    domain,
    category,
    target_brand || 'Unspecified Target',
    reporter_name,
    reporter_role || 'Community Contributor',
    evidence || '',
    notes || '',
    now,
    now
  );

  return {
    success: true,
    reportId: id,
    domain,
    message: 'Threat report submitted successfully and queued for analyst peer review.'
  };
}

/**
 * Casts an analyst vote on an existing threat report
 */
function castAnalystVote(reportId, voterId, voteType, comment = '') {
  if (!['UPVOTE', 'DOWNVOTE'].includes(voteType)) {
    throw new Error('Vote type must be either UPVOTE or DOWNVOTE');
  }

  const report = db.prepare('SELECT * FROM threat_reports WHERE id = ?').get(reportId);
  if (!report) {
    throw new Error(`Report not found with ID: ${reportId}`);
  }

  // Insert or update vote
  const voteId = crypto.randomUUID();
  const upsertVote = db.prepare(`
    INSERT INTO community_votes (id, report_id, voter_id, vote_type, comment)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(report_id, voter_id) DO UPDATE SET
      vote_type = excluded.vote_type,
      comment = excluded.comment,
      created_at = CURRENT_TIMESTAMP
  `);

  upsertVote.run(voteId, reportId, voterId, voteType, comment);

  // Recalculate upvotes and downvotes
  const counts = db.prepare(`
    SELECT
      SUM(CASE WHEN vote_type = 'UPVOTE' THEN 1 ELSE 0 END) as up,
      SUM(CASE WHEN vote_type = 'DOWNVOTE' THEN 1 ELSE 0 END) as down
    FROM community_votes
    WHERE report_id = ?
  `).get(reportId);

  const totalUp = (counts.up || 0) + 1; // +1 for submitter
  const totalDown = counts.down || 0;

  // Consensus Logic:
  // If upvotes >= 3 and upvotes > 2 * downvotes, mark as VERIFIED and promote to IOC table!
  let newStatus = report.status;
  let newConfidence = Math.min(60 + totalUp * 6 - totalDown * 15, 99);
  newConfidence = Math.max(newConfidence, 20);

  if (totalUp >= 3 && totalUp > totalDown * 2) {
    newStatus = 'VERIFIED';

    // Auto-promote to threat_iocs table
    const existingIoc = db.prepare('SELECT id FROM threat_iocs WHERE value = ?').get(report.domain);
    if (!existingIoc) {
      db.prepare(`
        INSERT INTO threat_iocs (id, ioc_type, value, threat_category, target_brand, severity, source, confidence, first_seen, last_seen)
        VALUES (?, 'DOMAIN', ?, ?, ?, 'CRITICAL', 'COMMUNITY_CONSENSUS', ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      `).run(
        crypto.randomUUID(),
        report.domain,
        report.category,
        report.target_brand,
        newConfidence
      );
    }
  } else if (totalDown >= 3 && totalDown > totalUp) {
    newStatus = 'FALSE_POSITIVE';
  }

  db.prepare(`
    UPDATE threat_reports
    SET upvotes = ?, downvotes = ?, status = ?, confidence = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(totalUp, totalDown, newStatus, newConfidence, reportId);

  return {
    success: true,
    reportId,
    newStatus,
    upvotes: totalUp,
    downvotes: totalDown,
    confidence: newConfidence
  };
}

/**
 * Retrieves all community reports with pagination and filter
 */
function getCommunityReports(filter = {}) {
  let query = 'SELECT * FROM threat_reports';
  const params = [];

  if (filter.status) {
    query += ' WHERE status = ?';
    params.push(filter.status);
  } else if (filter.domain) {
    query += ' WHERE domain LIKE ?';
    params.push(`%${filter.domain}%`);
  }

  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(filter.limit || 50, filter.offset || 0);

  return db.prepare(query).all(...params);
}

module.exports = {
  submitThreatReport,
  castAnalystVote,
  getCommunityReports
};
