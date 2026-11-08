/**
 * Persistent SQLite Database Layer using Node.js built-in node:sqlite
 * Zero external dependencies, fast, ACID-compliant storage for IOCs,
 * scans, community reports, and CA advisories.
 */

const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const fs = require('node:fs');

// Ensure data directory exists
const DATA_DIR = path.join(__dirname, '..', '..', 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PATH = path.join(DATA_DIR, 'trustmatrix.db');
const db = new DatabaseSync(DB_PATH);

// Enable WAL mode and foreign keys for high performance
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;

  -- 1. Scan Results Table
  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    domain TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    severity TEXT NOT NULL,
    threat_analysis TEXT NOT NULL,
    cert_analysis TEXT NOT NULL,
    security_analysis TEXT NOT NULL,
    dns_analysis TEXT NOT NULL,
    collaborative_intel TEXT NOT NULL,
    summary TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
  CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);

  -- 2. Collaborative Threat Reports Table
  CREATE TABLE IF NOT EXISTS threat_reports (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    domain TEXT NOT NULL,
    category TEXT NOT NULL,
    target_brand TEXT,
    reporter_name TEXT NOT NULL,
    reporter_role TEXT NOT NULL,
    evidence TEXT,
    notes TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING',
    upvotes INTEGER DEFAULT 1,
    downvotes INTEGER DEFAULT 0,
    confidence INTEGER DEFAULT 75,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_reports_domain ON threat_reports(domain);
  CREATE INDEX IF NOT EXISTS idx_reports_status ON threat_reports(status);

  -- 3. Community Analyst Votes Table
  CREATE TABLE IF NOT EXISTS community_votes (
    id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL,
    voter_id TEXT NOT NULL,
    vote_type TEXT NOT NULL, -- 'UPVOTE' (confirm) or 'DOWNVOTE' (dispute)
    comment TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(report_id) REFERENCES threat_reports(id) ON DELETE CASCADE,
    UNIQUE(report_id, voter_id)
  );

  -- 4. Shared Indicators of Compromise (IOC) Database
  CREATE TABLE IF NOT EXISTS threat_iocs (
    id TEXT PRIMARY KEY,
    ioc_type TEXT NOT NULL, -- 'DOMAIN', 'URL', 'IP', 'CERT_SHA256'
    value TEXT NOT NULL UNIQUE,
    threat_category TEXT NOT NULL,
    target_brand TEXT,
    severity TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence INTEGER DEFAULT 80,
    active INTEGER DEFAULT 1,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_iocs_type_val ON threat_iocs(ioc_type, value);
  CREATE INDEX IF NOT EXISTS idx_iocs_category ON threat_iocs(threat_category);

  -- 5. Monitored Brand Domains
  CREATE TABLE IF NOT EXISTS monitored_brands (
    id TEXT PRIMARY KEY,
    brand_name TEXT NOT NULL,
    official_domain TEXT NOT NULL UNIQUE,
    category TEXT NOT NULL,
    alert_email TEXT,
    active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

module.exports = db;
