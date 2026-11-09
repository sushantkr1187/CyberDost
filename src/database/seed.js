/**
 * Seed Database with realistic Threat IOCs, Community Reports,
 * Monitored Brands, and Historical Security Scans.
 */

const db = require('./db.js');
const crypto = require('node:crypto');

function uuid() {
  return crypto.randomUUID();
}

function seedDatabase() {
  console.log('[Seed] Seeding CyberDost security database...');

  // 1. Seed Monitored Brands
  const insertBrand = db.prepare(`
    INSERT OR IGNORE INTO monitored_brands (id, brand_name, official_domain, category, alert_email)
    VALUES (?, ?, ?, ?, ?)
  `);

  const initialBrands = [
    [uuid(), 'JPMorgan Chase', 'chase.com', 'Banking', 'soc@chase.com'],
    [uuid(), 'State Bank of India', 'onlinesbi.sbi', 'Banking', 'cybercell@sbi.co.in'],
    [uuid(), 'PayPal', 'paypal.com', 'Fintech', 'security@paypal.com'],
    [uuid(), 'Microsoft 365', 'microsoft.com', 'Technology', 'cert@microsoft.com'],
    [uuid(), 'Google Workspace', 'google.com', 'Technology', 'security@google.com'],
    [uuid(), 'Indian Railways IRCTC', 'irctc.co.in', 'Government', 'ciso@irctc.co.in'],
    [uuid(), 'Workday Enterprise', 'workday.com', 'Recruitment', 'secops@workday.com'],
    [uuid(), 'Binance Exchange', 'binance.com', 'Crypto', 'security@binance.com']
  ];

  for (const b of initialBrands) {
    insertBrand.run(...b);
  }

  // 2. Seed Threat Indicators of Compromise (IOCs)
  const insertIOC = db.prepare(`
    INSERT OR IGNORE INTO threat_iocs (id, ioc_type, value, threat_category, target_brand, severity, source, confidence, first_seen, last_seen)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const now = new Date().toISOString();
  const yesterday = new Date(Date.now() - 86400000).toISOString();
  const twoDaysAgo = new Date(Date.now() - 172800000).toISOString();

  const initialIOCs = [
    [
      uuid(),
      'DOMAIN',
      'chase-secure-login-portal.xyz',
      'Credential Harvesting Phishing',
      'JPMorgan Chase',
      'CRITICAL',
      'COMMUNITY_VALIDATED',
      95,
      twoDaysAgo,
      now
    ],
    [
      uuid(),
      'DOMAIN',
      'onlinesbi-kyc-pan-update.top',
      'Banking Trojan & Aadhaar KYC Phishing',
      'State Bank of India',
      'CRITICAL',
      'THREAT_FEED_SYNC',
      98,
      yesterday,
      now
    ],
    [
      uuid(),
      'DOMAIN',
      'paypal-account-verification-auth.click',
      'Payment Gateway Phishing',
      'PayPal',
      'HIGH',
      'OPENPHISH_SYNC',
      92,
      twoDaysAgo,
      now
    ],
    [
      uuid(),
      'DOMAIN',
      'login.micros0ft-support-portal.rest',
      'Typosquatting & Office 365 Token Theft',
      'Microsoft 365',
      'CRITICAL',
      'COMMUNITY_SUBMISSION',
      90,
      yesterday,
      now
    ],
    [
      uuid(),
      'DOMAIN',
      'workday-remote-career-portal.info',
      'Fake Recruitment & Identity Harvesting',
      'Workday Portal',
      'HIGH',
      'COMMUNITY_SUBMISSION',
      88,
      twoDaysAgo,
      now
    ],
    [
      uuid(),
      'DOMAIN',
      'irctc-ticket-refund-claim.sbs',
      'Government Impersonation & OTP Fraud',
      'Indian Railways (IRCTC)',
      'CRITICAL',
      'CERT_IN_ADVISORY',
      96,
      yesterday,
      now
    ],
    [
      uuid(),
      'CERT_SHA256',
      '8a514fae89bb900dc2b6c234a9b6c41b802e3b2e519965a0b7713f0cae2586b4',
      'Flawed CA Keygen / eMudhra Sub-CA Rogue Cert',
      'Generic Financial Impersonation',
      'CRITICAL',
      'CA_MONITORING_CT',
      94,
      yesterday,
      now
    ],
    [
      uuid(),
      'IP',
      '194.38.20.14',
      'Phishing Kit Hosting / Fast Flux Bulletproof Server',
      'Multiple Targets',
      'HIGH',
      'URLHAUS_SYNC',
      89,
      twoDaysAgo,
      now
    ]
  ];

  for (const ioc of initialIOCs) {
    insertIOC.run(...ioc);
  }

  // 3. Seed Collaborative Community Threat Reports
  const insertReport = db.prepare(`
    INSERT OR IGNORE INTO threat_reports (id, url, domain, category, target_brand, reporter_name, reporter_role, evidence, notes, status, upvotes, downvotes, confidence, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const initialReports = [
    [
      'rep-001',
      'https://onlinesbi-kyc-pan-update.top/login.html',
      'onlinesbi-kyc-pan-update.top',
      'Phishing & KYC Fraud',
      'State Bank of India',
      'Arun Sharma',
      'Senior SOC Analyst @ CyberDefense Labs',
      'Harvests SBI NetBanking Username, Profile Password, and sends OTP to unauthorized Telegram bot webhook.',
      'Circulated via fraudulent WhatsApp SMS claiming PAN card deactivation within 12 hours.',
      'VERIFIED',
      14,
      0,
      98,
      twoDaysAgo
    ],
    [
      'rep-002',
      'https://chase-secure-login-portal.xyz/auth/verify',
      'chase-secure-login-portal.xyz',
      'Credential Harvesting',
      'JPMorgan Chase',
      'Sarah Jenkins',
      'Incident Response Specialist',
      'Cloned Chase sign-in page with fake reCAPTCHA. Submits credit card number and debit PIN.',
      'Hosted behind Cloudflare with brand new Let\'s Encrypt certificate issued 4 hours before phishing campaign launched.',
      'VERIFIED',
      19,
      1,
      95,
      yesterday
    ],
    [
      'rep-003',
      'https://workday-remote-career-portal.info/apply',
      'workday-remote-career-portal.info',
      'Fake Recruitment Portal',
      'Workday Portal',
      'David Miller',
      'Threat Researcher',
      'Asks applicants to pay $45 "equipment verification fee" and upload driver license and SSN.',
      'Lure sent through fake LinkedIn recruiter profiles targeting newly graduated software engineers.',
      'VERIFIED',
      8,
      0,
      90,
      twoDaysAgo
    ],
    [
      'rep-004',
      'https://suspicious-emudhra-issued-portal.com',
      'suspicious-emudhra-issued-portal.com',
      'Certificate Trust & CA Key Flaw',
      'Banking Gateway',
      'Priya Nair',
      'PKI Cryptographic Auditor',
      'Identified TLS certificate issued under vulnerable eMudhra CA profile with weak prime generation and delayed CT logging.',
      'High risk of impersonation due to potential private key recoverability.',
      'VERIFIED',
      12,
      0,
      94,
      yesterday
    ]
  ];

  for (const r of initialReports) {
    insertReport.run(...r);
  }

  // 4. Seed Community Analyst Votes
  const insertVote = db.prepare(`
    INSERT OR IGNORE INTO community_votes (id, report_id, voter_id, vote_type, comment, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  const initialVotes = [
    [uuid(), 'rep-001', 'analyst_vikram', 'UPVOTE', 'Confirmed credential harvesting form dumping to Telegram API.', yesterday],
    [uuid(), 'rep-001', 'analyst_elena', 'UPVOTE', 'Matches signature of known "SmishSMS" banking fraud campaign.', yesterday],
    [uuid(), 'rep-002', 'analyst_marcus', 'UPVOTE', 'Full DOM replica of chase.com detected with fake login endpoints.', yesterday],
    [uuid(), 'rep-004', 'analyst_priya', 'UPVOTE', 'Cryptographic modulus audit confirms weak entropy seed characteristics.', yesterday]
  ];

  for (const v of initialVotes) {
    insertVote.run(...v);
  }

  console.log('[Seed] Database populated successfully.');
}

if (require.main === module) {
  seedDatabase();
}

module.exports = { seedDatabase };
