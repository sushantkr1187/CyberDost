#!/usr/bin/env node
/**
 * CyberDost CLI Utility
 * Command line scanner for automated CI/CD and terminal threat triage.
 */

const { scanWebsite } = require('./src/engines/unified_scanner.js');
const { exportSTIX21Bundle, getIntelStatistics } = require('./src/threat_intel/feed_manager.js');
const { seedDatabase } = require('./src/database/seed.js');
const db = require('./src/database/db.js');

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === 'help' || command === '--help' || command === '-h') {
    printHelp();
    process.exit(0);
  }

  // Ensure DB ready
  seedDatabase();

  if (command === 'scan') {
    const url = args[1];
    if (!url) {
      console.error('Error: URL parameter required. Usage: cyberdost scan <url> [--live]');
      process.exit(1);
    }

    const forceLive = args.includes('--live');
    console.log(`\n[*] Initiating CyberDost inspection on: ${url}`);
    if (forceLive) console.log('[*] Flag --live detected: forcing live network sockets.');

    try {
      const result = await scanWebsite(url, { forceLive });

      console.log('\n======================================================');
      console.log(` SCAN RESULT: ${result.domain}`);
      console.log('======================================================');
      console.log(`Risk Score:       ${result.composite.compositeScore}/100 (${result.composite.severity})`);
      console.log(`Summary:          ${result.composite.summary}`);
      console.log('------------------------------------------------------');
      console.log(`Threat Heuristics Score: ${result.threatAnalysis.compositeThreatScore}/100`);
      console.log(`Certificate Risk Score:  ${result.certAnalysis.certRiskScore}/100`);
      console.log(`Web Security Grade:      ${result.securityPosture.grade} (${result.securityPosture.securityScore}/100)`);
      console.log(`Intel / IOC Matches:     ${result.threatIntelligence.isKnownMalicious ? 'MALICIOUS MATCH' : 'CLEAN'}`);
      console.log('------------------------------------------------------');

      if (result.threatAnalysis.redFlags.length > 0) {
        console.log('\n[!] Detected Red Flags:');
        for (const flag of result.threatAnalysis.redFlags) {
          console.log(`  - [${flag.severity}] ${flag.rule}: ${flag.description}`);
        }
      }

      if (result.certAnalysis.certFlags?.length > 0) {
        console.log('\n[!] Certificate & PKI Flags:');
        for (const flag of result.certAnalysis.certFlags) {
          console.log(`  - [${flag.severity}] ${flag.rule}: ${flag.description}`);
        }
      }

      if (result.certAnalysis.caAudit?.eMudhraAnalysis?.isEMudhraCA) {
        console.log('\n[!] eMudhra CA Incident Audit:');
        console.log(`  - Audit Status: ${result.certAnalysis.caAudit.eMudhraAnalysis.auditStatus}`);
        for (const p of result.certAnalysis.caAudit.eMudhraAnalysis.flaggedParameters) {
          console.log(`    * ${p}`);
        }
      }

      console.log('\n[+] Actionable Recommendations:');
      for (const rec of result.composite.recommendations) {
        console.log(`  [${rec.priority}] ${rec.title}: ${rec.action}`);
      }

      console.log('======================================================\n');
    } catch (err) {
      console.error(`\n[-] Scan failed: ${err.message}`);
      process.exit(1);
    }
  } else if (command === 'iocs') {
    const iocs = db.prepare('SELECT ioc_type, value, threat_category, target_brand, severity FROM threat_iocs WHERE active = 1 LIMIT 20').all();
    console.log('\nActive Threat Indicators of Compromise (IOCs):');
    console.table(iocs);
  } else if (command === 'stats') {
    const stats = getIntelStatistics();
    console.log('\nTrustMatrix Platform Statistics:');
    console.log(JSON.stringify(stats, null, 2));
  } else if (command === 'export-stix') {
    const bundle = exportSTIX21Bundle();
    console.log(JSON.stringify(bundle, null, 2));
  } else {
    console.error(`Unknown command: ${command}`);
    printHelp();
    process.exit(1);
  }
}

function printHelp() {
  console.log(`
CyberDost CLI - Next-Gen Threat, Security & PKI Analysis Engine

USAGE:
  cyberdost <command> [options]

COMMANDS:
  scan <url> [--live]    Execute full multi-dimensional security scan on URL
  iocs                   Display active threat indicators of compromise
  stats                  Show platform threat intelligence statistics
  export-stix            Export full threat intelligence database in STIX 2.1 JSON
  help                   Show this help message

EXAMPLES:
  cyberdost scan https://chase-secure-login-portal.xyz/verify
  cyberdost scan https://suspicious-emudhra-issued-portal.com
  cyberdost scan https://www.google.com --live
  cyberdost export-stix > ioc-feed.json
  `);
}

if (require.main === module) {
  main();
}
