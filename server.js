/**
 * CyberDost — Intelligent Phishing Detection & Web Trust Infrastructure Platform
 * High-performance HTTP/REST API and SOC Dashboard Server.
 */

const http = require('node:http');
const { handleRequest } = require('./src/app.js');
const { seedDatabase } = require('./src/database/seed.js');

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '127.0.0.1';

// Initialize and ensure database is populated
seedDatabase();

const server = http.createServer(handleRequest);

server.listen(PORT, HOST, () => {
  console.log('================================================================');
  console.log('    CYBERDOST: Next-Gen Web Threat, PKI & Phishing Platform     ');
  console.log('================================================================');
  console.log(`[Server] Live at:   http://${HOST}:${PORT}`);
  console.log(`[API]    Endpoints: http://${HOST}:${PORT}/api/`);
  console.log(`[STIX]   STIX 2.1:  http://${HOST}:${PORT}/api/iocs/export/stix`);
  console.log(`[Audit]  eMudhra & CA Incident Audit Module active.`);
  console.log('================================================================');
});

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\n[Server] Shutting down gracefully...');
  server.close(() => {
    console.log('[Server] Terminated.');
    process.exit(0);
  });
});
