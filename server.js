/**
 * TrustMatrix Server Entry Point
 * Starts HTTP/REST API server and static SOC dashboard.
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
  console.log('   TRUSTMATRIX: Intelligent Threat, Web Security & PKI Platform ');
  console.log('================================================================');
  console.log(`[Server] Online at: http://${HOST}:${PORT}`);
  console.log(`[API]    REST Endpoints active at http://${HOST}:${PORT}/api/`);
  console.log(`[STIX]   STIX 2.1 Threat Feed at http://${HOST}:${PORT}/api/iocs/export/stix`);
  console.log(`[Audit]  eMudhra & CA Incident Audit Module initialized.`);
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
