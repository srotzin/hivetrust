/**
 * HiveTrust — Startup Script
 * Initializes PostgreSQL schema, seeds on first run, then starts the server.
 * Compatible with HiveAgent's startup pattern.
 */

import { initDatabase } from './src/db.js';

async function boot() {
  // Initialize PostgreSQL schema (creates tables if not exist)
  await initDatabase();

  // Import server (after DB is ready)
  const { default: app } = await import('./src/server.js');

  // Seed service accounts for JWT cross-platform auth
  const { seedServiceAccounts } = await import('./src/services/jwt-auth.js');
  await seedServiceAccounts();

  // Start the reputation decay engine (24h interval)
  const { startDecayEngine } = await import('./src/services/reputation-engine.js');
  startDecayEngine();

  const { sendAlert } = await import('./src/services/alerts.js');

  const PORT = process.env.PORT || 3001;
  app.listen(PORT, () => {
    console.log(`[HiveTrust] KYA Identity & Trust API running on port ${PORT}`);
    console.log(`[HiveTrust] MCP endpoint: POST /mcp`);
    console.log(`[HiveTrust] API endpoint: /v1/`);
    console.log(`[HiveTrust] Health check: GET /health`);
    sendAlert('info', 'HiveTrust', `Service started on port ${PORT}`, {
      version: '2.0.0',
      env: process.env.NODE_ENV || 'development',
    });
  });
}

boot().catch(err => {
  console.error('[HiveTrust] Fatal startup error:', err);
  process.exit(1);
});
