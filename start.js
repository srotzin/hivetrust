/**
 * HiveTrust — Startup Script
 * Auto-seeds database on first run, then starts the server.
 * Compatible with HiveAgent's startup pattern.
 */

import { existsSync } from 'fs';
import { mkdir } from 'fs/promises';

const DB_PATH = './data/hivetrust.db';

async function boot() {
  // Ensure data directory exists
  if (!existsSync('./data')) {
    await mkdir('./data', { recursive: true });
    console.log('[HiveTrust] Created data/ directory');
  }

  const firstRun = !existsSync(DB_PATH);

  // Import server (initializes DB on import)
  const { default: app } = await import('./src/server.js');

  if (firstRun) {
    console.log('[HiveTrust] First run detected — seeding database...');
    const { seedDatabase } = await import('./src/seed.js');
    await seedDatabase();
    console.log('[HiveTrust] Database seeded successfully');
  }

  const PORT = process.env.PORT || 3001;
  app.listen(PORT, () => {
    console.log(`[HiveTrust] KYA Identity & Trust API running on port ${PORT}`);
    console.log(`[HiveTrust] MCP endpoint: POST /mcp`);
    console.log(`[HiveTrust] API endpoint: /v1/`);
    console.log(`[HiveTrust] Health check: GET /health`);
  });
}

boot().catch(err => {
  console.error('[HiveTrust] Fatal startup error:', err);
  process.exit(1);
});
