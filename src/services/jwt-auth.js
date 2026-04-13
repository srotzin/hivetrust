/**
 * HiveTrust — JWT Service Account Authentication
 * Issues and verifies JWTs for cross-platform service accounts.
 * Uses HMAC-SHA256 (HS256) signing with JWT_SIGNING_SECRET.
 */

import jwt from 'jsonwebtoken';
import { createHash, randomBytes } from 'crypto';
import db from '../db.js';

const JWT_SIGNING_SECRET = process.env.JWT_SIGNING_SECRET || '';
const TOKEN_EXPIRY = '1h';

/**
 * Hash a secret with SHA-256 for storage comparison.
 */
function hashSecret(secret) {
  return createHash('sha256').update(secret).digest('hex');
}

/**
 * Issue a JWT for a service account after validating its secret.
 * @param {string} platform - Platform name (e.g. 'hivemind')
 * @param {string} secret - The platform's secret
 * @returns {{ token: string, expires_at: string, scopes: string[] }}
 */
export function issueServiceToken(platform, secret) {
  if (!JWT_SIGNING_SECRET) {
    throw Object.assign(new Error('JWT signing not configured'), { status: 500 });
  }

  const account = db.prepare(
    `SELECT account_id, platform, scopes, status, secret_hash
     FROM service_accounts
     WHERE platform = ?
     LIMIT 1`
  ).get(platform);

  if (!account) {
    throw Object.assign(new Error('Unknown platform'), { status: 401 });
  }

  if (account.status !== 'active') {
    throw Object.assign(new Error('Service account is disabled'), { status: 403 });
  }

  const providedHash = hashSecret(secret);
  if (providedHash !== account.secret_hash) {
    throw Object.assign(new Error('Invalid secret'), { status: 401 });
  }

  // Parse scopes from JSON string
  let scopes;
  try { scopes = JSON.parse(account.scopes); } catch { scopes = []; }

  const payload = {
    iss: 'hivetrust',
    sub: `svc:${platform}`,
    scopes,
    platform,
  };

  const token = jwt.sign(payload, JWT_SIGNING_SECRET, {
    algorithm: 'HS256',
    expiresIn: TOKEN_EXPIRY,
  });

  // Decode to get exact expiry
  const decoded = jwt.decode(token);
  const expires_at = new Date(decoded.exp * 1000).toISOString();

  // Update last_used_at
  try {
    db.prepare(`UPDATE service_accounts SET last_used_at = datetime('now') WHERE platform = ?`)
      .run(platform);
  } catch { /* non-fatal */ }

  return { token, expires_at, scopes };
}

/**
 * Verify a JWT and return its payload.
 * @param {string} token - The JWT to verify
 * @returns {object} Decoded JWT payload
 */
export function verifyServiceToken(token) {
  if (!JWT_SIGNING_SECRET) {
    throw Object.assign(new Error('JWT signing not configured'), { status: 500 });
  }

  try {
    return jwt.verify(token, JWT_SIGNING_SECRET, { algorithms: ['HS256'] });
  } catch (err) {
    const message = err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token';
    throw Object.assign(new Error(message), { status: 401 });
  }
}

/**
 * Seed service accounts for all platforms on startup.
 * If a platform's env var secret is not set, generates a random one and logs it.
 */
export function seedServiceAccounts() {
  const PLATFORMS = {
    hivemind: {
      display_name: 'HiveMind',
      secret_env: 'HIVEMIND_SERVICE_SECRET',
      scopes: ['trust:verify-did', 'trust:read-score', 'trust:telemetry'],
    },
    hiveforge: {
      display_name: 'HiveForge',
      secret_env: 'HIVEFORGE_SERVICE_SECRET',
      scopes: ['trust:register-agent', 'trust:verify-did', 'trust:read-score', 'trust:telemetry'],
    },
    hivelaw: {
      display_name: 'HiveLaw',
      secret_env: 'HIVELAW_SERVICE_SECRET',
      scopes: ['trust:verify-did', 'trust:read-score', 'trust:update-reputation', 'trust:telemetry'],
    },
    hiveagent: {
      display_name: 'HiveAgent',
      secret_env: 'HIVEAGENT_SERVICE_SECRET',
      scopes: ['trust:verify-did', 'trust:read-score', 'trust:verify-subscription', 'trust:telemetry'],
    },
  };

  const insert = db.prepare(`
    INSERT OR IGNORE INTO service_accounts (account_id, platform, display_name, secret_hash, scopes, status)
    VALUES (?, ?, ?, ?, ?, 'active')
  `);

  for (const [platform, config] of Object.entries(PLATFORMS)) {
    // Check if already exists
    const existing = db.prepare('SELECT account_id FROM service_accounts WHERE platform = ?').get(platform);
    if (existing) continue;

    let secret = process.env[config.secret_env];
    if (!secret) {
      secret = randomBytes(32).toString('hex');
      console.log(`[HiveTrust] Generated service secret for ${platform}: ${secret}`);
      console.log(`[HiveTrust]   Set ${config.secret_env}=${secret} in your environment`);
    }

    const accountId = crypto.randomUUID();
    insert.run(
      accountId,
      platform,
      config.display_name,
      hashSecret(secret),
      JSON.stringify(config.scopes),
    );
    console.log(`[HiveTrust] Seeded service account: ${platform} (${accountId})`);
  }
}
