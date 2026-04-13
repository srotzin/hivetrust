/**
 * HiveTrust — API Key Authentication Middleware
 * Checks X-API-Key header or ?api_key= query param.
 * Hashes the key with SHA-256 and looks it up in the api_keys table.
 * Attaches key info to req.apiKey if valid.
 * Allows INTERNAL_API_TOKEN as a master bypass key.
 * Some endpoints are public and skip auth entirely.
 */

import { createHash } from 'crypto';
import db from '../db.js';
import { verifyServiceToken } from '../services/jwt-auth.js';

// Public paths — no auth required (exact match or startsWith)
// NOTE: When mounted on /v1, req.path is relative (e.g. /stats not /v1/stats)
const PUBLIC_PATHS = [
  '/health',
  '/.well-known/hivetrust.json',
];

// Public path prefixes — checked with and without /v1 prefix
const PUBLIC_PREFIXES = [
  '/v1/verify_agent_risk',
  '/v1/stats',
  '/v1/pricing',
  '/verify_agent_risk',
  '/stats',
  '/pricing',
];

function hashKey(rawKey) {
  return createHash('sha256').update(rawKey).digest('hex');
}

function isPublicPath(path) {
  if (PUBLIC_PATHS.includes(path)) return true;
  return PUBLIC_PREFIXES.some((prefix) => path.startsWith(prefix));
}

/**
 * Express middleware for API key authentication.
 */
export default function authMiddleware(req, res, next) {
  // Skip auth for public endpoints
  if (isPublicPath(req.path)) {
    return next();
  }

  // Check for JWT Bearer token (Authorization: Bearer <token>)
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    // Only treat as JWT if it doesn't look like a DID
    if (!token.startsWith('did:hive:')) {
      try {
        const payload = verifyServiceToken(token);
        req.serviceAccount = {
          platform: payload.platform,
          scopes: payload.scopes || [],
        };
        req.apiKey = {
          id: `svc:${payload.platform}`,
          owner_id: payload.platform,
          name: `Service Account: ${payload.platform}`,
          scopes: payload.scopes || [],
          rate_limit: 100000,
          status: 'active',
        };
        return next();
      } catch (err) {
        return res.status(err.status || 401).json({
          success: false,
          error: err.message || 'Invalid token',
        });
      }
    }
  }

  // Extract raw API key from header or query param
  // Also check X-Hive-Internal-Key (used by constellation platforms: HiveMind, HiveForge, HiveLaw)
  const rawKey =
    req.headers['x-api-key'] ||
    req.headers['x-hive-internal-key'] ||
    req.query?.api_key ||
    null;

  if (!rawKey) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required. Provide X-API-Key header or ?api_key= query param.',
    });
  }

  // Check master internal token first (fast path, no DB)
  const internalToken = process.env.INTERNAL_API_TOKEN;
  if (internalToken && rawKey === internalToken) {
    req.apiKey = {
      id: 'internal',
      owner_id: 'system',
      name: 'Internal Master Key',
      scopes: ['*'],
      rate_limit: 100000,
      status: 'active',
    };
    return next();
  }

  // Hash and look up in DB
  const keyHash = hashKey(rawKey);

  let apiKeyRecord;
  try {
    apiKeyRecord = db
      .prepare(
        `SELECT id, owner_id, name, scopes, rate_limit, status, expires_at
         FROM api_keys
         WHERE key_hash = ?
         LIMIT 1`
      )
      .get(keyHash);
  } catch (err) {
    console.error('[auth] DB error during key lookup:', err.message);
    return res.status(500).json({
      success: false,
      error: 'Internal server error during authentication.',
    });
  }

  if (!apiKeyRecord) {
    return res.status(401).json({
      success: false,
      error: 'Invalid API key.',
    });
  }

  if (apiKeyRecord.status !== 'active') {
    return res.status(401).json({
      success: false,
      error: `API key is ${apiKeyRecord.status}.`,
    });
  }

  // Check expiry
  if (apiKeyRecord.expires_at) {
    const expiresAt = new Date(apiKeyRecord.expires_at);
    if (Date.now() > expiresAt.getTime()) {
      return res.status(401).json({
        success: false,
        error: 'API key has expired.',
      });
    }
  }

  // Update last_used_at asynchronously (fire and forget)
  try {
    db.prepare(`UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?`)
      .run(apiKeyRecord.id);
  } catch (_) {
    // Non-fatal
  }

  // Parse scopes from JSON string if needed
  let scopes = apiKeyRecord.scopes;
  if (typeof scopes === 'string') {
    try { scopes = JSON.parse(scopes); } catch (_) { scopes = ['read']; }
  }

  req.apiKey = {
    id: apiKeyRecord.id,
    owner_id: apiKeyRecord.owner_id,
    name: apiKeyRecord.name,
    scopes,
    rate_limit: apiKeyRecord.rate_limit,
    status: apiKeyRecord.status,
  };

  return next();
}
