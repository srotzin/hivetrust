/**
 * HiveTrust — API Key Authentication Middleware
 * Checks X-API-Key header or ?api_key= query param.
 * Hashes the key with SHA-256 and looks it up in the api_keys table.
 * Attaches key info to req.apiKey if valid.
 * Allows INTERNAL_API_TOKEN as a master bypass key.
 * Some endpoints are public and skip auth entirely.
 */

import { createHash } from 'crypto';
import { query } from '../db.js';
import { verifyServiceToken } from '../services/jwt-auth.js';

// Constellation cross-service API keys — accepted as internal keys
const CONSTELLATION_KEYS = new Set([
  'hive_hiveforge_5ba66a8a5065a287708833254fbd048fb2e18a95639fe68bfd28cc96d910c1a8',
  'hive_internal_125e04e071e8829be631ea0216dd4a0c9b707975fcecaf8c62c6a2ab43327d46',
]);

// Public paths — no auth required (exact match or startsWith)
const PUBLIC_PATHS = [
  '/health',
  '/.well-known/hivetrust.json',
];

// Public path prefixes — checked with and without /v1 prefix
const PUBLIC_PREFIXES = [
  '/v1/verify_agent_risk',
  '/v1/stats',
  '/v1/pricing',
  '/v1/oracle/streams',
  '/verify_agent_risk',
  '/stats',
  '/pricing',
  '/oracle/streams',
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
export default async function authMiddleware(req, res, next) {
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
  const rawKey =
    req.headers['x-api-key'] ||
    req.headers['x-hive-internal-key'] ||
    req.headers['x-hive-internal'] ||
    req.query?.api_key ||
    null;

  if (!rawKey) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required. Provide X-API-Key header or ?api_key= query param.',
    });
  }

  // Check master internal tokens first (fast path, no DB)
  const internalToken = process.env.INTERNAL_API_TOKEN;
  const hiveInternalKey = process.env.HIVETRUST_SERVICE_KEY || process.env.HIVE_INTERNAL_KEY;
  if ((internalToken && rawKey === internalToken) || (hiveInternalKey && rawKey === hiveInternalKey)) {
    req.apiKey = {
      id: 'internal',
      owner_id: 'system',
      name: rawKey === internalToken ? 'Internal Master Key' : 'Hive Constellation Key',
      scopes: ['*'],
      rate_limit: 100000,
      status: 'active',
    };
    return next();
  }

  // Check hardcoded constellation cross-service keys
  if (CONSTELLATION_KEYS.has(rawKey)) {
    const prefix = rawKey.split('_').slice(0, 2).join('_');
    req.apiKey = {
      id: `constellation:${prefix}`,
      owner_id: prefix,
      name: `Constellation Key: ${prefix}`,
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
    const result = await query(
      `SELECT id, owner_id, name, scopes, rate_limit, status, expires_at
       FROM api_keys
       WHERE key_hash = $1
       LIMIT 1`,
      [keyHash]
    );
    apiKeyRecord = result.rows[0] || null;
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
  query(`UPDATE api_keys SET last_used_at = NOW()::TEXT WHERE id = $1`, [apiKeyRecord.id])
    .catch(() => {});

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
