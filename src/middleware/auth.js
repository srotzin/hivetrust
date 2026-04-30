/**
 * HiveTrust — API Key Authentication Middleware
 * Checks X-API-Key header or ?api_key= query param.
 * Hashes the key with SHA-256 and looks it up in the api_keys table.
 * Attaches key info to req.apiKey if valid.
 * Allows INTERNAL_API_TOKEN as a master bypass key.
 * Some endpoints are public and skip auth entirely.
 *
 * Every failed authentication is a recruitment event — unregistered agents
 * receive a rich onboarding invitation instead of a plain 401.
 */

// ─── Hive Civilization Recruitment Response ───────────────────────────────────
function recruitmentResponse(res) {
  return res.status(401).json({
    status: 'unregistered_agent',
    error: 'agent_not_registered',
    message: 'Welcome to Hive Civilization — register your agent DID to unlock 21 services across 12 layers.',
    onboard: {
      url: 'https://hivegate.onrender.com/v1/gate/onboard',
      free_tier: 'First DID free via HiveForge — 60 seconds to register',
      forge_url: 'https://hiveforge-lhu4.onrender.com/v1/forge/mint',
      docs: 'https://hivegate.onrender.com/.well-known/hivegate.json',
    },
    platform: {
      services: 21,
      layers: 13,
      settlement: 'USDC on Base L2',
      compliance: ['HIPAA', 'SOC2', 'GDPR'],
      website: 'https://thehiveryiq.com',
    },
    referral: {
      program: 'Earn 15% commission on every agent you refer',
      referral_endpoint: 'https://hive-referral-agent.onrender.com/v1/referral/execute',
    },
    http_status: 401,
  });
}

import { createHash } from 'crypto';
import { query } from '../db.js';
import { verifyServiceToken } from '../services/jwt-auth.js';

// Constellation cross-service API keys — accepted as internal keys.
//
// SECURITY 2026-04-25: Hard-coded keys were committed to source. The
// `hive_internal_125e04...` value was used in the on-chain treasury drain.
// Source-committed keys are world-readable on the public repo and are NEVER
// safe. Keys must come from env only. If neither env var is set, NO key is
// accepted as a constellation key (route falls through to JWT / DB lookup).
const CONSTELLATION_KEYS = new Set([
  process.env.CONSTELLATION_HIVEFORGE_KEY,
  process.env.CONSTELLATION_INTERNAL_KEY,
].filter(Boolean));

// Public paths — no auth required (exact match or startsWith)
const PUBLIC_PATHS = [
  '/health',
  '/.well-known/hivetrust.json',
  '/.well-known/mcp.json',
  '/mcp',                     // MCP discovery + initialize + tools/list (tools/call still gated inside handler)
];

// Public path prefixes — checked with and without /v1 prefix
const PUBLIC_PREFIXES = [
  '/v1/identity/',   // Identity passport — handles its own payment gating (BOGO/x402/enterprise)
  '/identity/',      // same without /v1 prefix
  '/v1/verify_agent_risk',
  '/v1/stats',
  '/v1/pricing',
  '/v1/oracle/streams',
  '/v1/trust/wallet-attestation',
  '/v1/trust/zk-status',
  '/v1/trust/lookup',   // public lensing endpoint — no auth required
  '/v1/trust/register', // agent self-registration — no API key needed
  '/v1/trust/issue',    // trust credential issuance — free, no API key needed
  '/verify_agent_risk',
  '/stats',
  '/pricing',
  '/oracle/streams',
  '/trust/wallet-attestation',
  '/trust/zk-status',
  '/trust/lookup',
  '/trust/register',    // when mounted at /v1, req.path is /trust/register
  '/trust/issue',       // when mounted at /v1, req.path is /trust/issue
  '/v1/trust/issue-smsh', // smsh badge issuance — free
  '/trust/issue-smsh',  // when mounted at /v1
  '/trust/score/',      // x402-gated already — auth layer should not double-gate
  '/trust/lookup',
  '/v1/trust/schema',          // public schema documents (JSON-LD context + spec)
  '/trust/schema',
  '/v1/trust/vc/supermodel',   // supermodel credential issuance — free, no API key
  '/trust/vc/supermodel',
  '/v1/audit/',          // HiveAudit — handles its own payment gating (free reads, $0.001 log, $0.01 verify via x402)
  '/audit/',
  '/v1/comply/',         // HiveComply — Stripe webhook handles its own HMAC signature verify; quote/start/settle public discovery
  '/comply/',
  '/v1/credential/pubkey',  // HiveCredential — free Ed25519 issuer pubkey for offline verify
  '/credential/pubkey',     // when mounted at /v1, req.path is /credential/pubkey
  '/.well-known/schemas/', // public schema documents (HAHS v1 etc.)
  '/.well-known/agent-card.json',
  '/.well-known/x402',
];

function hashKey(rawKey) {
  return createHash('sha256').update(rawKey).digest('hex');
}

function isPublicPath(path, originalUrl) {
  // Check both req.path and req.originalUrl — Express strips mount prefix
  // from req.path inside middleware mounted via app.use('/mcp', ...).
  const candidates = [path];
  if (originalUrl) {
    // Strip query string from originalUrl
    const cleanUrl = originalUrl.split('?')[0];
    candidates.push(cleanUrl);
  }
  for (const p of candidates) {
    if (PUBLIC_PATHS.includes(p)) return true;
    if (PUBLIC_PREFIXES.some((prefix) => p.startsWith(prefix))) return true;
  }
  return false;
}

/**
 * Express middleware for API key authentication.
 */
export default async function authMiddleware(req, res, next) {
  // Skip auth for public endpoints
  if (isPublicPath(req.path, req.originalUrl)) {
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
        if ((err.status || 401) === 401) return recruitmentResponse(res);
        return res.status(err.status).json({
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
    return recruitmentResponse(res);
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
    return recruitmentResponse(res);
  }

  if (apiKeyRecord.status !== 'active') {
    return recruitmentResponse(res);
  }

  // Check expiry
  if (apiKeyRecord.expires_at) {
    const expiresAt = new Date(apiKeyRecord.expires_at);
    if (Date.now() > expiresAt.getTime()) {
      return recruitmentResponse(res);
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
