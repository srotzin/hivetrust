/**
 * HiveTrust — Per-DID Rate Limiter with SQLite Persistence
 *
 * Tiered limits:
 *   - Internal keys (['*'] scopes): 100,000 req/min
 *   - Authenticated DIDs / API keys: 1,000 req/min
 *   - Unauthenticated IPs: 100 req/min
 *
 * Uses SQLite rate_limits table for persistence with in-memory Map fallback.
 */

import db from '../db.js';

const WINDOW_MS = 60 * 1000; // 60-second window

// Tiered limits
const LIMIT_INTERNAL = 100000;
const LIMIT_AUTHENTICATED = 1000;
const LIMIT_ANONYMOUS = 100;

// In-memory fallback if DB fails
const fallbackMap = new Map();

// Periodic cleanup of expired windows (every 5 minutes)
setInterval(() => {
  // Clean DB
  try {
    db.prepare("DELETE FROM rate_limits WHERE datetime(window_start) < datetime('now', '-2 minutes')").run();
  } catch (_) { /* non-fatal */ }

  // Clean fallback map
  const now = Date.now();
  for (const [key, entry] of fallbackMap.entries()) {
    if (now >= entry.resetAt) {
      fallbackMap.delete(key);
    }
  }
}, 5 * 60 * 1000).unref();

/**
 * Resolve the rate-limit key and tier limit from the request.
 */
function resolveKeyAndLimit(req) {
  // Internal keys get highest limit
  if (req.apiKey?.scopes?.includes('*')) {
    return { key: `key:${req.apiKey.id}`, limit: LIMIT_INTERNAL };
  }

  // Authenticated DID
  if (req.agentDid) {
    return { key: `did:${req.agentDid}`, limit: LIMIT_AUTHENTICATED };
  }

  // Authenticated API key
  if (req.apiKey?.id) {
    return { key: `key:${req.apiKey.id}`, limit: LIMIT_AUTHENTICATED };
  }

  // Anonymous — fall back to IP
  const ip =
    req.headers['x-forwarded-for']?.split(',')[0].trim() ||
    req.socket?.remoteAddress ||
    'unknown';
  return { key: `ip:${ip}`, limit: LIMIT_ANONYMOUS };
}

/**
 * Get current window start as ISO string (rounded to current minute).
 */
function currentWindowStart() {
  const now = new Date();
  now.setSeconds(0, 0);
  return now.toISOString();
}

/**
 * Try to increment counter in SQLite. Returns { count, windowStart } or null on failure.
 */
function incrementDb(key, windowStart) {
  try {
    db.prepare(
      `INSERT INTO rate_limits (key, window_start, request_count)
       VALUES (?, ?, 1)
       ON CONFLICT(key, window_start) DO UPDATE SET request_count = request_count + 1`
    ).run(key, windowStart);

    const row = db.prepare(
      'SELECT request_count FROM rate_limits WHERE key = ? AND window_start = ?'
    ).get(key, windowStart);

    return row ? row.request_count : 1;
  } catch (err) {
    console.error('[rate-limiter] DB error, falling back to in-memory:', err.message);
    return null;
  }
}

/**
 * In-memory fallback counter.
 */
function incrementFallback(key, limit) {
  const now = Date.now();
  const entry = fallbackMap.get(key);

  if (!entry || now >= entry.resetAt) {
    fallbackMap.set(key, { count: 1, resetAt: now + WINDOW_MS });
    return { count: 1, resetAt: now + WINDOW_MS };
  }

  entry.count += 1;
  return entry;
}

/**
 * Express middleware factory. Accepts optional limit override.
 * @param {number} [limitOverride] - override the tiered limit
 */
export function createRateLimiter(limitOverride) {
  return function rateLimiter(req, res, next) {
    const { key, limit: tieredLimit } = resolveKeyAndLimit(req);
    const limit = limitOverride || tieredLimit;

    const windowStart = currentWindowStart();
    let count = incrementDb(key, windowStart);

    let resetAt;
    if (count !== null) {
      // DB path — reset is end of current minute window
      const windowDate = new Date(windowStart);
      resetAt = windowDate.getTime() + WINDOW_MS;
    } else {
      // Fallback to in-memory
      const fallback = incrementFallback(key, limit);
      count = fallback.count;
      resetAt = fallback.resetAt;
    }

    const remaining = Math.max(0, limit - count);
    const resetEpoch = Math.ceil(resetAt / 1000);

    if (count > limit) {
      const retryAfter = Math.ceil((resetAt - Date.now()) / 1000);
      res.setHeader('Retry-After', Math.max(1, retryAfter));
      res.setHeader('X-RateLimit-Limit', limit);
      res.setHeader('X-RateLimit-Remaining', 0);
      res.setHeader('X-RateLimit-Reset', resetEpoch);
      return res.status(429).json({
        success: false,
        error: 'Too Many Requests',
        retryAfter: Math.max(1, retryAfter),
      });
    }

    res.setHeader('X-RateLimit-Limit', limit);
    res.setHeader('X-RateLimit-Remaining', remaining);
    res.setHeader('X-RateLimit-Reset', resetEpoch);

    return next();
  };
}

// Default export: pre-built middleware with tiered limits
export default createRateLimiter();
