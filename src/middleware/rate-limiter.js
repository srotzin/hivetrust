/**
 * HiveTrust — In-Memory Rate Limiter Middleware
 * Tracks requests per IP in a Map, resets every 60 seconds.
 * Default: 1000 requests per minute per IP.
 */

const DEFAULT_LIMIT = 1000;
const WINDOW_MS = 60 * 1000; // 60 seconds

// Map<ip, { count: number, resetAt: number }>
const ipMap = new Map();

// Periodic cleanup of stale entries (every 5 minutes)
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of ipMap.entries()) {
    if (now >= entry.resetAt) {
      ipMap.delete(ip);
    }
  }
}, 5 * 60 * 1000).unref();

/**
 * Express middleware factory. Accepts optional limit override.
 * @param {number} [limit=1000] - max requests per minute per IP
 */
export function createRateLimiter(limit = DEFAULT_LIMIT) {
  return function rateLimiter(req, res, next) {
    const ip =
      req.headers['x-forwarded-for']?.split(',')[0].trim() ||
      req.socket?.remoteAddress ||
      'unknown';

    const now = Date.now();
    const entry = ipMap.get(ip);

    if (!entry || now >= entry.resetAt) {
      // New window
      ipMap.set(ip, { count: 1, resetAt: now + WINDOW_MS });
      return next();
    }

    entry.count += 1;

    if (entry.count > limit) {
      const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
      res.setHeader('Retry-After', retryAfter);
      res.setHeader('X-RateLimit-Limit', limit);
      res.setHeader('X-RateLimit-Remaining', 0);
      res.setHeader('X-RateLimit-Reset', Math.ceil(entry.resetAt / 1000));
      return res.status(429).json({
        success: false,
        error: 'Too Many Requests',
        retryAfter,
      });
    }

    res.setHeader('X-RateLimit-Limit', limit);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, limit - entry.count));
    res.setHeader('X-RateLimit-Reset', Math.ceil(entry.resetAt / 1000));

    return next();
  };
}

// Default export: pre-built middleware with default limit
export default createRateLimiter(DEFAULT_LIMIT);
