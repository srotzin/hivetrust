/**
 * HiveTrust — IP Allowlist Middleware
 *
 * Restricts access to internal endpoints by source IP.
 * Reads ALLOWED_INTERNAL_IPS from env (comma-separated).
 * If the env var is not set, skips the check entirely (won't break existing deploys).
 */

/**
 * Returns Express middleware that blocks requests from IPs not in the allowlist.
 */
export default function ipAllowlist(req, res, next) {
  const allowedRaw = process.env.ALLOWED_INTERNAL_IPS;

  // If not configured, skip check entirely
  if (!allowedRaw) {
    return next();
  }

  const allowedIps = new Set(
    allowedRaw.split(',').map((ip) => ip.trim()).filter(Boolean)
  );

  const clientIp =
    req.headers['x-forwarded-for']?.split(',')[0].trim() ||
    req.socket?.remoteAddress ||
    'unknown';

  // Normalize IPv6 loopback
  const normalizedIp = clientIp === '::1' ? '127.0.0.1' : clientIp;

  if (!allowedIps.has(normalizedIp)) {
    console.warn(`[ip-allowlist] Blocked request from ${clientIp} to ${req.method} ${req.path}`);
    return res.status(403).json({
      success: false,
      error: 'Access denied: IP not in allowlist',
    });
  }

  return next();
}
