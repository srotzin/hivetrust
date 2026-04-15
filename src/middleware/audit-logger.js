/**
 * HiveTrust — Audit Logging Middleware
 *
 * Logs every request to the existing audit_log table.
 * Captures actor identity, action, response status, and timing.
 * Non-fatal: errors are logged but never break the request.
 */

import { randomUUID } from 'crypto';
import { query } from '../db.js';

/**
 * Resolve the actor identity from the request (set by auth middleware).
 */
function resolveActor(req) {
  if (req.agentDid) {
    return { actor_id: req.agentDid, actor_type: 'agent' };
  }
  if (req.apiKey?.owner_id && req.apiKey.owner_id !== 'system') {
    return { actor_id: req.apiKey.owner_id, actor_type: 'api_key' };
  }
  if (req.serviceAccount?.platform) {
    return { actor_id: req.serviceAccount.platform, actor_type: 'service' };
  }
  if (req.apiKey?.id === 'internal') {
    return { actor_id: 'system', actor_type: 'service' };
  }
  return { actor_id: 'anonymous', actor_type: 'anonymous' };
}

export default function auditLogger(req, res, next) {
  const startTime = Date.now();

  res.on('finish', () => {
    try {
      const { actor_id, actor_type } = resolveActor(req);
      const duration = Date.now() - startTime;
      const ip =
        req.headers['x-forwarded-for']?.split(',')[0].trim() ||
        req.socket?.remoteAddress ||
        'unknown';

      const details = JSON.stringify({
        method: req.method,
        status_code: res.statusCode,
        duration_ms: duration,
        success: res.statusCode < 400,
        payment_method: req.paymentMethod || null,
        user_agent: req.headers['user-agent'] || null,
      });

      query(
        `INSERT INTO audit_log (id, actor_id, actor_type, action, resource_type, resource_id, details, ip_address)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [
          randomUUID(),
          actor_id,
          actor_type,
          `${req.method} ${req.path}`,
          'http_request',
          req.path,
          details,
          ip,
        ]
      ).catch(err => {
        console.error('[audit-logger] Failed to write audit log:', err.message);
      });
    } catch (err) {
      console.error('[audit-logger] Failed to write audit log:', err.message);
    }
  });

  next();
}
