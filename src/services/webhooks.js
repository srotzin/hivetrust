/**
 * HiveTrust — Webhook Delivery Service
 *
 * Pattern: HMAC-SHA256 signed payloads, exponential back-off retry,
 * delivery log in webhook_deliveries table.
 *
 * Signing headers:
 *   X-HiveTrust-Signature: sha256=<hex-hmac>
 *   X-HiveTrust-Event:    <event_type>
 *   X-HiveTrust-Delivery: <delivery_id>
 *   X-HiveTrust-Timestamp:<unix_seconds>
 */

import { query } from '../db.js';
import { v4 as uuidv4 } from 'uuid';
import { createHmac, randomBytes } from 'crypto';
import * as audit from './audit.js';

const MAX_RETRIES = 5;

// ─── Register ─────────────────────────────────────────────────

/**
 * Register a new webhook endpoint.
 *
 * @param {string}   ownerId      - Owning user / org ID
 * @param {string}   url          - HTTPS URL to deliver to
 * @param {string[]} events       - Array of event types, e.g. ['score.update', '*']
 * @param {string}   [ipAddress]
 * @returns {{ success: boolean, endpoint?: object, secret?: string, error?: string }}
 */
export async function registerWebhook(ownerId, url, events = ['*'], ipAddress = null) {
  try {
    if (!ownerId) return { success: false, error: 'ownerId is required' };
    if (!url)     return { success: false, error: 'url is required' };

    try { new URL(url); } catch {
      return { success: false, error: 'Invalid URL format' };
    }

    const id     = uuidv4();
    const secret = randomBytes(32).toString('hex'); // 64-char hex secret

    await query(`
      INSERT INTO webhook_endpoints (id, owner_id, url, secret, events, status, created_at)
      VALUES ($1, $2, $3, $4, $5, 'active', NOW()::TEXT)
    `, [id, ownerId, url, secret, JSON.stringify(events)]);

    await audit.log(ownerId, 'user', 'webhook.register', 'webhook_endpoint', id,
      { url, events }, ipAddress);

    return {
      success: true,
      endpoint: { id, owner_id: ownerId, url, events, status: 'active' },
      secret,
    };
  } catch (err) {
    console.error('[webhooks] registerWebhook failed:', err.message);
    return { success: false, error: err.message };
  }
}

// ─── List ─────────────────────────────────────────────────────

/**
 * List webhook endpoints for an owner.
 */
export async function listWebhooks(ownerId) {
  try {
    const result = await query(
      'SELECT id, owner_id, url, events, status, created_at FROM webhook_endpoints WHERE owner_id = $1',
      [ownerId]
    );

    return {
      success: true,
      endpoints: result.rows.map(r => ({ ...r, events: JSON.parse(r.events || '["*"]') })),
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ─── Deactivate ───────────────────────────────────────────────

/**
 * Deactivate (remove) a webhook endpoint.
 */
export async function deactivateWebhook(endpointId, ownerId, ipAddress = null) {
  try {
    const result = await query('SELECT * FROM webhook_endpoints WHERE id = $1', [endpointId]);
    const ep = result.rows[0];
    if (!ep) return { success: false, error: 'Webhook endpoint not found' };
    if (ep.owner_id !== ownerId) return { success: false, error: 'Unauthorized' };

    await query("UPDATE webhook_endpoints SET status = 'inactive' WHERE id = $1", [endpointId]);

    await audit.log(ownerId, 'user', 'webhook.deactivate', 'webhook_endpoint', endpointId, {}, ipAddress);
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ─── Deliver ──────────────────────────────────────────────────

/**
 * Deliver an event to all matching active webhook endpoints.
 *
 * @param {string} eventType   - e.g. 'score.update', 'credential.issue'
 * @param {object} payload     - Arbitrary event data
 * @returns {{ success: boolean, deliveries?: object[], error?: string }}
 */
export async function deliverWebhook(eventType, payload) {
  try {
    const epResult = await query("SELECT * FROM webhook_endpoints WHERE status = 'active'", []);

    const matching = epResult.rows.filter(ep => {
      const evts = JSON.parse(ep.events || '["*"]');
      return evts.includes('*') || evts.includes(eventType);
    });

    if (matching.length === 0) return { success: true, deliveries: [] };

    const timestamp = Math.floor(Date.now() / 1000);
    const deliveries = [];

    for (const ep of matching) {
      const deliveryId = uuidv4();
      const body = JSON.stringify({
        id: deliveryId,
        event_type: eventType,
        timestamp,
        payload,
      });

      const signature = signPayload(ep.secret, body);

      await query(`
        INSERT INTO webhook_deliveries (id, endpoint_id, event_type, payload, status, attempts, created_at)
        VALUES ($1, $2, $3, $4, 'pending', 0, NOW()::TEXT)
      `, [deliveryId, ep.id, eventType, body]);

      const result = await attemptDelivery(ep, deliveryId, body, signature, eventType, timestamp);
      deliveries.push(result);
    }

    return { success: true, deliveries };
  } catch (err) {
    console.error('[webhooks] deliverWebhook failed:', err.message);
    return { success: false, error: err.message };
  }
}

// ─── Retry Pending Deliveries ─────────────────────────────────

/**
 * Retry failed deliveries using exponential back-off.
 * Intended to be called from a scheduled job.
 */
export async function retryPendingDeliveries() {
  try {
    const result = await query(`
      SELECT wd.*, we.url, we.secret
      FROM webhook_deliveries wd
      JOIN webhook_endpoints we ON wd.endpoint_id = we.id
      WHERE wd.status IN ('pending', 'failed') AND wd.attempts < $1
      ORDER BY wd.created_at ASC
      LIMIT 50
    `, [MAX_RETRIES]);

    const pending = result.rows;
    const results = [];
    for (const delivery of pending) {
      const backoffSeconds = Math.pow(2, delivery.attempts) * 5;
      const lastAttempt = delivery.last_attempt_at ? new Date(delivery.last_attempt_at) : null;
      if (lastAttempt) {
        const nextRetryAt = new Date(lastAttempt.getTime() + backoffSeconds * 1000);
        if (new Date() < nextRetryAt) continue;
      }

      const ep = { url: delivery.url, secret: delivery.secret, id: delivery.endpoint_id };
      const timestamp = Math.floor(new Date(delivery.created_at).getTime() / 1000);
      const signature = signPayload(ep.secret, delivery.payload);

      const res = await attemptDelivery(ep, delivery.id, delivery.payload, signature, delivery.event_type, timestamp);
      results.push(res);
    }

    return { success: true, processed: results.length, results };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ─── Internal Helpers ─────────────────────────────────────────

function signPayload(secret, body) {
  return 'sha256=' + createHmac('sha256', secret).update(body).digest('hex');
}

async function attemptDelivery(ep, deliveryId, body, signature, eventType, timestamp) {
  const now = new Date().toISOString();

  await query(
    'UPDATE webhook_deliveries SET attempts = attempts + 1, last_attempt_at = $1 WHERE id = $2',
    [now, deliveryId]
  );

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10_000);

    const response = await fetch(ep.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-HiveTrust-Signature': signature,
        'X-HiveTrust-Event': eventType,
        'X-HiveTrust-Delivery': deliveryId,
        'X-HiveTrust-Timestamp': String(timestamp),
        'User-Agent': 'HiveTrust-Webhook/1.0',
      },
      body,
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (response.ok) {
      await query(
        "UPDATE webhook_deliveries SET status = 'delivered', delivered_at = $1 WHERE id = $2",
        [now, deliveryId]
      );
      return { deliveryId, endpointId: ep.id, status: 'delivered', httpStatus: response.status };
    }

    await query("UPDATE webhook_deliveries SET status = 'failed' WHERE id = $1", [deliveryId]);
    return { deliveryId, endpointId: ep.id, status: 'failed', httpStatus: response.status };

  } catch (fetchErr) {
    const isTimeout = fetchErr.name === 'AbortError';
    await query("UPDATE webhook_deliveries SET status = 'failed' WHERE id = $1", [deliveryId]);
    return {
      deliveryId,
      endpointId: ep.id,
      status: 'failed',
      error: isTimeout ? 'timeout' : fetchErr.message,
    };
  }
}
