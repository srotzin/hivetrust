/**
 * HiveTrust — Audit Service
 * Immutable audit logging for all platform operations.
 * Every write is append-only; no update/delete exposed.
 */

import { query } from '../db.js';
import { v4 as uuidv4 } from 'uuid';

// ─── Log ─────────────────────────────────────────────────────

/**
 * Append an immutable audit record.
 *
 * @param {string} actorId       - ID of the entity performing the action
 * @param {string} actorType     - 'agent' | 'user' | 'system' | 'api_key'
 * @param {string} action        - Verb, e.g. 'agent.register', 'score.compute'
 * @param {string} resourceType  - Table / domain, e.g. 'agent', 'trust_score'
 * @param {string} resourceId    - PK of the resource
 * @param {object} details       - Arbitrary JSON context
 * @param {string} [ipAddress]   - Caller IP (optional)
 * @returns {{ success: boolean, id?: string, error?: string }}
 */
export async function log(
  actorId,
  actorType = 'system',
  action,
  resourceType,
  resourceId,
  details = {},
  ipAddress = null
) {
  try {
    const id = uuidv4();
    await query(`
      INSERT INTO audit_log
        (id, actor_id, actor_type, action, resource_type, resource_id, details, ip_address, created_at)
      VALUES
        ($1, $2, $3, $4, $5, $6, $7, $8, NOW()::TEXT)
    `, [
      id,
      actorId,
      actorType,
      action,
      resourceType,
      resourceId,
      JSON.stringify(details),
      ipAddress,
    ]);
    return { success: true, id };
  } catch (err) {
    // Audit failures must never crash callers — swallow & return error shape
    console.error('[audit] log failed:', err.message);
    return { success: false, error: err.message };
  }
}

// ─── Query ────────────────────────────────────────────────────

/**
 * Query the audit log with optional filters.
 */
export async function queryAuditLog(filters = {}) {
  try {
    const {
      actorId,
      actorType,
      action,
      actionPrefix,
      resourceType,
      resourceId,
      since,
      until,
      limit = 100,
      offset = 0,
    } = filters;

    const conditions = [];
    const params = [];
    let paramIdx = 1;

    if (actorId)       { conditions.push(`actor_id = $${paramIdx++}`);       params.push(actorId); }
    if (actorType)     { conditions.push(`actor_type = $${paramIdx++}`);     params.push(actorType); }
    if (action)        { conditions.push(`action = $${paramIdx++}`);         params.push(action); }
    if (actionPrefix)  { conditions.push(`action LIKE $${paramIdx++}`);      params.push(`${actionPrefix}%`); }
    if (resourceType)  { conditions.push(`resource_type = $${paramIdx++}`);  params.push(resourceType); }
    if (resourceId)    { conditions.push(`resource_id = $${paramIdx++}`);    params.push(resourceId); }
    if (since)         { conditions.push(`created_at >= $${paramIdx++}`);    params.push(since); }
    if (until)         { conditions.push(`created_at <= $${paramIdx++}`);    params.push(until); }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

    const countResult = await query(`SELECT COUNT(*) as n FROM audit_log ${where}`, params);
    const total = parseInt(countResult.rows[0].n, 10);

    const rowsResult = await query(`
      SELECT * FROM audit_log ${where}
      ORDER BY created_at DESC
      LIMIT $${paramIdx++} OFFSET $${paramIdx++}
    `, [...params, limit, offset]);

    const entries = rowsResult.rows.map(r => ({
      ...r,
      details: typeof r.details === 'string' ? JSON.parse(r.details || '{}') : r.details,
    }));

    return { success: true, entries, total };
  } catch (err) {
    console.error('[audit] query failed:', err.message);
    return { success: false, error: err.message };
  }
}

// Keep backward-compatible export name
export { queryAuditLog as query };
