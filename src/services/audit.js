/**
 * HiveTrust — Audit Service
 * Immutable audit logging for all platform operations.
 * Every write is append-only; no update/delete exposed.
 */

import db from '../db.js';
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
export function log(
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
    db.prepare(`
      INSERT INTO audit_log
        (id, actor_id, actor_type, action, resource_type, resource_id, details, ip_address, created_at)
      VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).run(
      id,
      actorId,
      actorType,
      action,
      resourceType,
      resourceId,
      JSON.stringify(details),
      ipAddress
    );
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
 *
 * @param {object} filters
 * @param {string}  [filters.actorId]
 * @param {string}  [filters.actorType]
 * @param {string}  [filters.action]          - exact match
 * @param {string}  [filters.actionPrefix]    - LIKE prefix, e.g. 'agent.'
 * @param {string}  [filters.resourceType]
 * @param {string}  [filters.resourceId]
 * @param {string}  [filters.since]           - ISO 8601 lower bound (inclusive)
 * @param {string}  [filters.until]           - ISO 8601 upper bound (inclusive)
 * @param {number}  [filters.limit=100]
 * @param {number}  [filters.offset=0]
 * @returns {{ success: boolean, entries?: object[], total?: number, error?: string }}
 */
export function query(filters = {}) {
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

    if (actorId)       { conditions.push('actor_id = ?');         params.push(actorId); }
    if (actorType)     { conditions.push('actor_type = ?');       params.push(actorType); }
    if (action)        { conditions.push('action = ?');            params.push(action); }
    if (actionPrefix)  { conditions.push('action LIKE ?');         params.push(`${actionPrefix}%`); }
    if (resourceType)  { conditions.push('resource_type = ?');    params.push(resourceType); }
    if (resourceId)    { conditions.push('resource_id = ?');      params.push(resourceId); }
    if (since)         { conditions.push('created_at >= ?');      params.push(since); }
    if (until)         { conditions.push('created_at <= ?');      params.push(until); }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

    const countRow = db.prepare(`SELECT COUNT(*) as n FROM audit_log ${where}`).get(...params);
    const total = countRow.n;

    const rows = db.prepare(`
      SELECT * FROM audit_log ${where}
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `).all(...params, limit, offset);

    const entries = rows.map(r => ({
      ...r,
      details: JSON.parse(r.details || '{}'),
    }));

    return { success: true, entries, total };
  } catch (err) {
    console.error('[audit] query failed:', err.message);
    return { success: false, error: err.message };
  }
}
