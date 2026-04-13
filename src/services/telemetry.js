/**
 * HiveTrust — Telemetry Service
 * High-throughput behavioral event ingestion and querying.
 *
 * Event types:
 *  - transaction_complete, transaction_failed
 *  - sla_met, sla_violated
 *  - dispute_filed, dispute_resolved
 *  - credential_issued, credential_revoked
 *  - anomaly_detected
 *
 * Score recompute is triggered when >= 10 new events have arrived
 * since the last trust score computation.
 */

import db from '../db.js';
import { v4 as uuidv4 } from 'uuid';
import * as audit from './audit.js';

const VALID_EVENT_TYPES = new Set([
  'transaction_complete',
  'transaction_failed',
  'sla_met',
  'sla_violated',
  'dispute_filed',
  'dispute_resolved',
  'credential_issued',
  'credential_revoked',
  'anomaly_detected',
]);

const RECOMPUTE_THRESHOLD = 10; // new events since last score computation

// Pillar mapping: which pillar an event primarily affects
const EVENT_PILLAR_MAP = {
  transaction_complete: 'behavior',
  transaction_failed:   'behavior',
  sla_met:              'behavior',
  sla_violated:         'behavior',
  dispute_filed:        'behavior',
  dispute_resolved:     'behavior',
  credential_issued:    'identity',
  credential_revoked:   'identity',
  anomaly_detected:     'behavior',
};

// Indicative score impact per event type (used for behavioral analytics)
const EVENT_SCORE_IMPACT = {
  transaction_complete: +2,
  transaction_failed:   -3,
  sla_met:              +2,
  sla_violated:         -4,
  dispute_filed:        -8,
  dispute_resolved:     +3,
  credential_issued:    +5,
  credential_revoked:   -5,
  anomaly_detected:     -10,
};

// ─── Ingest ───────────────────────────────────────────────────

/**
 * Bulk-ingest an array of behavioral events.
 *
 * Each event object:
 * {
 *   agent_id:           string  (required)
 *   event_type:         string  (required)
 *   action:             string  (optional descriptor)
 *   outcome:            string  'success' | 'failure' | 'pending'
 *   counterparty_id:    string  (optional)
 *   transaction_value:  number  (optional, USDC)
 *   evidence:           object  (optional)
 *   source_platform:    string  (default: 'hivetrust')
 * }
 *
 * @param {object[]} events
 * @param {string}   [source]     - Source identifier for bulk attribution
 * @returns {{ success: boolean, ingested?: number, skipped?: number, recomputes?: string[], errors?: string[], error?: string }}
 */
export function ingestEvents(events, source = 'api') {
  try {
    if (!Array.isArray(events) || events.length === 0) {
      return { success: false, error: 'events must be a non-empty array' };
    }

    const insert = db.prepare(`
      INSERT INTO behavioral_events (
        id, agent_id, event_type, source, source_platform,
        action, outcome, counterparty_id, transaction_value,
        score_impact, pillar_affected,
        evidence, metadata, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', datetime('now'))
    `);

    const insertMany = db.transaction((evts) => {
      const ingested = [];
      const errors   = [];
      const agentEventCounts = new Map();

      for (const evt of evts) {
        // Validate required fields
        if (!evt.agent_id) { errors.push('Missing agent_id'); continue; }
        if (!VALID_EVENT_TYPES.has(evt.event_type)) {
          errors.push(`Invalid event_type '${evt.event_type}' for agent ${evt.agent_id}`);
          continue;
        }

        // Verify agent exists
        const agentExists = db.prepare('SELECT id FROM agents WHERE id = ?').get(evt.agent_id);
        if (!agentExists) {
          errors.push(`Agent ${evt.agent_id} not found`);
          continue;
        }

        const id = uuidv4();
        insert.run(
          id,
          evt.agent_id,
          evt.event_type,
          source,
          evt.source_platform || 'hivetrust',
          evt.action   || null,
          evt.outcome  || null,
          evt.counterparty_id   || null,
          evt.transaction_value ?? null,
          EVENT_SCORE_IMPACT[evt.event_type] ?? 0,
          EVENT_PILLAR_MAP[evt.event_type]   ?? 'behavior',
          JSON.stringify(evt.evidence || {})
        );

        ingested.push({ id, agent_id: evt.agent_id, event_type: evt.event_type });

        // Track event count per agent for recompute check
        agentEventCounts.set(evt.agent_id, (agentEventCounts.get(evt.agent_id) || 0) + 1);
      }

      return { ingested, errors, agentEventCounts };
    });

    const { ingested, errors, agentEventCounts } = insertMany(events);

    // Check which agents need score recomputation
    const recomputes = [];
    for (const [agentId, newCount] of agentEventCounts) {
      if (shouldRecompute(agentId, newCount)) {
        recomputes.push(agentId);
        // Trigger async recompute (import lazily to avoid circular dep)
        triggerRecompute(agentId);
      }
    }

    audit.log('system', 'system', 'telemetry.ingest', 'behavioral_events', 'bulk',
      { count: ingested.length, source, recomputes: recomputes.length });

    return {
      success: true,
      ingested: ingested.length,
      skipped: events.length - ingested.length - errors.length,
      errors: errors.length > 0 ? errors : undefined,
      recomputes,
      events: ingested,
    };
  } catch (err) {
    console.error('[telemetry] ingestEvents failed:', err.message);
    return { success: false, error: err.message };
  }
}

// ─── Query Events ─────────────────────────────────────────────

/**
 * Query behavioral events for an agent with optional filters.
 *
 * @param {string} agentId
 * @param {object} options
 * @param {string}   [options.eventType]       - Filter by event type
 * @param {string}   [options.outcome]         - Filter by outcome
 * @param {string}   [options.counterpartyId]
 * @param {string}   [options.since]           - ISO 8601 lower bound
 * @param {string}   [options.until]           - ISO 8601 upper bound
 * @param {string}   [options.sourcePlatform]
 * @param {number}   [options.limit=50]
 * @param {number}   [options.offset=0]
 * @returns {{ success: boolean, events?: object[], total?: number, error?: string }}
 */
export function getEvents(agentId, options = {}) {
  try {
    const {
      eventType,
      outcome,
      counterpartyId,
      since,
      until,
      sourcePlatform,
      limit  = 50,
      offset = 0,
    } = options;

    const conditions = ['agent_id = ?'];
    const params     = [agentId];

    if (eventType)       { conditions.push('event_type = ?');       params.push(eventType); }
    if (outcome)         { conditions.push('outcome = ?');           params.push(outcome); }
    if (counterpartyId)  { conditions.push('counterparty_id = ?');   params.push(counterpartyId); }
    if (since)           { conditions.push('created_at >= ?');       params.push(since); }
    if (until)           { conditions.push('created_at <= ?');       params.push(until); }
    if (sourcePlatform)  { conditions.push('source_platform = ?');   params.push(sourcePlatform); }

    const where = `WHERE ${conditions.join(' AND ')}`;

    const total = db.prepare(`SELECT COUNT(*) as n FROM behavioral_events ${where}`).get(...params).n;
    const rows  = db.prepare(`
      SELECT * FROM behavioral_events ${where}
      ORDER BY created_at DESC LIMIT ? OFFSET ?
    `).all(...params, limit, offset);

    return {
      success: true,
      events: rows.map(r => ({
        ...r,
        evidence: JSON.parse(r.evidence || '{}'),
        metadata: JSON.parse(r.metadata || '{}'),
      })),
      total,
    };
  } catch (err) {
    console.error('[telemetry] getEvents failed:', err.message);
    return { success: false, error: err.message };
  }
}

/**
 * Get aggregated event statistics for an agent.
 */
export function getEventStats(agentId) {
  try {
    const stats = db.prepare(`
      SELECT
        event_type,
        COUNT(*) as count,
        SUM(CASE WHEN outcome = 'success' THEN 1 ELSE 0 END) as successes,
        SUM(CASE WHEN outcome = 'failure' THEN 1 ELSE 0 END) as failures,
        SUM(CASE WHEN transaction_value > 0 THEN transaction_value ELSE 0 END) as total_value,
        SUM(score_impact) as total_score_impact
      FROM behavioral_events
      WHERE agent_id = ?
      GROUP BY event_type
    `).all(agentId);

    const totalEvents = db.prepare('SELECT COUNT(*) as n FROM behavioral_events WHERE agent_id = ?').get(agentId);

    return {
      success: true,
      agentId,
      total_events: totalEvents.n,
      by_type: stats,
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ─── Recompute Logic ──────────────────────────────────────────

/**
 * Decide if we should trigger score recomputation for an agent.
 * Threshold: >= RECOMPUTE_THRESHOLD new events since last compute.
 */
function shouldRecompute(agentId, newEventsCount) {
  if (newEventsCount < RECOMPUTE_THRESHOLD) {
    // Check total events since last score computation
    const lastScore = db.prepare(`
      SELECT computed_at FROM trust_scores WHERE agent_id = ? ORDER BY computed_at DESC LIMIT 1
    `).get(agentId);

    if (!lastScore) return true; // No score yet — always compute

    const eventsSince = db.prepare(`
      SELECT COUNT(*) as n FROM behavioral_events
      WHERE agent_id = ? AND created_at > ?
    `).get(agentId, lastScore.computed_at).n;

    return eventsSince >= RECOMPUTE_THRESHOLD;
  }
  return true;
}

/**
 * Trigger trust score recomputation. Uses dynamic import to avoid
 * circular module dependency (trust-scoring imports nothing from here).
 */
async function triggerRecompute(agentId) {
  try {
    const { computeTrustScore } = await import('./trust-scoring.js');
    computeTrustScore(agentId);
  } catch (err) {
    console.error(`[telemetry] Recompute trigger failed for ${agentId}:`, err.message);
  }
}
