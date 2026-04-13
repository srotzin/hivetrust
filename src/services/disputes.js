/**
 * HiveTrust — Dispute & Appeal Service
 *
 * Dispute types:
 *  - score_correction      : agent disputes their trust score
 *  - credential_challenge  : dispute against an issued credential
 *  - claim_dispute         : dispute an insurance claim decision
 *  - identity_dispute      : dispute an identity assertion
 */

import db from '../db.js';
import { v4 as uuidv4 } from 'uuid';
import * as audit from './audit.js';

const VALID_TYPES = new Set([
  'score_correction',
  'credential_challenge',
  'claim_dispute',
  'identity_dispute',
]);

const VALID_TARGET_TYPES = new Set(['trust_score', 'credential', 'claim', 'agent', 'policy']);

// ─── File Dispute ─────────────────────────────────────────────

/**
 * File a dispute against a score, credential, claim, or identity record.
 *
 * @param {string} agentId       - Agent filing the dispute
 * @param {string} disputeType   - One of VALID_TYPES
 * @param {string} targetType    - 'trust_score' | 'credential' | 'claim' | 'agent' | 'policy'
 * @param {string} targetId      - ID of the disputed resource
 * @param {string} reason        - Human-readable reason
 * @param {object} [evidence]    - Supporting documents / links
 * @param {string} [ipAddress]
 * @returns {{ success: boolean, dispute?: object, error?: string }}
 */
export function fileDispute(agentId, disputeType, targetType, targetId, reason, evidence = {}, ipAddress = null) {
  try {
    if (!VALID_TYPES.has(disputeType)) {
      return { success: false, error: `Invalid dispute type. Allowed: ${[...VALID_TYPES].join(', ')}` };
    }
    if (!VALID_TARGET_TYPES.has(targetType)) {
      return { success: false, error: `Invalid target type. Allowed: ${[...VALID_TARGET_TYPES].join(', ')}` };
    }
    if (!reason || reason.trim().length < 10) {
      return { success: false, error: 'Reason must be at least 10 characters' };
    }

    const agent = db.prepare('SELECT id, status FROM agents WHERE id = ?').get(agentId);
    if (!agent) return { success: false, error: 'Agent not found' };

    // Check for duplicate open dispute on same target
    const existing = db.prepare(
      "SELECT id FROM disputes WHERE agent_id = ? AND target_id = ? AND status = 'open'"
    ).get(agentId, targetId);
    if (existing) {
      return { success: false, error: 'An open dispute already exists for this target', disputeId: existing.id };
    }

    const id = uuidv4();

    db.prepare(`
      INSERT INTO disputes (
        id, agent_id, dispute_type,
        target_type, target_id,
        reason, evidence,
        status, filed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'open', datetime('now'))
    `).run(
      id, agentId, disputeType,
      targetType, targetId,
      reason.trim(), JSON.stringify(evidence)
    );

    audit.log(agentId, 'agent', 'dispute.file', 'dispute', id,
      { disputeType, targetType, targetId }, ipAddress);

    const row = db.prepare('SELECT * FROM disputes WHERE id = ?').get(id);
    return { success: true, dispute: deserializeDispute(row) };
  } catch (err) {
    console.error('[disputes] fileDispute failed:', err.message);
    return { success: false, error: err.message };
  }
}

// ─── Get Dispute ──────────────────────────────────────────────

/**
 * Get a single dispute by ID.
 */
export function getDispute(disputeId) {
  try {
    const row = db.prepare('SELECT * FROM disputes WHERE id = ?').get(disputeId);
    if (!row) return { success: false, error: 'Dispute not found' };
    return { success: true, dispute: deserializeDispute(row) };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ─── Resolve Dispute ──────────────────────────────────────────

/**
 * Resolve a dispute (admin / arbitration).
 *
 * @param {string} disputeId
 * @param {string} resolution   - 'upheld' | 'rejected' | 'partial'
 * @param {string} resolvedBy   - Actor performing resolution
 * @param {string} [notes]      - Optional resolution notes
 * @param {string} [ipAddress]
 */
export function resolveDispute(disputeId, resolution, resolvedBy, notes = null, ipAddress = null) {
  try {
    const allowed = new Set(['upheld', 'rejected', 'partial']);
    if (!allowed.has(resolution)) {
      return { success: false, error: `Invalid resolution. Allowed: ${[...allowed].join(', ')}` };
    }

    const row = db.prepare('SELECT * FROM disputes WHERE id = ?').get(disputeId);
    if (!row) return { success: false, error: 'Dispute not found' };
    if (row.status !== 'open') return { success: false, error: `Dispute is already ${row.status}` };

    const resolutionText = notes ? `${resolution}: ${notes}` : resolution;

    db.prepare(`
      UPDATE disputes
      SET status = 'resolved', resolution = ?, resolved_by = ?, resolved_at = datetime('now')
      WHERE id = ?
    `).run(resolutionText, resolvedBy, disputeId);

    audit.log(resolvedBy, 'user', 'dispute.resolve', 'dispute', disputeId,
      { resolution, agentId: row.agent_id }, ipAddress);

    const updated = db.prepare('SELECT * FROM disputes WHERE id = ?').get(disputeId);
    return { success: true, dispute: deserializeDispute(updated) };
  } catch (err) {
    console.error('[disputes] resolveDispute failed:', err.message);
    return { success: false, error: err.message };
  }
}

// ─── List Disputes ────────────────────────────────────────────

/**
 * List disputes for an agent, optionally filtered by status.
 *
 * @param {string} agentId
 * @param {string} [status]   - 'open' | 'resolved' | 'closed'
 * @param {number} [limit=50]
 * @param {number} [offset=0]
 */
export function listDisputes(agentId, status = null, limit = 50, offset = 0) {
  try {
    const conditions = ['agent_id = ?'];
    const params = [agentId];

    if (status) {
      conditions.push('status = ?');
      params.push(status);
    }

    const where = `WHERE ${conditions.join(' AND ')}`;

    const total = db.prepare(`SELECT COUNT(*) as n FROM disputes ${where}`).get(...params).n;
    const rows  = db.prepare(`
      SELECT * FROM disputes ${where} ORDER BY filed_at DESC LIMIT ? OFFSET ?
    `).all(...params, limit, offset);

    return {
      success: true,
      disputes: rows.map(deserializeDispute),
      total,
    };
  } catch (err) {
    console.error('[disputes] listDisputes failed:', err.message);
    return { success: false, error: err.message };
  }
}

// ─── Serialization Helper ─────────────────────────────────────

function deserializeDispute(row) {
  if (!row) return null;
  return {
    ...row,
    evidence: JSON.parse(row.evidence || '{}'),
  };
}
