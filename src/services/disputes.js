/**
 * HiveTrust — Dispute & Appeal Service
 *
 * Dispute types:
 *  - score_correction      : agent disputes their trust score
 *  - credential_challenge  : dispute against an issued credential
 *  - claim_dispute         : dispute an insurance claim decision
 *  - identity_dispute      : dispute an identity assertion
 */

import { query } from '../db.js';
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
export async function fileDispute(agentId, disputeType, targetType, targetId, reason, evidence = {}, ipAddress = null) {
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

    const agentResult = await query('SELECT id, status FROM agents WHERE id = $1', [agentId]);
    if (!agentResult.rows[0]) return { success: false, error: 'Agent not found' };

    // Check for duplicate open dispute on same target
    const existingResult = await query(
      "SELECT id FROM disputes WHERE agent_id = $1 AND target_id = $2 AND status = 'open'",
      [agentId, targetId]
    );
    if (existingResult.rows[0]) {
      return { success: false, error: 'An open dispute already exists for this target', disputeId: existingResult.rows[0].id };
    }

    const id = uuidv4();

    await query(`
      INSERT INTO disputes (
        id, agent_id, dispute_type,
        target_type, target_id,
        reason, evidence,
        status, filed_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'open', NOW()::TEXT)
    `, [
      id, agentId, disputeType,
      targetType, targetId,
      reason.trim(), JSON.stringify(evidence)
    ]);

    await audit.log(agentId, 'agent', 'dispute.file', 'dispute', id,
      { disputeType, targetType, targetId }, ipAddress);

    const rowResult = await query('SELECT * FROM disputes WHERE id = $1', [id]);
    return { success: true, dispute: deserializeDispute(rowResult.rows[0]) };
  } catch (err) {
    console.error('[disputes] fileDispute failed:', err.message);
    return { success: false, error: err.message };
  }
}

// ─── Get Dispute ──────────────────────────────────────────────

/**
 * Get a single dispute by ID.
 */
export async function getDispute(disputeId) {
  try {
    const result = await query('SELECT * FROM disputes WHERE id = $1', [disputeId]);
    if (!result.rows[0]) return { success: false, error: 'Dispute not found' };
    return { success: true, dispute: deserializeDispute(result.rows[0]) };
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
export async function resolveDispute(disputeId, resolution, resolvedBy, notes = null, ipAddress = null) {
  try {
    const allowed = new Set(['upheld', 'rejected', 'partial']);
    if (!allowed.has(resolution)) {
      return { success: false, error: `Invalid resolution. Allowed: ${[...allowed].join(', ')}` };
    }

    const rowResult = await query('SELECT * FROM disputes WHERE id = $1', [disputeId]);
    const row = rowResult.rows[0];
    if (!row) return { success: false, error: 'Dispute not found' };
    if (row.status !== 'open') return { success: false, error: `Dispute is already ${row.status}` };

    const resolutionText = notes ? `${resolution}: ${notes}` : resolution;

    await query(`
      UPDATE disputes
      SET status = 'resolved', resolution = $1, resolved_by = $2, resolved_at = NOW()::TEXT
      WHERE id = $3
    `, [resolutionText, resolvedBy, disputeId]);

    await audit.log(resolvedBy, 'user', 'dispute.resolve', 'dispute', disputeId,
      { resolution, agentId: row.agent_id }, ipAddress);

    const updatedResult = await query('SELECT * FROM disputes WHERE id = $1', [disputeId]);
    return { success: true, dispute: deserializeDispute(updatedResult.rows[0]) };
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
export async function listDisputes(agentId, status = null, limit = 50, offset = 0) {
  try {
    let paramIdx = 1;
    const conditions = [`agent_id = $${paramIdx++}`];
    const params = [agentId];

    if (status) {
      conditions.push(`status = $${paramIdx++}`);
      params.push(status);
    }

    const where = `WHERE ${conditions.join(' AND ')}`;

    const countResult = await query(`SELECT COUNT(*) as n FROM disputes ${where}`, params);
    const total = parseInt(countResult.rows[0].n, 10);

    const rowsResult = await query(`
      SELECT * FROM disputes ${where} ORDER BY filed_at DESC LIMIT $${paramIdx++} OFFSET $${paramIdx++}
    `, [...params, limit, offset]);

    return {
      success: true,
      disputes: rowsResult.rows.map(deserializeDispute),
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
