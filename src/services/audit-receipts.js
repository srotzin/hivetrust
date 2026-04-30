// HiveAudit — Receipt service.
//
// Substrate of the entire HiveAudit product family. Every settled call
// produces exactly one append-only row in audit_receipts with a
// canonical-JSON SHA-256 plus optional Ed25519 signature.
//
// Downstream consumers (badges, comply, verify, readiness) are read-only
// projections of this table. Nothing else writes here.

import { query } from '../db.js';
import { v4 as uuidv4 } from 'uuid';
import { createHash } from 'crypto';
import { canonicalize, canonicalBytes } from '../lib/canonical.js';
import { issueTicket } from './spectral-issuer.js';

const REQUIRED_FIELDS = ['did', 'request_hash', 'response_hash'];

function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

/**
 * Compute the canonical hash for a receipt. Order-independent.
 * Uses the byte-identical canonicalizer that scored 4/4 against AgentGraph CTEF v0.3.1.
 */
export function canonicalHashOf(receipt) {
  const canon = canonicalBytes({
    did: receipt.did,
    actor_id: receipt.actor_id || null,
    upstream: receipt.upstream || null,
    model: receipt.model || null,
    request_hash: receipt.request_hash,
    response_hash: receipt.response_hash,
    epoch_id: receipt.epoch_id || null,
    sector: receipt.sector || null,
    revenue_usdc: receipt.revenue_usdc || 0,
    settlement_tx: receipt.settlement_tx || null,
    created_at: receipt.created_at,
  });
  return sha256Hex(canon);
}

/**
 * Append a single audit receipt. Append-only — no update, no delete.
 *
 * @param {object} input
 * @param {string} input.did
 * @param {string} input.request_hash    SHA-256 hex of the request body
 * @param {string} input.response_hash   SHA-256 hex of the response body
 * @param {string} [input.actor_id]
 * @param {string} [input.upstream]
 * @param {string} [input.model]
 * @param {string} [input.epoch_id]
 * @param {string} [input.sector]
 * @param {number} [input.revenue_usdc]
 * @param {string} [input.settlement_tx]
 * @param {object} [input.payload]       Full receipt payload (will be JSON-stringified)
 * @param {boolean} [input.sign=true]    Sign with HiveTrust issuer key
 */
export async function appendReceipt(input) {
  for (const f of REQUIRED_FIELDS) {
    if (!input[f]) {
      return { success: false, error: `missing_field:${f}` };
    }
  }

  const receipt_id = uuidv4();
  const created_at = new Date().toISOString();
  const base = {
    receipt_id,
    did: input.did,
    actor_id: input.actor_id || null,
    upstream: input.upstream || null,
    model: input.model || null,
    request_hash: input.request_hash,
    response_hash: input.response_hash,
    epoch_id: input.epoch_id || null,
    sector: input.sector || null,
    revenue_usdc: Number(input.revenue_usdc || 0),
    settlement_tx: input.settlement_tx || null,
    created_at,
  };

  const canonical_hash = canonicalHashOf(base);

  let signature = null;
  let pubkey = null;
  if (input.sign !== false) {
    try {
      // issueTicket signs against the same Ed25519 key advertised at
      // /v1/compliance/pubkey (12de746d...). Best-effort — never block ingress.
      const ticket = await issueTicket({
        to: input.did,
        amount: base.revenue_usdc,
        reason: 'audit_receipt',
        did: input.did,
        regime: 'NORMAL_CYAN',
        exp_sec: 86400,
      });
      if (ticket && ticket.signature) {
        signature = ticket.signature;
        pubkey = ticket.issuer_pubkey || null;
      }
    } catch (err) {
      // Signing failure must not break ingress — receipt still has canonical hash.
      console.warn('[audit-receipts] sign failed:', err.message);
    }
  }

  const payloadStr = JSON.stringify(input.payload || base);

  try {
    await query(`
      INSERT INTO audit_receipts
        (receipt_id, did, actor_id, upstream, model, request_hash, response_hash,
         canonical_hash, signature, pubkey, epoch_id, sector, revenue_usdc,
         settlement_tx, payload, created_at)
      VALUES
        ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
    `, [
      base.receipt_id, base.did, base.actor_id, base.upstream, base.model,
      base.request_hash, base.response_hash, canonical_hash, signature, pubkey,
      base.epoch_id, base.sector, base.revenue_usdc, base.settlement_tx,
      payloadStr, base.created_at,
    ]);
    return {
      success: true,
      receipt_id,
      canonical_hash,
      signature,
      pubkey,
      created_at,
    };
  } catch (err) {
    console.error('[audit-receipts] insert failed:', err.message);
    return { success: false, error: err.message };
  }
}

/**
 * Read receipts for a DID. Default last 100, configurable.
 */
export async function listReceipts({ did, limit = 100, offset = 0, since = null }) {
  if (!did) return { success: false, error: 'missing_did' };
  const safeLimit = Math.min(Math.max(parseInt(limit) || 100, 1), 1000);
  const safeOffset = Math.max(parseInt(offset) || 0, 0);
  try {
    const params = [did];
    let where = 'did = $1';
    if (since) {
      params.push(since);
      where += ` AND created_at >= $${params.length}`;
    }
    params.push(safeLimit, safeOffset);
    const rows = await query(`
      SELECT receipt_id, did, actor_id, upstream, model, request_hash, response_hash,
             canonical_hash, signature, pubkey, epoch_id, sector, revenue_usdc,
             settlement_tx, created_at
      FROM audit_receipts
      WHERE ${where}
      ORDER BY created_at DESC
      LIMIT $${params.length - 1} OFFSET $${params.length}
    `, params);
    return { success: true, receipts: rows.rows, count: rows.rows.length };
  } catch (err) {
    console.error('[audit-receipts] list failed:', err.message);
    return { success: false, error: err.message };
  }
}

/**
 * Aggregate stats for a DID. Used by readiness scoring + badges.
 */
export async function statsForDid(did, windowDays = 30) {
  try {
    const r = await query(`
      SELECT
        COUNT(*)::int          AS total,
        COALESCE(SUM(revenue_usdc), 0)::float AS revenue,
        COUNT(DISTINCT model)::int AS distinct_models,
        COUNT(DISTINCT upstream)::int AS distinct_upstreams,
        MIN(created_at)        AS first_receipt,
        MAX(created_at)        AS last_receipt
      FROM audit_receipts
      WHERE did = $1
        AND created_at >= (NOW() - ($2 || ' days')::interval)::TEXT
    `, [did, windowDays]);
    return { success: true, stats: r.rows[0] };
  } catch (err) {
    return { success: false, error: err.message };
  }
}
