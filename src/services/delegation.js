/**
 * HiveTrust — Spend Delegation Service
 * ZK-Spend Delegation Trees: scoped, revocable spending budgets.
 *
 * An agent (grantee) can be delegated to spend up to a capped USDC budget
 * on a scoped set of categories, subject to per-tx limits, vendor allow/block
 * lists, and optional compliance proof requirements.
 *
 * Every authorized spend AND every denied attempt is recorded immutably.
 */

import { createHash, randomBytes } from 'crypto';
import db from '../db.js';
import * as audit from './audit.js';

// ─── Helpers ────────────────────────────────────────────────

function delegationHash(params) {
  const canonical = JSON.stringify({
    grantor_did: params.grantor_did,
    grantee_did: params.grantee_did,
    budget_usdc: params.budget_usdc,
    scope: (params.scope || []).slice().sort(),
    restrictions: params.restrictions || {},
    expires_at: params.expires_at || null,
  });
  return createHash('sha256').update(canonical).digest('hex');
}

function txHash(params) {
  const canonical = JSON.stringify({
    delegation_id: params.delegation_id,
    amount_usdc: params.amount_usdc,
    vendor: params.vendor || null,
    category: params.category || null,
    tx_description: params.tx_description || null,
    compliance_proof_hash: params.compliance_proof_hash || null,
    nonce: randomBytes(16).toString('hex'),
    timestamp: new Date().toISOString(),
  });
  return createHash('sha256').update(canonical).digest('hex');
}

function parseJson(val, fallback) {
  if (val == null) return fallback;
  if (typeof val === 'object') return val;
  try { return JSON.parse(val); } catch { return fallback; }
}

function formatDelegation(row) {
  if (!row) return null;
  return {
    ...row,
    scope: parseJson(row.scope, []),
    restrictions: parseJson(row.restrictions, {}),
    remaining_usdc: +(row.budget_usdc - row.spent_usdc).toFixed(4),
  };
}

// ─── Create ─────────────────────────────────────────────────

export function createDelegation({ grantor_did, grantee_did, budget_usdc, scope, expires_at, restrictions }) {
  if (!grantor_did || !grantee_did) throw Object.assign(new Error('grantor_did and grantee_did are required'), { status: 400 });
  if (!budget_usdc || budget_usdc <= 0) throw Object.assign(new Error('budget_usdc must be positive'), { status: 400 });
  if (grantor_did === grantee_did) throw Object.assign(new Error('grantor and grantee must be different DIDs'), { status: 400 });

  const hash = delegationHash({ grantor_did, grantee_did, budget_usdc, scope, restrictions, expires_at });

  const existing = db.prepare('SELECT id FROM spend_delegations WHERE delegation_hash = ?').get(hash);
  if (existing) throw Object.assign(new Error('Duplicate delegation — identical parameters already exist'), { status: 409 });

  const id = 'del_' + randomBytes(8).toString('hex');
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO spend_delegations
      (id, delegation_hash, grantor_did, grantee_did, budget_usdc, spent_usdc, scope, restrictions, status, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, 0, ?, ?, 'active', ?, ?)
  `).run(
    id, hash, grantor_did, grantee_did, budget_usdc,
    JSON.stringify(scope || []),
    JSON.stringify(restrictions || {}),
    now, expires_at || null
  );

  audit.log(grantor_did, 'agent', 'delegation.create', 'spend_delegation', id, {
    grantee_did, budget_usdc, scope, restrictions, expires_at,
  });

  const row = db.prepare('SELECT * FROM spend_delegations WHERE id = ?').get(id);
  return formatDelegation(row);
}

// ─── Authorize Spend ────────────────────────────────────────

/**
 * Atomic check-and-deduct. Uses a SQLite transaction to prevent races.
 */
export function authorizeSpend({ delegation_id, amount_usdc, vendor, category, tx_description, compliance_proof_hash }) {
  if (!delegation_id) throw Object.assign(new Error('delegation_id is required'), { status: 400 });
  if (!amount_usdc || amount_usdc <= 0) throw Object.assign(new Error('amount_usdc must be positive'), { status: 400 });

  const hash = txHash({ delegation_id, amount_usdc, vendor, category, tx_description, compliance_proof_hash });

  // Run inside a transaction for atomicity
  const result = db.transaction(() => {
    const del = db.prepare('SELECT * FROM spend_delegations WHERE id = ?').get(delegation_id);
    if (!del) return { authorized: false, reason: 'Delegation not found', tx_hash: hash };

    const scope = parseJson(del.scope, []);
    const restrictions = parseJson(del.restrictions, {});
    const remaining = +(del.budget_usdc - del.spent_usdc).toFixed(4);

    // Status checks
    if (del.status === 'revoked') return deny('Delegation has been revoked');
    if (del.status === 'exhausted') return deny('Delegation budget exhausted');
    if (del.status === 'expired') return deny('Delegation has expired');
    if (del.status !== 'active') return deny(`Delegation status is ${del.status}`);

    // Expiration check
    if (del.expires_at && new Date(del.expires_at) < new Date()) {
      db.prepare('UPDATE spend_delegations SET status = ? WHERE id = ?').run('expired', delegation_id);
      return deny('Delegation has expired');
    }

    // Budget check
    if (amount_usdc > remaining) {
      return deny(`Insufficient budget: requested ${amount_usdc} USDC but only ${remaining} USDC remaining`);
    }

    // Scope check
    if (scope.length > 0 && category) {
      if (!scope.includes(category)) {
        return deny(`Category "${category}" is not in delegation scope [${scope.join(', ')}]`);
      }
    } else if (scope.length > 0 && !category) {
      return deny('Category is required when delegation has a scoped budget');
    }

    // Max single tx check
    if (restrictions.max_single_tx_usdc && amount_usdc > restrictions.max_single_tx_usdc) {
      return deny(`Amount ${amount_usdc} USDC exceeds max single transaction limit of ${restrictions.max_single_tx_usdc} USDC`);
    }

    // Vendor block/allow list (check blocked first for specific feedback)
    if (vendor) {
      if (restrictions.blocked_vendors?.length && restrictions.blocked_vendors.includes(vendor)) {
        return deny(`Vendor "${vendor}" is blocked`);
      }
      if (restrictions.allowed_vendors?.length && !restrictions.allowed_vendors.includes(vendor)) {
        return deny(`Vendor "${vendor}" is not in the allowed vendors list`);
      }
    }

    // Compliance proof requirement
    if (restrictions.require_compliance_proof && !compliance_proof_hash) {
      return deny('Compliance proof hash is required for this delegation');
    }

    // All checks passed — deduct atomically
    const newSpent = +(del.spent_usdc + amount_usdc).toFixed(4);
    const newRemaining = +(del.budget_usdc - newSpent).toFixed(4);
    const newStatus = newRemaining <= 0 ? 'exhausted' : 'active';

    db.prepare('UPDATE spend_delegations SET spent_usdc = ?, status = ? WHERE id = ?')
      .run(newSpent, newStatus, delegation_id);

    // Record authorized transaction
    const txId = 'dtx_' + randomBytes(8).toString('hex');
    db.prepare(`
      INSERT INTO delegation_transactions
        (id, delegation_id, tx_hash, amount_usdc, vendor, category, tx_description, compliance_proof_hash, authorized)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
    `).run(txId, delegation_id, hash, amount_usdc, vendor || null, category || null, tx_description || null, compliance_proof_hash || null);

    return {
      authorized: true,
      reason: 'Spend authorized',
      delegation_id,
      amount_usdc,
      remaining_budget_usdc: newRemaining,
      tx_id: txId,
      tx_hash: hash,
    };

    function deny(reason) {
      // Record denied attempt
      const txId = 'dtx_' + randomBytes(8).toString('hex');
      db.prepare(`
        INSERT INTO delegation_transactions
          (id, delegation_id, tx_hash, amount_usdc, vendor, category, tx_description, compliance_proof_hash, authorized, denial_reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
      `).run(txId, delegation_id, hash, amount_usdc, vendor || null, category || null, tx_description || null, compliance_proof_hash || null, reason);

      return {
        authorized: false,
        reason,
        delegation_id,
        amount_usdc,
        remaining_budget_usdc: remaining,
        tx_id: txId,
        tx_hash: hash,
      };
    }
  })();

  // Audit log (outside transaction — non-fatal)
  audit.log(
    delegation_id, 'system',
    result.authorized ? 'delegation.spend.authorized' : 'delegation.spend.denied',
    'delegation_transaction', result.tx_id,
    { amount_usdc, vendor, category, authorized: result.authorized, reason: result.reason }
  );

  return result;
}

// ─── Revoke ─────────────────────────────────────────────────

export function revokeDelegation({ delegation_id, grantor_did, reason }) {
  if (!delegation_id) throw Object.assign(new Error('delegation_id is required'), { status: 400 });
  if (!grantor_did) throw Object.assign(new Error('grantor_did is required'), { status: 400 });

  const del = db.prepare('SELECT * FROM spend_delegations WHERE id = ?').get(delegation_id);
  if (!del) throw Object.assign(new Error('Delegation not found'), { status: 404 });
  if (del.grantor_did !== grantor_did) throw Object.assign(new Error('Only the grantor can revoke a delegation'), { status: 403 });
  if (del.status === 'revoked') throw Object.assign(new Error('Delegation is already revoked'), { status: 409 });

  const now = new Date().toISOString();
  db.prepare('UPDATE spend_delegations SET status = ?, revoked_reason = ?, revoked_at = ? WHERE id = ?')
    .run('revoked', reason || null, now, delegation_id);

  audit.log(grantor_did, 'agent', 'delegation.revoke', 'spend_delegation', delegation_id, {
    reason, remaining_usdc: +(del.budget_usdc - del.spent_usdc).toFixed(4),
  });

  return {
    delegation_id,
    status: 'revoked',
    revoked_at: now,
    remaining_unspent_usdc: +(del.budget_usdc - del.spent_usdc).toFixed(4),
    reason: reason || null,
  };
}

// ─── Get Delegation ─────────────────────────────────────────

export function getDelegation(id) {
  const del = db.prepare('SELECT * FROM spend_delegations WHERE id = ?').get(id);
  if (!del) return null;

  // Check for expiration on read
  if (del.status === 'active' && del.expires_at && new Date(del.expires_at) < new Date()) {
    db.prepare('UPDATE spend_delegations SET status = ? WHERE id = ?').run('expired', id);
    del.status = 'expired';
  }

  const formatted = formatDelegation(del);

  const transactions = db.prepare(
    'SELECT * FROM delegation_transactions WHERE delegation_id = ? ORDER BY created_at DESC'
  ).all(id);

  formatted.transactions = transactions.map(tx => ({
    ...tx,
    authorized: !!tx.authorized,
  }));

  return formatted;
}

// ─── Get Delegations for Agent ──────────────────────────────

export function getDelegationsForAgent(did) {
  if (!did) throw Object.assign(new Error('DID is required'), { status: 400 });

  const rows = db.prepare(
    'SELECT * FROM spend_delegations WHERE grantor_did = ? OR grantee_did = ? ORDER BY created_at DESC'
  ).all(did, did);

  return rows.map(row => {
    // Check for expiration on read
    if (row.status === 'active' && row.expires_at && new Date(row.expires_at) < new Date()) {
      db.prepare('UPDATE spend_delegations SET status = ? WHERE id = ?').run('expired', row.id);
      row.status = 'expired';
    }
    return formatDelegation(row);
  });
}

// ─── Audit Trail ────────────────────────────────────────────

export function getAuditTrail(delegation_id) {
  if (!delegation_id) throw Object.assign(new Error('delegation_id is required'), { status: 400 });

  const del = db.prepare('SELECT * FROM spend_delegations WHERE id = ?').get(delegation_id);
  if (!del) throw Object.assign(new Error('Delegation not found'), { status: 404 });

  const transactions = db.prepare(
    'SELECT * FROM delegation_transactions WHERE delegation_id = ? ORDER BY created_at ASC'
  ).all(delegation_id);

  const auditEntries = audit.query({
    resourceType: 'spend_delegation',
    resourceId: delegation_id,
    limit: 500,
  });

  const txAuditEntries = audit.query({
    actionPrefix: 'delegation.spend',
    limit: 500,
  });

  // Filter tx audit entries to this delegation
  const relevantTxAudit = (txAuditEntries.entries || []).filter(e => {
    try {
      const details = typeof e.details === 'string' ? JSON.parse(e.details) : e.details;
      return true; // already filtered by actionPrefix
    } catch { return false; }
  });

  return {
    delegation: formatDelegation(del),
    transactions: transactions.map(tx => ({
      ...tx,
      authorized: !!tx.authorized,
    })),
    authorized_count: transactions.filter(tx => tx.authorized).length,
    denied_count: transactions.filter(tx => !tx.authorized).length,
    total_spent_usdc: del.spent_usdc,
    remaining_usdc: +(del.budget_usdc - del.spent_usdc).toFixed(4),
    audit_log: auditEntries.entries || [],
  };
}
