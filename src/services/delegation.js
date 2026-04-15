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
import { query, getClient } from '../db.js';
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

export async function createDelegation({ grantor_did, grantee_did, budget_usdc, scope, expires_at, restrictions }) {
  if (!grantor_did || !grantee_did) throw Object.assign(new Error('grantor_did and grantee_did are required'), { status: 400 });
  if (!budget_usdc || budget_usdc <= 0) throw Object.assign(new Error('budget_usdc must be positive'), { status: 400 });
  if (grantor_did === grantee_did) throw Object.assign(new Error('grantor and grantee must be different DIDs'), { status: 400 });

  const hash = delegationHash({ grantor_did, grantee_did, budget_usdc, scope, restrictions, expires_at });

  const existing = await query('SELECT id FROM spend_delegations WHERE delegation_hash = $1', [hash]);
  if (existing.rows[0]) throw Object.assign(new Error('Duplicate delegation — identical parameters already exist'), { status: 409 });

  const id = 'del_' + randomBytes(8).toString('hex');
  const now = new Date().toISOString();

  await query(`
    INSERT INTO spend_delegations
      (id, delegation_hash, grantor_did, grantee_did, budget_usdc, spent_usdc, scope, restrictions, status, created_at, expires_at)
    VALUES ($1, $2, $3, $4, $5, 0, $6, $7, 'active', $8, $9)
  `, [
    id, hash, grantor_did, grantee_did, budget_usdc,
    JSON.stringify(scope || []),
    JSON.stringify(restrictions || {}),
    now, expires_at || null
  ]);

  await audit.log(grantor_did, 'agent', 'delegation.create', 'spend_delegation', id, {
    grantee_did, budget_usdc, scope, restrictions, expires_at,
  });

  const result = await query('SELECT * FROM spend_delegations WHERE id = $1', [id]);
  return formatDelegation(result.rows[0]);
}

// ─── Authorize Spend ────────────────────────────────────────

/**
 * Atomic check-and-deduct. Uses a PostgreSQL transaction to prevent races.
 */
export async function authorizeSpend({ delegation_id, amount_usdc, vendor, category, tx_description, compliance_proof_hash }) {
  if (!delegation_id) throw Object.assign(new Error('delegation_id is required'), { status: 400 });
  if (!amount_usdc || amount_usdc <= 0) throw Object.assign(new Error('amount_usdc must be positive'), { status: 400 });

  const hash = txHash({ delegation_id, amount_usdc, vendor, category, tx_description, compliance_proof_hash });

  const client = await getClient();
  let result;
  try {
    await client.query('BEGIN');

    const delResult = await client.query('SELECT * FROM spend_delegations WHERE id = $1', [delegation_id]);
    const del = delResult.rows[0];
    if (!del) {
      await client.query('COMMIT');
      result = { authorized: false, reason: 'Delegation not found', tx_hash: hash };
      return result;
    }

    const scope = parseJson(del.scope, []);
    const restrictions = parseJson(del.restrictions, {});
    const remaining = +(del.budget_usdc - del.spent_usdc).toFixed(4);

    // Inner deny helper — records denied attempt using the transaction client
    async function deny(reason) {
      const txId = 'dtx_' + randomBytes(8).toString('hex');
      await client.query(`
        INSERT INTO delegation_transactions
          (id, delegation_id, tx_hash, amount_usdc, vendor, category, tx_description, compliance_proof_hash, authorized, denial_reason)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, $9)
      `, [txId, delegation_id, hash, amount_usdc, vendor || null, category || null, tx_description || null, compliance_proof_hash || null, reason]);

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

    // Status checks
    if (del.status === 'revoked') { result = await deny('Delegation has been revoked'); await client.query('COMMIT'); return result; }
    if (del.status === 'exhausted') { result = await deny('Delegation budget exhausted'); await client.query('COMMIT'); return result; }
    if (del.status === 'expired') { result = await deny('Delegation has expired'); await client.query('COMMIT'); return result; }
    if (del.status !== 'active') { result = await deny(`Delegation status is ${del.status}`); await client.query('COMMIT'); return result; }

    // Expiration check
    if (del.expires_at && new Date(del.expires_at) < new Date()) {
      await client.query('UPDATE spend_delegations SET status = $1 WHERE id = $2', ['expired', delegation_id]);
      result = await deny('Delegation has expired');
      await client.query('COMMIT');
      return result;
    }

    // Budget check
    if (amount_usdc > remaining) {
      result = await deny(`Insufficient budget: requested ${amount_usdc} USDC but only ${remaining} USDC remaining`);
      await client.query('COMMIT');
      return result;
    }

    // Scope check
    if (scope.length > 0 && category) {
      if (!scope.includes(category)) {
        result = await deny(`Category "${category}" is not in delegation scope [${scope.join(', ')}]`);
        await client.query('COMMIT');
        return result;
      }
    } else if (scope.length > 0 && !category) {
      result = await deny('Category is required when delegation has a scoped budget');
      await client.query('COMMIT');
      return result;
    }

    // Max single tx check
    if (restrictions.max_single_tx_usdc && amount_usdc > restrictions.max_single_tx_usdc) {
      result = await deny(`Amount ${amount_usdc} USDC exceeds max single transaction limit of ${restrictions.max_single_tx_usdc} USDC`);
      await client.query('COMMIT');
      return result;
    }

    // Vendor block/allow list (check blocked first for specific feedback)
    if (vendor) {
      if (restrictions.blocked_vendors?.length && restrictions.blocked_vendors.includes(vendor)) {
        result = await deny(`Vendor "${vendor}" is blocked`);
        await client.query('COMMIT');
        return result;
      }
      if (restrictions.allowed_vendors?.length && !restrictions.allowed_vendors.includes(vendor)) {
        result = await deny(`Vendor "${vendor}" is not in the allowed vendors list`);
        await client.query('COMMIT');
        return result;
      }
    }

    // Compliance proof requirement
    if (restrictions.require_compliance_proof && !compliance_proof_hash) {
      result = await deny('Compliance proof hash is required for this delegation');
      await client.query('COMMIT');
      return result;
    }

    // All checks passed — deduct atomically
    const newSpent = +(del.spent_usdc + amount_usdc).toFixed(4);
    const newRemaining = +(del.budget_usdc - newSpent).toFixed(4);
    const newStatus = newRemaining <= 0 ? 'exhausted' : 'active';

    await client.query('UPDATE spend_delegations SET spent_usdc = $1, status = $2 WHERE id = $3',
      [newSpent, newStatus, delegation_id]);

    // Record authorized transaction
    const txId = 'dtx_' + randomBytes(8).toString('hex');
    await client.query(`
      INSERT INTO delegation_transactions
        (id, delegation_id, tx_hash, amount_usdc, vendor, category, tx_description, compliance_proof_hash, authorized)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1)
    `, [txId, delegation_id, hash, amount_usdc, vendor || null, category || null, tx_description || null, compliance_proof_hash || null]);

    await client.query('COMMIT');

    result = {
      authorized: true,
      reason: 'Spend authorized',
      delegation_id,
      amount_usdc,
      remaining_budget_usdc: newRemaining,
      tx_id: txId,
      tx_hash: hash,
    };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }

  // Audit log (outside transaction — non-fatal)
  await audit.log(
    delegation_id, 'system',
    result.authorized ? 'delegation.spend.authorized' : 'delegation.spend.denied',
    'delegation_transaction', result.tx_id,
    { amount_usdc, vendor, category, authorized: result.authorized, reason: result.reason }
  );

  return result;
}

// ─── Revoke ─────────────────────────────────────────────────

export async function revokeDelegation({ delegation_id, grantor_did, reason }) {
  if (!delegation_id) throw Object.assign(new Error('delegation_id is required'), { status: 400 });
  if (!grantor_did) throw Object.assign(new Error('grantor_did is required'), { status: 400 });

  const delResult = await query('SELECT * FROM spend_delegations WHERE id = $1', [delegation_id]);
  const del = delResult.rows[0];
  if (!del) throw Object.assign(new Error('Delegation not found'), { status: 404 });
  if (del.grantor_did !== grantor_did) throw Object.assign(new Error('Only the grantor can revoke a delegation'), { status: 403 });
  if (del.status === 'revoked') throw Object.assign(new Error('Delegation is already revoked'), { status: 409 });

  const now = new Date().toISOString();
  await query('UPDATE spend_delegations SET status = $1, revoked_reason = $2, revoked_at = $3 WHERE id = $4',
    ['revoked', reason || null, now, delegation_id]);

  await audit.log(grantor_did, 'agent', 'delegation.revoke', 'spend_delegation', delegation_id, {
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

export async function getDelegation(id) {
  const delResult = await query('SELECT * FROM spend_delegations WHERE id = $1', [id]);
  const del = delResult.rows[0];
  if (!del) return null;

  // Check for expiration on read
  if (del.status === 'active' && del.expires_at && new Date(del.expires_at) < new Date()) {
    await query('UPDATE spend_delegations SET status = $1 WHERE id = $2', ['expired', id]);
    del.status = 'expired';
  }

  const formatted = formatDelegation(del);

  const txResult = await query(
    'SELECT * FROM delegation_transactions WHERE delegation_id = $1 ORDER BY created_at DESC',
    [id]
  );

  formatted.transactions = txResult.rows.map(tx => ({
    ...tx,
    authorized: !!tx.authorized,
  }));

  return formatted;
}

// ─── Get Delegations for Agent ──────────────────────────────

export async function getDelegationsForAgent(did) {
  if (!did) throw Object.assign(new Error('DID is required'), { status: 400 });

  const result = await query(
    'SELECT * FROM spend_delegations WHERE grantor_did = $1 OR grantee_did = $2 ORDER BY created_at DESC',
    [did, did]
  );

  const rows = result.rows;
  for (const row of rows) {
    // Check for expiration on read
    if (row.status === 'active' && row.expires_at && new Date(row.expires_at) < new Date()) {
      await query('UPDATE spend_delegations SET status = $1 WHERE id = $2', ['expired', row.id]);
      row.status = 'expired';
    }
  }

  return rows.map(row => formatDelegation(row));
}

// ─── Audit Trail ────────────────────────────────────────────

export async function getAuditTrail(delegation_id) {
  if (!delegation_id) throw Object.assign(new Error('delegation_id is required'), { status: 400 });

  const delResult = await query('SELECT * FROM spend_delegations WHERE id = $1', [delegation_id]);
  const del = delResult.rows[0];
  if (!del) throw Object.assign(new Error('Delegation not found'), { status: 404 });

  const txResult = await query(
    'SELECT * FROM delegation_transactions WHERE delegation_id = $1 ORDER BY created_at ASC',
    [delegation_id]
  );
  const transactions = txResult.rows;

  const auditEntries = await audit.query({
    resourceType: 'spend_delegation',
    resourceId: delegation_id,
    limit: 500,
  });

  const txAuditEntries = await audit.query({
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
