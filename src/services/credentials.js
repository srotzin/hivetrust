/**
 * HiveTrust — Verifiable Credential Service
 * W3C VC-compatible credential issuance, verification, and revocation.
 *
 * Credential types:
 *  - identity_verification
 *  - capability_attestation
 *  - compliance_certification
 *  - performance_badge
 *  - insurance_bond
 */

import { query } from '../db.js';
import { v4 as uuidv4 } from 'uuid';
import { createHash } from 'crypto';
import * as audit from './audit.js';

const VALID_TYPES = new Set([
  'identity_verification',
  'capability_attestation',
  'compliance_certification',
  'performance_badge',
  'insurance_bond',
]);

// ─── Issue ────────────────────────────────────────────────────

/**
 * Issue a new Verifiable Credential to an agent.
 *
 * @param {string}  agentId
 * @param {string}  credentialType
 * @param {string}  issuerId
 * @param {object}  claims         - Domain-specific claims object
 * @param {string}  [expiresAt]    - ISO 8601 expiry datetime
 * @param {object}  [metadata]
 * @returns {Promise<{ success: boolean, credential?: object, error?: string }>}
 */
export async function issueCredential(agentId, credentialType, issuerId, claims = {}, expiresAt = null, metadata = {}) {
  try {
    if (!VALID_TYPES.has(credentialType)) {
      return { success: false, error: `Invalid credential type. Allowed: ${[...VALID_TYPES].join(', ')}` };
    }

    const agentResult = await query('SELECT id, did, status FROM agents WHERE id = $1', [agentId]);
    const agent = agentResult.rows[0];
    if (!agent) return { success: false, error: 'Agent not found' };
    if (agent.status !== 'active') return { success: false, error: 'Cannot issue credential to inactive agent' };

    const id = uuidv4();
    const now = new Date().toISOString();

    // Build W3C VC-compatible subject
    const subject = JSON.stringify({
      id: agent.did || `did:hive:${agentId}`,
      ...claims,
    });

    // Simple proof: SHA-256 hash of (credentialId + issuerId + claims) acting as integrity seal
    const proofHash = createHash('sha256')
      .update(`${id}:${issuerId}:${JSON.stringify(claims)}`)
      .digest('hex');

    const proof = JSON.stringify({
      type: 'Ed25519Signature2020',
      created: now,
      verificationMethod: `did:hive:${issuerId}#key-1`,
      proofPurpose: 'assertionMethod',
      proofValue: proofHash,
    });

    await query(`
      INSERT INTO credentials (
        id, agent_id, credential_type, issuer_id, issuer_did,
        subject, claims, proof, proof_type,
        status, issued_at, expires_at, metadata
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'Ed25519Signature2020', 'active', NOW()::TEXT, $9, $10)
    `, [
      id, agentId, credentialType, issuerId,
      `did:hive:${issuerId}`,
      subject,
      JSON.stringify(claims),
      proof,
      expiresAt || null,
      JSON.stringify(metadata)
    ]);

    await audit.log(issuerId, 'system', 'credential.issue', 'credential', id,
      { agentId, credentialType, expiresAt });

    const result = await query('SELECT * FROM credentials WHERE id = $1', [id]);
    return { success: true, credential: deserializeCredential(result.rows[0]) };
  } catch (err) {
    console.error('[credentials] issueCredential failed:', err.message);
    return { success: false, error: err.message };
  }
}

// ─── Verify ───────────────────────────────────────────────────

/**
 * Verify a credential — checks existence, expiry, and revocation status.
 *
 * @param {string} credentialId
 * @returns {Promise<{ success: boolean, valid?: boolean, credential?: object, reason?: string, error?: string }>}
 */
export async function verifyCredential(credentialId) {
  try {
    const result = await query('SELECT * FROM credentials WHERE id = $1', [credentialId]);
    const row = result.rows[0];
    if (!row) return { success: false, error: 'Credential not found' };

    const cred = deserializeCredential(row);

    // Check revocation
    if (cred.status === 'revoked') {
      return {
        success: true,
        valid: false,
        credential: cred,
        reason: `Credential was revoked at ${cred.revoked_at}: ${cred.revocation_reason || 'no reason given'}`,
      };
    }

    // Check expiry
    if (cred.expires_at && new Date(cred.expires_at) < new Date()) {
      return {
        success: true,
        valid: false,
        credential: cred,
        reason: `Credential expired at ${cred.expires_at}`,
      };
    }

    // Cross-check revocation registry
    const revResult = await query('SELECT * FROM revocation_registry WHERE credential_id = $1', [credentialId]);
    const revEntry = revResult.rows[0];
    if (revEntry) {
      return {
        success: true,
        valid: false,
        credential: cred,
        reason: `Found in revocation registry: ${revEntry.reason}`,
      };
    }

    await audit.log('system', 'system', 'credential.verify', 'credential', credentialId, { valid: true });

    return { success: true, valid: true, credential: cred };
  } catch (err) {
    console.error('[credentials] verifyCredential failed:', err.message);
    return { success: false, error: err.message };
  }
}

// ─── Revoke ───────────────────────────────────────────────────

/**
 * Revoke a credential and add it to the revocation registry.
 *
 * @param {string} credentialId
 * @param {string} revokedBy      - Actor performing the revocation
 * @param {string} reason         - Human-readable reason
 * @param {object} [evidence]     - Supporting evidence
 * @returns {Promise<{ success: boolean, registryId?: string, error?: string }>}
 */
export async function revokeCredential(credentialId, revokedBy, reason, evidence = {}) {
  try {
    const result = await query('SELECT * FROM credentials WHERE id = $1', [credentialId]);
    const row = result.rows[0];
    if (!row) return { success: false, error: 'Credential not found' };
    if (row.status === 'revoked') return { success: false, error: 'Credential is already revoked' };

    const now = new Date().toISOString();

    await query(`
      UPDATE credentials SET status = 'revoked', revoked_at = $1, revocation_reason = $2 WHERE id = $3
    `, [now, reason, credentialId]);

    const registryId = uuidv4();
    await query(`
      INSERT INTO revocation_registry (id, credential_id, revoked_by, reason, evidence, revoked_at)
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [registryId, credentialId, revokedBy, reason, JSON.stringify(evidence), now]);

    await audit.log(revokedBy, 'user', 'credential.revoke', 'credential', credentialId,
      { reason, registryId });

    return { success: true, registryId, revokedAt: now };
  } catch (err) {
    console.error('[credentials] revokeCredential failed:', err.message);
    return { success: false, error: err.message };
  }
}

// ─── List ─────────────────────────────────────────────────────

/**
 * List credentials for an agent.
 *
 * @param {string} agentId
 * @param {string} [status]  - 'active' | 'revoked' | 'expired' | undefined (all)
 * @returns {Promise<{ success: boolean, credentials?: object[], error?: string }>}
 */
export async function listCredentials(agentId, status = null) {
  try {
    let sql = 'SELECT * FROM credentials WHERE agent_id = $1';
    const params = [agentId];

    if (status) {
      sql += ' AND status = $2';
      params.push(status);
    }

    sql += ' ORDER BY issued_at DESC';

    const result = await query(sql, params);
    return {
      success: true,
      credentials: result.rows.map(deserializeCredential),
    };
  } catch (err) {
    console.error('[credentials] listCredentials failed:', err.message);
    return { success: false, error: err.message };
  }
}

// ─── Serialization Helper ─────────────────────────────────────

function deserializeCredential(row) {
  if (!row) return null;
  return {
    ...row,
    claims: JSON.parse(row.claims || '{}'),
    subject: JSON.parse(row.subject || '{}'),
    proof: row.proof ? JSON.parse(row.proof) : null,
    metadata: JSON.parse(row.metadata || '{}'),
  };
}
