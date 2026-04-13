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

import db from '../db.js';
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
 * @returns {{ success: boolean, credential?: object, error?: string }}
 */
export function issueCredential(agentId, credentialType, issuerId, claims = {}, expiresAt = null, metadata = {}) {
  try {
    if (!VALID_TYPES.has(credentialType)) {
      return { success: false, error: `Invalid credential type. Allowed: ${[...VALID_TYPES].join(', ')}` };
    }

    const agent = db.prepare('SELECT id, did, status FROM agents WHERE id = ?').get(agentId);
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

    db.prepare(`
      INSERT INTO credentials (
        id, agent_id, credential_type, issuer_id, issuer_did,
        subject, claims, proof, proof_type,
        status, issued_at, expires_at, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Ed25519Signature2020', 'active', datetime('now'), ?, ?)
    `).run(
      id, agentId, credentialType, issuerId,
      `did:hive:${issuerId}`,
      subject,
      JSON.stringify(claims),
      proof,
      expiresAt || null,
      JSON.stringify(metadata)
    );

    audit.log(issuerId, 'system', 'credential.issue', 'credential', id,
      { agentId, credentialType, expiresAt });

    const row = db.prepare('SELECT * FROM credentials WHERE id = ?').get(id);
    return { success: true, credential: deserializeCredential(row) };
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
 * @returns {{ success: boolean, valid?: boolean, credential?: object, reason?: string, error?: string }}
 */
export function verifyCredential(credentialId) {
  try {
    const row = db.prepare('SELECT * FROM credentials WHERE id = ?').get(credentialId);
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
    const revEntry = db.prepare('SELECT * FROM revocation_registry WHERE credential_id = ?').get(credentialId);
    if (revEntry) {
      return {
        success: true,
        valid: false,
        credential: cred,
        reason: `Found in revocation registry: ${revEntry.reason}`,
      };
    }

    audit.log('system', 'system', 'credential.verify', 'credential', credentialId, { valid: true });

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
 * @returns {{ success: boolean, registryId?: string, error?: string }}
 */
export function revokeCredential(credentialId, revokedBy, reason, evidence = {}) {
  try {
    const row = db.prepare('SELECT * FROM credentials WHERE id = ?').get(credentialId);
    if (!row) return { success: false, error: 'Credential not found' };
    if (row.status === 'revoked') return { success: false, error: 'Credential is already revoked' };

    const now = new Date().toISOString();

    db.prepare(`
      UPDATE credentials SET status = 'revoked', revoked_at = ?, revocation_reason = ? WHERE id = ?
    `).run(now, reason, credentialId);

    const registryId = uuidv4();
    db.prepare(`
      INSERT INTO revocation_registry (id, credential_id, revoked_by, reason, evidence, revoked_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(registryId, credentialId, revokedBy, reason, JSON.stringify(evidence), now);

    audit.log(revokedBy, 'user', 'credential.revoke', 'credential', credentialId,
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
 * @returns {{ success: boolean, credentials?: object[], error?: string }}
 */
export function listCredentials(agentId, status = null) {
  try {
    let query = 'SELECT * FROM credentials WHERE agent_id = ?';
    const params = [agentId];

    if (status) {
      query += ' AND status = ?';
      params.push(status);
    }

    query += ' ORDER BY issued_at DESC';

    const rows = db.prepare(query).all(...params);
    return {
      success: true,
      credentials: rows.map(deserializeCredential),
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
