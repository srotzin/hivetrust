/**
 * HiveTrust — Agent Identity Service (KYA)
 * Know Your Agent: registration, checksum computation, DID management,
 * version tracking, and lifecycle operations.
 *
 * Spec references:
 *  - Ed25519 keys (base58), SHA-256 fingerprints
 *  - Agent checksum per IETF A-JWT draft (SHA-256 of system_prompt + tools + model_config)
 *  - DID format: did:hive:{uuid}
 *  - Registration fee: $4.99 USDC
 */

import db from '../db.js';
import { v4 as uuidv4 } from 'uuid';
import { createHash } from 'crypto';
import * as audit from './audit.js';

const REGISTRATION_FEE_USDC = 4.99;

// ─── Helpers ─────────────────────────────────────────────────

/**
 * Compute a SHA-256 fingerprint of a base58 public key.
 */
function computeKeyFingerprint(publicKey) {
  return createHash('sha256').update(publicKey).digest('hex');
}

/**
 * Compute the IETF A-JWT agent checksum.
 * Canonical JSON of { system_prompt, tools, model_config } → SHA-256.
 *
 * @param {object} components
 * @param {string} [components.system_prompt]
 * @param {Array}  [components.tools]
 * @param {object} [components.model_config]
 */
export function computeChecksum(components = {}) {
  const canonical = JSON.stringify({
    system_prompt: components.system_prompt ?? '',
    tools: components.tools ?? [],
    model_config: components.model_config ?? {},
  });
  return createHash('sha256').update(canonical).digest('hex');
}

/**
 * Generate a W3C DID in did:hive:{uuid} format.
 */
function generateDID(agentId) {
  return `did:hive:${agentId}`;
}

/**
 * Bump a semver version string by patch.
 */
function bumpVersion(current = '1.0.0') {
  const parts = current.split('.').map(Number);
  parts[2] = (parts[2] || 0) + 1;
  return parts.join('.');
}

// ─── Registration ─────────────────────────────────────────────

/**
 * Register a new agent.
 *
 * @param {object} params
 * @param {string} params.name
 * @param {string} [params.description]
 * @param {string} params.publicKey           - Ed25519 public key (base58)
 * @param {string} params.ownerId
 * @param {string} [params.ownerType]         - 'organization' | 'individual'
 * @param {string} [params.modelProvider]
 * @param {string} [params.modelName]
 * @param {string} [params.modelVersion]
 * @param {Array}  [params.capabilities]
 * @param {Array}  [params.verticals]
 * @param {string} [params.systemPrompt]      - For checksum computation
 * @param {Array}  [params.tools]             - Tool definitions
 * @param {object} [params.modelConfig]       - Model config object
 * @param {string} [params.euAiActClass]
 * @param {boolean}[params.nistAiRmfAligned]
 * @param {string} [params.hiveagentId]       - Cross-reference to HiveAgent
 * @param {object} [params.metadata]
 * @param {string} [params.ipAddress]
 * @returns {{ success: boolean, agent?: object, error?: string }}
 */
export function registerAgent(params, ipAddress = null) {
  try {
    const {
      name,
      description,
      publicKey,
      ownerId,
      ownerType = 'organization',
      modelProvider,
      modelName,
      modelVersion,
      capabilities = [],
      verticals = [],
      systemPrompt,
      tools = [],
      modelConfig = {},
      euAiActClass = 'minimal_risk',
      nistAiRmfAligned = false,
      hiveagentId,
      metadata = {},
    } = params;

    if (!publicKey) return { success: false, error: 'publicKey is required' };
    if (!ownerId)   return { success: false, error: 'ownerId is required' };

    const keyFingerprint = computeKeyFingerprint(publicKey);

    // Guard: duplicate key
    const existing = db.prepare('SELECT id FROM agents WHERE key_fingerprint = ?').get(keyFingerprint);
    if (existing) {
      return { success: false, error: 'An agent with this public key is already registered', agentId: existing.id };
    }

    const id = uuidv4();
    const did = generateDID(id);
    const checksum = computeChecksum({ system_prompt: systemPrompt, tools, model_config: modelConfig });
    const now = new Date().toISOString();

    // Build minimal DID document
    const didDocument = JSON.stringify({
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: did,
      verificationMethod: [{
        id: `${did}#key-1`,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyBase58: publicKey,
      }],
      authentication: [`${did}#key-1`],
      created: now,
    });

    db.prepare(`
      INSERT INTO agents (
        id, version, name, description,
        public_key, public_key_format, key_fingerprint,
        checksum, checksum_algorithm, checksum_components,
        owner_id, owner_type, owner_verified,
        model_provider, model_name, model_version,
        capabilities, verticals,
        eu_ai_act_class, nist_ai_rmf_aligned,
        trust_tier, trust_score, credit_score,
        status, did, did_document,
        hiveagent_id, metadata,
        created_at, updated_at
      ) VALUES (
        ?, '1.0.0', ?, ?,
        ?, 'ed25519-base58', ?,
        ?, 'sha256', ?,
        ?, ?, 0,
        ?, ?, ?,
        ?, ?,
        ?, ?,
        'provisional', 50.0, 300,
        'active', ?, ?,
        ?, ?,
        datetime('now'), datetime('now')
      )
    `).run(
      id, name || null, description || null,
      publicKey, keyFingerprint,
      checksum, JSON.stringify(['system_prompt', 'tools', 'model_config']),
      ownerId, ownerType,
      modelProvider || null, modelName || null, modelVersion || null,
      JSON.stringify(capabilities), JSON.stringify(verticals),
      euAiActClass, nistAiRmfAligned ? 1 : 0,
      did, didDocument,
      hiveagentId || null, JSON.stringify(metadata)
    );

    // Record initial version
    db.prepare(`
      INSERT INTO agent_versions (id, agent_id, version, checksum, checksum_previous, changes, created_at)
      VALUES (?, ?, '1.0.0', ?, NULL, ?, datetime('now'))
    `).run(uuidv4(), id, checksum, JSON.stringify({ type: 'initial_registration' }));

    audit.log(ownerId, 'user', 'agent.register', 'agent', id,
      { name, keyFingerprint, did, fee_usdc: REGISTRATION_FEE_USDC }, ipAddress);

    const agent = db.prepare('SELECT * FROM agents WHERE id = ?').get(id);
    return { success: true, agent: deserializeAgent(agent), registration_fee_usdc: REGISTRATION_FEE_USDC };
  } catch (err) {
    console.error('[agent-identity] registerAgent failed:', err.message);
    return { success: false, error: err.message };
  }
}

// ─── Lookup ───────────────────────────────────────────────────

/**
 * Get a single agent by ID.
 */
export function getAgent(agentId) {
  try {
    const agent = db.prepare('SELECT * FROM agents WHERE id = ?').get(agentId);
    if (!agent) return { success: false, error: 'Agent not found' };
    return { success: true, agent: deserializeAgent(agent) };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Get agent by DID.
 */
export function getAgentByDID(did) {
  try {
    const agent = db.prepare('SELECT * FROM agents WHERE did = ?').get(did);
    if (!agent) return { success: false, error: 'Agent not found' };
    return { success: true, agent: deserializeAgent(agent) };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Get agent by key fingerprint.
 */
export function getAgentByFingerprint(fingerprint) {
  try {
    const agent = db.prepare('SELECT * FROM agents WHERE key_fingerprint = ?').get(fingerprint);
    if (!agent) return { success: false, error: 'Agent not found' };
    return { success: true, agent: deserializeAgent(agent) };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ─── Update ───────────────────────────────────────────────────

/**
 * Update agent — creates a new version record on each call.
 *
 * @param {string} agentId
 * @param {object} updates  - Subset of agent fields
 * @param {string} [updatedBy]
 * @param {string} [ipAddress]
 */
export function updateAgent(agentId, updates, updatedBy = null, ipAddress = null) {
  try {
    const existing = db.prepare('SELECT * FROM agents WHERE id = ?').get(agentId);
    if (!existing) return { success: false, error: 'Agent not found' };
    if (existing.status === 'deactivated') return { success: false, error: 'Agent is deactivated' };

    const prevChecksum = existing.checksum;
    const newVersion = bumpVersion(existing.version);

    // Recompute checksum if behavioral components changed
    let newChecksum = prevChecksum;
    if (updates.systemPrompt !== undefined || updates.tools !== undefined || updates.modelConfig !== undefined) {
      const prevComponents = JSON.parse(existing.checksum_components || '[]');
      // We need the old component values — reconstruct from metadata or accept provided
      newChecksum = computeChecksum({
        system_prompt: updates.systemPrompt,
        tools: updates.tools ?? [],
        model_config: updates.modelConfig ?? {},
      });
    }

    // Build SET clause dynamically
    const allowed = {
      name: updates.name,
      description: updates.description,
      model_provider: updates.modelProvider,
      model_name: updates.modelName,
      model_version: updates.modelVersion,
      capabilities: updates.capabilities !== undefined ? JSON.stringify(updates.capabilities) : undefined,
      verticals: updates.verticals !== undefined ? JSON.stringify(updates.verticals) : undefined,
      eu_ai_act_class: updates.euAiActClass,
      nist_ai_rmf_aligned: updates.nistAiRmfAligned !== undefined ? (updates.nistAiRmfAligned ? 1 : 0) : undefined,
      metadata: updates.metadata !== undefined ? JSON.stringify(updates.metadata) : undefined,
      authorized_by: updates.authorizedBy,
      delegation_scope: updates.delegationScope !== undefined ? JSON.stringify(updates.delegationScope) : undefined,
      delegation_expires_at: updates.delegationExpiresAt,
      max_transaction_value: updates.maxTransactionValue,
    };

    const setClauses = [];
    const setParams = [];
    for (const [col, val] of Object.entries(allowed)) {
      if (val !== undefined) {
        setClauses.push(`${col} = ?`);
        setParams.push(val);
      }
    }

    // Always bump version, checksum, updated_at
    setClauses.push('version = ?', 'checksum = ?', 'updated_at = datetime(\'now\')');
    setParams.push(newVersion, newChecksum);
    setParams.push(agentId);

    db.prepare(`UPDATE agents SET ${setClauses.join(', ')} WHERE id = ?`).run(...setParams);

    // Record version history
    db.prepare(`
      INSERT INTO agent_versions (id, agent_id, version, checksum, checksum_previous, changes, created_at)
      VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    `).run(
      uuidv4(), agentId, newVersion, newChecksum, prevChecksum,
      JSON.stringify({ ...updates, updated_by: updatedBy })
    );

    audit.log(
      updatedBy || agentId, updatedBy ? 'user' : 'agent',
      'agent.update', 'agent', agentId,
      { version: newVersion, checksum_changed: newChecksum !== prevChecksum },
      ipAddress
    );

    const agent = db.prepare('SELECT * FROM agents WHERE id = ?').get(agentId);
    return { success: true, agent: deserializeAgent(agent) };
  } catch (err) {
    console.error('[agent-identity] updateAgent failed:', err.message);
    return { success: false, error: err.message };
  }
}

// ─── Deactivation ─────────────────────────────────────────────

/**
 * Deactivate an agent (soft delete).
 */
export function deactivateAgent(agentId, reason = null, deactivatedBy = null, ipAddress = null) {
  try {
    const existing = db.prepare('SELECT id, status FROM agents WHERE id = ?').get(agentId);
    if (!existing) return { success: false, error: 'Agent not found' };
    if (existing.status === 'deactivated') return { success: false, error: 'Agent is already deactivated' };

    db.prepare(`
      UPDATE agents SET status = 'deactivated', suspended_reason = ?, updated_at = datetime('now') WHERE id = ?
    `).run(reason, agentId);

    audit.log(
      deactivatedBy || agentId, deactivatedBy ? 'user' : 'agent',
      'agent.deactivate', 'agent', agentId,
      { reason }, ipAddress
    );

    return { success: true, agentId, status: 'deactivated' };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ─── Version History ──────────────────────────────────────────

/**
 * Get version history for an agent.
 */
export function getVersionHistory(agentId, limit = 20) {
  try {
    const rows = db.prepare(`
      SELECT * FROM agent_versions WHERE agent_id = ? ORDER BY created_at DESC LIMIT ?
    `).all(agentId, limit);

    return {
      success: true,
      versions: rows.map(r => ({ ...r, changes: JSON.parse(r.changes || '{}') })),
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ─── Serialization Helper ─────────────────────────────────────

function deserializeAgent(row) {
  if (!row) return null;
  return {
    ...row,
    capabilities: JSON.parse(row.capabilities || '[]'),
    verticals: JSON.parse(row.verticals || '[]'),
    delegation_scope: JSON.parse(row.delegation_scope || '[]'),
    checksum_components: JSON.parse(row.checksum_components || '[]'),
    metadata: JSON.parse(row.metadata || '{}'),
    did_document: row.did_document ? JSON.parse(row.did_document) : null,
    nist_ai_rmf_aligned: Boolean(row.nist_ai_rmf_aligned),
    owner_verified: Boolean(row.owner_verified),
  };
}
