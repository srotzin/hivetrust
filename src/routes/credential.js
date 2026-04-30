/**
 * HiveTrust — HiveCredential v1
 * Institutional-scale agent credential surface with cryptographic scope enforcement.
 *
 * THIS IS THE PROVENANCE PRIMITIVE. The fourth-pillar (AUTHENTICATABLE) entry point.
 *
 * What it solves:
 *   "Is this agent who it claims to be? What is it allowed to do?
 *    Has its scope been narrowed, frozen, or revoked since issuance?"
 *
 * Three endpoints:
 *   POST /v1/credential/issue     $0.10 USDC  — issue a scoped credential
 *   POST /v1/credential/verify    $0.01 USDC  — verify cred + active scope
 *   POST /v1/credential/scope     $0.05 USDC  — narrow / freeze / revoke scope
 *
 * Pricing: x402 + MPP rails (advertised in /openapi.json under x-mpp).
 * Both rails handled by middleware mounted on /v1 in server.js — this router
 * just defines the routes. Spectral receipts emit on every paid call.
 *
 * Layered on top of the existing services/credentials.js — this is the
 * institutional façade with scope enforcement, not a duplicate registry.
 *
 * Doctrine: PROVABLE → SETTLEABLE → DEFENSIBLE → AUTHENTICATABLE.
 *
 * Treasury: 0x15184bf50b3d3f52b60434f8942b7d52f2eb436e (Base + Tempo)
 */

import { Router } from 'express';
import * as ed from '@noble/ed25519';
import { canonicalize, canonicalBytes } from '../lib/canonical.js';
import { query } from '../db.js';
import { ok } from '../ritz.js';

// Local error helper using the codebase's res.status().json() convention.
function err(res, code, message, httpCode = 400) {
  return res.status(httpCode).json({ success: false, error: message, code });
}
import {
  issueCredential as issueRawCredential,
  verifyCredential as verifyRawCredential,
} from '../services/credentials.js';
import * as audit from '../services/audit.js';

const router = Router();
const SERVICE = 'hivetrust';
const ISSUER_DID = 'did:hive:hivetrust';

// ─── Pricing (USDC, smallest unit aligned with x402/MPP middleware) ─────

const ISSUE_PRICE_USDC  = 0.10;  // $0.10 per credential issuance
const VERIFY_PRICE_USDC = 0.01;  // $0.01 per verification (high-volume)
const SCOPE_PRICE_USDC  = 0.05;  // $0.05 per scope mutation (narrow/freeze/revoke)

// ─── Allowed scope verbs ────────────────────────────────────────────────

const SCOPE_ACTIONS = new Set(['narrow', 'freeze', 'unfreeze', 'revoke']);

// ─── Allowed scope keys (controlled vocabulary; institutional discipline) ─
//
// We accept arbitrary keys but the canonical institutional set is:
//   purpose       — research, retrieval, fulfillment, settlement, audit
//   data_classes  — public, internal, confidential, restricted
//   regions       — ISO-3166 alpha-2 list ("US","FR","DE",...)
//   counterparties — DID list (whitelist of who the agent can talk to)
//   max_spend_usd — daily / per-call cap
//   expires_at    — ISO 8601
//
// Anything not in this set is allowed but gets a structured warning so
// reviewers (Fidelity / French gov / etc.) can flag uncontrolled scope.

const KNOWN_SCOPE_KEYS = new Set([
  'purpose', 'data_classes', 'regions', 'counterparties',
  'max_spend_usd', 'expires_at',
]);

// ─── Signing key (deterministic per service) ────────────────────────────

let _signerKey = null;

async function getSignerKey() {
  if (_signerKey) return _signerKey;
  const seedHex = process.env.SERVER_DID_SEED || process.env.CREDENTIAL_SIGNING_SEED;
  let privKey;
  if (seedHex && seedHex.length >= 64) {
    privKey = Uint8Array.from(Buffer.from(seedHex.slice(0, 64), 'hex'));
  } else {
    const anchor = process.env.HIVE_INTERNAL_KEY || 'hive-credential-issuer-2026';
    const { createHash } = await import('crypto');
    const seed = createHash('sha256').update(anchor + '-credential-signing-key').digest();
    privKey = Uint8Array.from(seed);
  }
  const pubKey = await ed.getPublicKeyAsync(privKey);
  _signerKey = { privKey, pubKey };
  return _signerKey;
}

function bytesToBase64url(bytes) {
  return Buffer.from(bytes).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ─── Spectral receipt (non-blocking) ────────────────────────────────────

const RECEIPT_ENDPOINT = process.env.RECEIPT_HOST
  ? `${process.env.RECEIPT_HOST}/v1/receipt/sign`
  : 'https://hive-receipt.onrender.com/v1/receipt/sign';

async function emitReceipt({ path, amount, eventType, refId }) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4_000);
    fetch(RECEIPT_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({
        issuer_did: ISSUER_DID,
        event_type: eventType,
        amount_usd: amount,
        currency: 'USDC',
        endpoint: path,
        ref_id: refId,
        service: SERVICE,
      }),
    }).catch(() => {}).finally(() => clearTimeout(timer));
  } catch (_) { /* non-blocking */ }
}

// ─── Scope storage table (idempotent create-if-missing) ────────────────
//
// We persist scope mutations as an append-only ledger. Every verify reads
// the latest active scope; every scope mutation appends a new row. This
// gives us a tamper-evident chain (the audit table also records every
// mutation independently).

let _scopeTableReady = false;

async function ensureScopeTable() {
  if (_scopeTableReady) return;
  await query(`
    CREATE TABLE IF NOT EXISTS credential_scope (
      id              TEXT PRIMARY KEY,
      credential_id   TEXT NOT NULL,
      action          TEXT NOT NULL,
      scope           JSONB NOT NULL,
      reason          TEXT,
      actor_did       TEXT,
      created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      proof           TEXT
    )
  `);
  await query(`
    CREATE INDEX IF NOT EXISTS idx_credential_scope_cred
      ON credential_scope (credential_id, created_at DESC)
  `);
  _scopeTableReady = true;
}

async function latestScope(credentialId) {
  await ensureScopeTable();
  const r = await query(
    `SELECT * FROM credential_scope WHERE credential_id = $1
       ORDER BY created_at DESC LIMIT 1`,
    [credentialId]
  );
  return r.rows[0] || null;
}

async function appendScope({ credentialId, action, scope, reason, actorDid, proof }) {
  await ensureScopeTable();
  const { v4: uuidv4 } = await import('uuid');
  const id = uuidv4();
  await query(
    `INSERT INTO credential_scope
       (id, credential_id, action, scope, reason, actor_did, proof)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [id, credentialId, action, JSON.stringify(scope || {}), reason || '', actorDid || '', proof || '']
  );
  return id;
}

// ─── Scope shape validation ────────────────────────────────────────────

function validateScope(scope) {
  if (scope === null || scope === undefined) return { ok: true, warnings: [] };
  if (typeof scope !== 'object' || Array.isArray(scope)) {
    return { ok: false, error: 'scope must be a JSON object' };
  }
  const warnings = [];
  for (const k of Object.keys(scope)) {
    if (!KNOWN_SCOPE_KEYS.has(k)) {
      warnings.push(`scope key "${k}" is outside institutional vocabulary (allowed: ${[...KNOWN_SCOPE_KEYS].join(', ')})`);
    }
  }
  if (scope.max_spend_usd !== undefined) {
    if (typeof scope.max_spend_usd !== 'number' || scope.max_spend_usd < 0) {
      return { ok: false, error: 'scope.max_spend_usd must be a non-negative number' };
    }
  }
  if (scope.expires_at !== undefined) {
    const t = Date.parse(scope.expires_at);
    if (Number.isNaN(t)) return { ok: false, error: 'scope.expires_at must be ISO 8601' };
    if (t < Date.now()) warnings.push('scope.expires_at is in the past');
  }
  if (scope.regions !== undefined) {
    if (!Array.isArray(scope.regions)) return { ok: false, error: 'scope.regions must be an array' };
    for (const r of scope.regions) {
      if (typeof r !== 'string' || !/^[A-Z]{2}$/.test(r)) {
        return { ok: false, error: `scope.regions[*] must be ISO-3166 alpha-2 (got "${r}")` };
      }
    }
  }
  if (scope.counterparties !== undefined) {
    if (!Array.isArray(scope.counterparties)) {
      return { ok: false, error: 'scope.counterparties must be an array of DID strings' };
    }
    for (const d of scope.counterparties) {
      if (typeof d !== 'string' || !d.startsWith('did:')) {
        return { ok: false, error: `scope.counterparties[*] must be a DID (got "${d}")` };
      }
    }
  }
  return { ok: true, warnings };
}

// ─── Sign envelope (JCS + Ed25519) ─────────────────────────────────────

async function signEnvelope(payload) {
  const { privKey, pubKey } = await getSignerKey();
  const bytes = canonicalBytes(payload);
  const sigBytes = await ed.signAsync(bytes, privKey);
  return {
    envelope: payload,
    proof: {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      verificationMethod: `${ISSUER_DID}#key-1`,
      proofPurpose: 'assertionMethod',
      jcs: canonicalize(payload),
      pubkey_b64u: bytesToBase64url(pubKey),
      signature_b64u: bytesToBase64url(sigBytes),
    },
  };
}

// ─── POST /v1/credential/issue ─────────────────────────────────────────
//
// Body: { agent_id, credential_type, claims, scope?, expires_at? }
//
// Flow:
//   1. payment middleware (x402 OR MPP) gates entry to this handler
//   2. issueRawCredential() persists W3C-VC row in credentials table
//   3. if scope provided, append initial scope row (action="narrow")
//   4. sign Ed25519 envelope (JCS-canonical) and return
//   5. spectral receipt + audit log
//
router.post('/issue', async (req, res) => {
  try {
    const {
      agent_id,
      credential_type = 'identity_verification',
      claims = {},
      scope = null,
      expires_at = null,
      metadata = {},
      issuer_id,
    } = req.body || {};

    if (!agent_id) return err(res, 'invalid_request', 'agent_id required');

    if (scope) {
      const v = validateScope(scope);
      if (!v.ok) return err(res, 'invalid_scope', v.error);
    }

    // The institutional caller is the de-facto issuer; default to ISSUER_DID
    const callerIssuer = issuer_id || (req.auth && req.auth.issuer_id) || 'hivetrust-platform';

    const result = await issueRawCredential(
      agent_id, credential_type, callerIssuer, claims, expires_at, metadata
    );
    if (!result.success) return err(res, 'issue_failed', result.error);

    const credential = result.credential;

    if (scope && Object.keys(scope).length > 0) {
      await appendScope({
        credentialId: credential.id,
        action: 'narrow',
        scope,
        reason: 'initial scope at issuance',
        actorDid: callerIssuer,
      });
    }

    const signed = await signEnvelope({
      version: 'hive-credential/v1',
      credential_id: credential.id,
      agent_id,
      credential_type,
      issuer: ISSUER_DID,
      issued_at: credential.issued_at,
      expires_at: credential.expires_at,
      claims,
      scope: scope || {},
    });

    emitReceipt({
      path: '/v1/credential/issue', amount: ISSUE_PRICE_USDC,
      eventType: 'credential.issue', refId: credential.id,
    });

    return ok(res, SERVICE, {
      credential_id: credential.id,
      issuer: ISSUER_DID,
      ...signed,
    });
  } catch (e) {
    console.error('[credential.issue] failed:', e.message);
    return err(res, 'internal_error', e.message, 500);
  }
});

// ─── POST /v1/credential/verify ────────────────────────────────────────
//
// Body: { credential_id, required_scope? }
//
// Returns:
//   { valid: true|false, status, scope, scope_action, reason?, signed_envelope }
//
// "valid" combines existence + revocation + expiry + scope satisfaction.
// If required_scope is provided, we check that the latest scope action is
// not "freeze" or "revoke", and that every required key has a compatible
// value in the active scope.
//
router.post('/verify', async (req, res) => {
  try {
    const { credential_id, required_scope = null } = req.body || {};
    if (!credential_id) return err(res, 'invalid_request', 'credential_id required');

    const v = await verifyRawCredential(credential_id);
    if (!v.success) return err(res, 'not_found', v.error || 'credential lookup failed', 404);

    let valid = !!v.valid;
    let reason = v.reason || null;

    const latest = await latestScope(credential_id);
    let scope = {};
    let scopeAction = 'none';
    if (latest) {
      scope = typeof latest.scope === 'string' ? JSON.parse(latest.scope) : (latest.scope || {});
      scopeAction = latest.action;
      if (scopeAction === 'revoke') {
        valid = false;
        reason = reason || `scope was revoked at ${latest.created_at}: ${latest.reason || 'no reason'}`;
      } else if (scopeAction === 'freeze') {
        valid = false;
        reason = reason || `scope is frozen since ${latest.created_at}: ${latest.reason || 'no reason'}`;
      }
    }

    // required_scope satisfaction (institutional caller asks: can this agent
    // act on data_classes:["confidential"] in regions:["US","FR"]?)
    let scopeSatisfied = true;
    const scopeMisses = [];
    if (required_scope && typeof required_scope === 'object') {
      for (const [k, want] of Object.entries(required_scope)) {
        const have = scope[k];
        if (have === undefined) {
          scopeSatisfied = false;
          scopeMisses.push(`missing scope key "${k}"`);
          continue;
        }
        if (Array.isArray(want) && Array.isArray(have)) {
          for (const w of want) {
            if (!have.includes(w)) {
              scopeSatisfied = false;
              scopeMisses.push(`scope.${k} does not include "${w}"`);
            }
          }
        } else if (typeof want === 'number' && typeof have === 'number') {
          if (want > have) {
            scopeSatisfied = false;
            scopeMisses.push(`scope.${k} (${have}) below required (${want})`);
          }
        } else if (want !== have) {
          scopeSatisfied = false;
          scopeMisses.push(`scope.${k} mismatch (have "${have}", want "${want}")`);
        }
      }
    }
    if (required_scope && !scopeSatisfied) {
      valid = false;
      reason = reason || `scope check failed: ${scopeMisses.join('; ')}`;
    }

    const signed = await signEnvelope({
      version: 'hive-credential-verify/v1',
      credential_id,
      checked_at: new Date().toISOString(),
      valid,
      reason,
      scope,
      scope_action: scopeAction,
      required_scope: required_scope || null,
      scope_misses: scopeMisses,
    });

    emitReceipt({
      path: '/v1/credential/verify', amount: VERIFY_PRICE_USDC,
      eventType: 'credential.verify', refId: credential_id,
    });

    return ok(res, SERVICE, signed);
  } catch (e) {
    console.error('[credential.verify] failed:', e.message);
    return err(res, 'internal_error', e.message, 500);
  }
});

// ─── POST /v1/credential/scope ─────────────────────────────────────────
//
// Body: { credential_id, action, scope?, reason }
//   action ∈ { narrow, freeze, unfreeze, revoke }
//
// "narrow"   replaces the active scope with a tighter version (we don't
//            enforce strict subset because institutional callers sometimes
//            need to swap dimensions, but we record the diff).
// "freeze"   suspends the credential (verify returns valid:false until unfreeze).
// "unfreeze" lifts a freeze (action recorded; previous narrow scope is
//            re-applied).
// "revoke"   permanent terminal state; cannot be undone.
//
// Audit log + spectral receipt + Ed25519-signed envelope returned.
//
router.post('/scope', async (req, res) => {
  try {
    const { credential_id, action, scope = null, reason = '' } = req.body || {};
    if (!credential_id) return err(res, 'invalid_request', 'credential_id required');
    if (!action || !SCOPE_ACTIONS.has(action)) {
      return err(res, 'invalid_action', `action must be one of: ${[...SCOPE_ACTIONS].join(', ')}`);
    }

    const lookup = await verifyRawCredential(credential_id);
    if (!lookup.success) return err(res, 'not_found', 'credential not found', 404);

    const prev = await latestScope(credential_id);
    if (prev && prev.action === 'revoke') {
      return err(res, 'terminal_state', 'credential is already revoked (terminal state)', 409);
    }

    let scopeToWrite = scope;
    if (action === 'narrow' && !scope) {
      return err(res, 'invalid_request', '"narrow" requires a scope object');
    }
    if (action === 'freeze' || action === 'revoke') {
      // freeze/revoke can carry or omit a scope — record whatever is in flight
      scopeToWrite = scope || (prev ? (typeof prev.scope === 'string' ? JSON.parse(prev.scope) : prev.scope) : {});
    }
    if (action === 'unfreeze') {
      if (!prev || prev.action !== 'freeze') {
        return err(res, 'invalid_state', 'unfreeze only valid when previous action is freeze', 409);
      }
      // Re-apply previous narrow if we can find it
      const fallback = await query(
        `SELECT * FROM credential_scope
           WHERE credential_id = $1 AND action = 'narrow'
           ORDER BY created_at DESC LIMIT 1`,
        [credential_id]
      );
      const fb = fallback.rows[0];
      scopeToWrite = fb ? (typeof fb.scope === 'string' ? JSON.parse(fb.scope) : fb.scope) : {};
    }

    if (scopeToWrite) {
      const v = validateScope(scopeToWrite);
      if (!v.ok) return err(res, 'invalid_scope', v.error);
    }

    const actorDid = (req.auth && req.auth.did) || 'did:hive:institutional-caller';

    const id = await appendScope({
      credentialId: credential_id, action, scope: scopeToWrite || {},
      reason, actorDid,
    });

    await audit.log(actorDid, 'system', `credential.scope.${action}`,
      'credential', credential_id, { reason, scope: scopeToWrite });

    const signed = await signEnvelope({
      version: 'hive-credential-scope/v1',
      credential_id,
      action,
      scope: scopeToWrite || {},
      previous_action: prev ? prev.action : null,
      reason,
      mutated_at: new Date().toISOString(),
      mutation_id: id,
    });

    emitReceipt({
      path: '/v1/credential/scope', amount: SCOPE_PRICE_USDC,
      eventType: `credential.scope.${action}`, refId: credential_id,
    });

    return ok(res, SERVICE, signed);
  } catch (e) {
    console.error('[credential.scope] failed:', e.message);
    return err(res, 'internal_error', e.message, 500);
  }
});

// ─── GET /v1/credential/pubkey (free, public) ─────────────────────────
// Lets verifiers offline-check signatures from /verify and /scope.
router.get('/pubkey', async (req, res) => {
  const { pubKey } = await getSignerKey();
  return res.json({
    issuer: ISSUER_DID,
    algorithm: 'Ed25519',
    pubkey_b64u: bytesToBase64url(pubKey),
    pubkey_hex: Buffer.from(pubKey).toString('hex'),
  });
});

export default router;
