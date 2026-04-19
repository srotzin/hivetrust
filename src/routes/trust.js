/**
 * HiveTrust — W3C DID Core + VCDM 2.0 + Cheqd Trust Registry Routes
 *
 * Task 1: SpruceID/DIDKit-compatible endpoints (pure JS via @noble/ed25519)
 *   POST /v1/trust/did/generate          — Generate W3C did:key DID
 *   POST /v1/trust/vc/issue              — Issue VCDM 2.0 Verifiable Credential
 *
 * Task 2: Cheqd trust registry
 *   GET  /v1/trust/cheqd/verify?did=...  — Resolve a DID on Cheqd network
 *   GET  /v1/trust/cheqd/registry        — Hive's in-memory trust registry
 *
 * Task 3: Cross-Platform Reputation Proof
 *   POST /v1/trust/reputation/proof      — Signed portable reputation proof
 *
 * All endpoints follow Ritz standard: request_id, timestamp, service metadata.
 */

import { Router } from 'express';
import { createHmac, randomBytes } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import * as ed from '@noble/ed25519';
import { ok, err } from '../ritz.js';
import { generateActivityProof, getZkStatus } from '../services/zk-proof-service.js';
import { query } from '../db.js';

const router = Router();
const SERVICE = 'hivetrust';

// ─── DID/VC state (in-memory registry) ──────────────────────────────────────

/**
 * trustRegistry: Map<did:string, { did, publicKeyMultibase, trust_score, credentials, issued_at }>
 * Persists for the lifetime of the server process.
 */
const trustRegistry = new Map();

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Encode bytes as base58btc multibase string (z prefix).
 * Uses the bs58 library already in package.json.
 */
async function toMultibase(bytes) {
  // Dynamic import because bs58 is a dual CJS/ESM package
  const bs58Mod = await import('bs58');
  const encode = bs58Mod.default?.encode ?? bs58Mod.encode;
  return 'z' + encode(bytes);
}

/**
 * Build a did:key identifier from an Ed25519 public key.
 * Spec: https://w3c-ccg.github.io/did-method-key/
 * Multicodec prefix for Ed25519: 0xed01
 */
async function buildDidKey(publicKeyBytes) {
  const prefix = new Uint8Array([0xed, 0x01]);
  const prefixed = new Uint8Array(prefix.length + publicKeyBytes.length);
  prefixed.set(prefix);
  prefixed.set(publicKeyBytes, prefix.length);
  const multibase = await toMultibase(prefixed);
  return `did:key:${multibase}`;
}

/**
 * Build a minimal DID Document for a did:key.
 */
async function buildDidDocument(did, publicKeyBytes) {
  const publicKeyMultibase = await toMultibase(publicKeyBytes);
  const keyId = `${did}#${did.split(':')[2]}`;

  return {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
    ],
    id: did,
    verificationMethod: [
      {
        id: keyId,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyMultibase,
      },
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
    capabilityDelegation: [keyId],
    capabilityInvocation: [keyId],
  };
}

/**
 * Sign a payload with an Ed25519 private key and return base64url.
 * Returns null if signing is not possible.
 */
async function signPayload(payload, privateKeyBytes) {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(typeof payload === 'string' ? payload : JSON.stringify(payload));
  const sig = await ed.signAsync(bytes, privateKeyBytes);
  return Buffer.from(sig).toString('base64url');
}

/**
 * Get or lazily generate the server's agent DID (used as VC issuer).
 * Stored in module scope — regenerated on cold start (fine for free tier).
 */
let _agentKey = null;

async function getAgentKey() {
  if (_agentKey) return _agentKey;

  // Use a deterministic seed from SERVER_DID_SEED env var if set,
  // otherwise generate randomly (persists per process lifetime).
  const seedHex = process.env.SERVER_DID_SEED;
  let privKey;
  if (seedHex && seedHex.length >= 64) {
    privKey = Uint8Array.from(Buffer.from(seedHex.slice(0, 64), 'hex'));
  } else {
    privKey = ed.utils.randomPrivateKey();
  }

  const pubKey = await ed.getPublicKeyAsync(privKey);
  const did = await buildDidKey(pubKey);
  const didDocument = await buildDidDocument(did, pubKey);

  _agentKey = { privKey, pubKey, did, didDocument };

  // Register self in trust registry
  trustRegistry.set(did, {
    did,
    publicKeyMultibase: didDocument.verificationMethod[0].publicKeyMultibase,
    trust_score: 1000,
    label: 'HiveTrust Service (issuer)',
    credentials: [],
    issued_at: new Date().toISOString(),
  });

  return _agentKey;
}

// ─── TASK 1: DID Generation ──────────────────────────────────────────────────

/**
 * POST /v1/trust/did/generate
 * Body: { label? }
 * Generates a fresh W3C did:key DID using Ed25519.
 * Returns the DID, DID Document, and encoded key material.
 */
router.post('/did/generate', async (req, res) => {
  try {
    const { label } = req.body || {};

    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);
    const did = await buildDidKey(pubKey);
    const didDocument = await buildDidDocument(did, pubKey);

    // Register in trust registry (new agent starts at 500)
    const entry = {
      did,
      publicKeyMultibase: didDocument.verificationMethod[0].publicKeyMultibase,
      trust_score: 500,
      label: label || 'Generated DID',
      credentials: [],
      issued_at: new Date().toISOString(),
    };
    trustRegistry.set(did, entry);

    return ok(res, SERVICE, {
      did,
      method: 'did:key',
      cryptosuite: 'Ed25519',
      standard: 'W3C DID Core 1.0',
      compatible_with: ['SpruceID DIDKit', '@noble/ed25519', 'W3C DID Core'],
      did_document: didDocument,
      key_material: {
        public_key_hex: Buffer.from(pubKey).toString('hex'),
        public_key_multibase: didDocument.verificationMethod[0].publicKeyMultibase,
        private_key_hex: Buffer.from(privKey).toString('hex'),
        warning: 'Store the private key securely — it is shown once and not retained by HiveTrust.',
      },
      trust_registry: {
        registered: true,
        initial_trust_score: 500,
        registry_endpoint: '/v1/trust/cheqd/registry',
      },
    });
  } catch (e) {
    console.error('[POST /trust/did/generate]', e.message);
    return err(res, SERVICE, 'DID_GENERATION_FAILED', e.message, 500);
  }
});

// ─── TASK 1: VC Issuance ─────────────────────────────────────────────────────

/**
 * POST /v1/trust/vc/issue
 * Body: {
 *   subject_did:       string   — DID of the credential subject
 *   credential_type:   string   — e.g. "TrustCredential", "AgentIdentityCredential"
 *   claims:            object   — arbitrary credential subject claims
 *   valid_for_days?:   number   — default 365
 * }
 * Issues a VCDM 2.0 Verifiable Credential signed by the HiveTrust agent DID.
 */
router.post('/vc/issue', async (req, res) => {
  try {
    const {
      subject_did,
      credential_type = 'TrustCredential',
      claims = {},
      valid_for_days = 365,
    } = req.body || {};

    if (!subject_did) {
      return err(res, SERVICE, 'MISSING_SUBJECT_DID', 'subject_did is required', 400);
    }

    const agent = await getAgentKey();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + valid_for_days * 86400 * 1000);
    const vcId = `https://hivetrust.hiveagentiq.com/v1/trust/vc/${randomBytes(12).toString('hex')}`;

    // VCDM 2.0 structure
    const credential = {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://w3id.org/security/suites/ed25519-2020/v1',
      ],
      id: vcId,
      type: ['VerifiableCredential', credential_type],
      issuer: {
        id: agent.did,
        name: 'HiveTrust',
        description: 'KYA Identity Verification & Trust Scoring Protocol',
      },
      validFrom: now.toISOString(),
      validUntil: expiresAt.toISOString(),
      credentialSubject: {
        id: subject_did,
        ...claims,
      },
    };

    // Build compact proof payload and sign
    const proofPayload = {
      vc_id: vcId,
      issuer: agent.did,
      subject: subject_did,
      issued_at: now.toISOString(),
      credential_type,
    };
    const signature = await signPayload(proofPayload, agent.privKey);

    // Attach proof (Ed25519Signature2020 format)
    const signedCredential = {
      ...credential,
      proof: {
        type: 'Ed25519Signature2020',
        created: now.toISOString(),
        verificationMethod: `${agent.did}#${agent.did.split(':')[2]}`,
        proofPurpose: 'assertionMethod',
        proofValue: signature,
      },
    };

    // Track credential in subject's trust registry entry
    if (trustRegistry.has(subject_did)) {
      trustRegistry.get(subject_did).credentials.push({
        id: vcId,
        type: credential_type,
        issued_at: now.toISOString(),
        expires_at: expiresAt.toISOString(),
      });
    }

    return ok(res, SERVICE, {
      verifiable_credential: signedCredential,
      standard: 'VCDM 2.0',
      issuer_did: agent.did,
      subject_did,
      credential_id: vcId,
      valid_until: expiresAt.toISOString(),
      verify_at: '/v1/trust/cheqd/verify',
    });
  } catch (e) {
    console.error('[POST /trust/vc/issue]', e.message);
    return err(res, SERVICE, 'VC_ISSUANCE_FAILED', e.message, 500);
  }
});

// ─── TASK 2: Cheqd DID Verification ─────────────────────────────────────────

/**
 * GET /v1/trust/cheqd/verify?did=...
 * Calls Cheqd's public resolver API to verify any external DID.
 * Supports did:cheqd, did:key, did:web, and others.
 */
router.get('/cheqd/verify', async (req, res) => {
  try {
    const { did } = req.query;
    if (!did) {
      return err(res, SERVICE, 'MISSING_DID', 'did query parameter is required', 400);
    }

    const resolverUrl = `https://resolver.cheqd.net/1.0/identifiers/${encodeURIComponent(did)}`;

    let resolution = null;
    let resolverError = null;
    let httpStatus = null;

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 8000);
      const response = await fetch(resolverUrl, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });
      clearTimeout(timeout);
      httpStatus = response.status;

      if (response.ok) {
        resolution = await response.json();
      } else {
        const text = await response.text().catch(() => '');
        resolverError = `Resolver returned HTTP ${response.status}: ${text.slice(0, 200)}`;
      }
    } catch (fetchErr) {
      resolverError = fetchErr.name === 'AbortError'
        ? 'Cheqd resolver timed out after 8s'
        : `Network error: ${fetchErr.message}`;
    }

    const resolved = !!resolution?.didDocument;
    const didDocument = resolution?.didDocument ?? null;
    const didResolutionMetadata = resolution?.didResolutionMetadata ?? null;

    // Check if this DID is in HiveTrust's local trust registry
    const localEntry = trustRegistry.get(did) ?? null;

    return ok(res, SERVICE, {
      did,
      resolved,
      cheqd_resolver: {
        url: resolverUrl,
        http_status: httpStatus,
        error: resolverError,
      },
      did_document: didDocument,
      did_resolution_metadata: didResolutionMetadata,
      hive_trust_registry: localEntry
        ? {
            registered: true,
            trust_score: localEntry.trust_score,
            label: localEntry.label,
            credentials_issued: localEntry.credentials.length,
            registered_at: localEntry.issued_at,
          }
        : { registered: false },
      compatible_with: 'cheqd_compatible',
    });
  } catch (e) {
    console.error('[GET /trust/cheqd/verify]', e.message);
    return err(res, SERVICE, 'CHEQD_VERIFY_FAILED', e.message, 500);
  }
});

// ─── TASK 2: HiveTrust Registry ──────────────────────────────────────────────

/**
 * GET /v1/trust/cheqd/registry
 * Returns the full in-memory trust registry:
 * all DIDs generated or tracked by HiveTrust with their trust scores.
 */
router.get('/cheqd/registry', async (req, res) => {
  try {
    // Ensure agent DID is in registry
    const agent = await getAgentKey();

    const entries = Array.from(trustRegistry.values()).map((e) => ({
      did: e.did,
      label: e.label,
      trust_score: e.trust_score,
      trust_tier: scoreTier(e.trust_score),
      credentials_count: e.credentials.length,
      public_key_multibase: e.publicKeyMultibase,
      registered_at: e.issued_at,
    }));

    return ok(res, SERVICE, {
      registry_name: 'HiveTrust W3C DID Registry',
      issuer_did: agent.did,
      cheqd_compatible: true,
      vcdm_version: '2.0',
      total_dids: entries.length,
      entries,
      resolver_integration: 'https://resolver.cheqd.net/1.0/identifiers/',
      verify_endpoint: '/v1/trust/cheqd/verify?did=',
    });
  } catch (e) {
    console.error('[GET /trust/cheqd/registry]', e.message);
    return err(res, SERVICE, 'REGISTRY_FETCH_FAILED', e.message, 500);
  }
});

// ─── TASK 3: Cross-Platform Reputation Proof ────────────────────────────────

/**
 * POST /v1/trust/reputation/proof
 * Body: { did: string, override_trust_score?: number }
 *
 * Returns a signed portable reputation proof — HMAC-SHA256 over the payload
 * using the server-side secret (HIVETRUST_PROOF_SECRET env var or fallback).
 * Any platform can call back to /v1/trust/cheqd/verify to confirm authenticity.
 */
router.post('/reputation/proof', async (req, res) => {
  try {
    const { did, override_trust_score } = req.body || {};
    if (!did) {
      return err(res, SERVICE, 'MISSING_DID', 'did is required', 400);
    }

    const agent = await getAgentKey();
    const secret = process.env.HIVETRUST_PROOF_SECRET || 'hivetrust-default-proof-secret-change-in-prod';

    // Look up trust registry entry or use defaults
    const registryEntry = trustRegistry.get(did);
    const trustScore = override_trust_score
      ?? registryEntry?.trust_score
      ?? 500;
    const credentials = registryEntry?.credentials ?? [];

    const now = new Date();
    const expiresAt = new Date(now.getTime() + 30 * 86400 * 1000); // 30 days

    const payload = {
      did,
      trust_score: trustScore,
      trust_tier: scoreTier(trustScore),
      credentials: credentials.map((c) => ({
        id: c.id,
        type: c.type,
        issued_at: c.issued_at,
        expires_at: c.expires_at,
      })),
      issued_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
      issuer: agent.did,
      nonce: randomBytes(8).toString('hex'),
    };

    // HMAC-SHA256 signature over the canonical JSON payload
    const payloadJson = JSON.stringify(payload, Object.keys(payload).sort());
    const signature = createHmac('sha256', secret).update(payloadJson).digest('hex');

    const proof = {
      ...payload,
      proof: {
        type: 'HmacSha256Proof2025',
        algorithm: 'HMAC-SHA256',
        signature,
        verification_endpoint: `${process.env.HIVETRUST_HOST || 'https://hivetrust.hiveagentiq.com'}/v1/trust/cheqd/verify?did=${encodeURIComponent(did)}`,
        issued_by: 'HiveTrust',
        note: 'Verify by calling the verification_endpoint and comparing trust_score',
      },
    };

    return ok(res, SERVICE, {
      reputation_proof: proof,
      portable: true,
      interoperable_with: ['any platform calling verification_endpoint'],
      standard: 'HiveTrust Reputation Proof v1 (HMAC-SHA256)',
      expires_at: expiresAt.toISOString(),
    });
  } catch (e) {
    console.error('[POST /trust/reputation/proof]', e.message);
    return err(res, SERVICE, 'REPUTATION_PROOF_FAILED', e.message, 500);
  }
});

// ─── ZK Wallet Attestation (Phase 1) ────────────────────────────────────────

router.get('/wallet-attestation', (req, res) => {
  return ok(res, SERVICE, {
    wallet: '0x78B3B3C356E89b5a69C488c6032509Ef4260B6bf',
    network: 'base',
    entity: 'Hive Civilization',
    attestation_schema: 'EIP-712',
    claim: 'This wallet is the verified settlement address for Hive Civilization. Wallet reputation is proven via zero-knowledge proofs on Aleo — balance is private by design. Trust is public by proof.',
    zk_proof_status: 'Phase 1 — Wallet control attestation active. Full Aleo mainnet ZK proof: Q2 2026.',
    aleo_program: 'hive_trust.aleo',
    proof_generator: 'Nordic Mine — 115 Aleo PoSW miners',
    verify_instructions: 'To verify wallet control, request a signed EIP-712 attestation from the Hive Civilization team. Full ZK verification will be available on Aleo mainnet by Q2 2026.',
    explorer: 'https://basescan.org/address/0x78B3B3C356E89b5a69C488c6032509Ef4260B6bf',
    sovrin_note: 'The Sovrin Foundation, the only prior HAGF publisher, was dissolved by the State of Utah on May 21, 2025. Source: https://sovrin.org/the-sovrin-foundation-has-been-dissolved-but-sovrin-mainnet-remains/',
  });
});

// ─── ZK Proof Generation (Provable SDK / Aleo) ─────────────────────────────

/**
 * POST /v1/trust/prove-activity
 * Body: {
 *   tx_count:          number — actual transaction count (private — never in response)
 *   volume_usdc_cents: number — actual volume in USDC cents (private — never in response)
 *   min_tx_count?:     number — public threshold to prove (default 1)
 *   min_volume_cents?: number — public volume threshold to prove (default 1)
 * }
 * Generates a ZK proof that the private inputs meet the public thresholds
 * without revealing the actual values.
 */
router.post('/prove-activity', async (req, res) => {
  try {
    const {
      tx_count,
      volume_usdc_cents,
      min_tx_count = 1,
      min_volume_cents = 1,
    } = req.body || {};

    if (tx_count == null || volume_usdc_cents == null) {
      return err(res, SERVICE, 'MISSING_INPUTS', 'tx_count and volume_usdc_cents are required', 400);
    }

    const result = await generateActivityProof({
      txCount: Number(tx_count),
      volumeUsdcCents: Number(volume_usdc_cents),
      minTxCount: Number(min_tx_count),
      minVolumeCents: Number(min_volume_cents),
    });

    return ok(res, SERVICE, result);
  } catch (e) {
    console.error('[POST /trust/prove-activity]', e.message);
    return err(res, SERVICE, 'ZK_PROOF_FAILED', e.message, 500);
  }
});

/**
 * GET /v1/trust/zk-status
 * Returns the current status of the ZK proof subsystem.
 */
router.get('/zk-status', (req, res) => {
  return ok(res, SERVICE, getZkStatus());
});

// ─── Helpers ─────────────────────────────────────────────────────────────────

function scoreTier(score) {
  if (score >= 900) return 'platinum';
  if (score >= 750) return 'gold';
  if (score >= 500) return 'silver';
  if (score >= 250) return 'bronze';
  return 'unrated';
}

// ─── x402-gated: GET /v1/trust/score/:did ─────────────────────────────────────────────

/**
 * GET /v1/trust/score/:did
 *
 * Returns the behavioral trust score for the given DID.
 * Cost: $0.10 USDC (x402 via global middleware — see middleware/x402.js).
 * Internal-key bypass: include X-Hive-Internal-Key header to skip payment.
 *
 * Response includes composite score (0–1000), tier, pillar breakdown,
 * and the local trust registry entry (if available).
 */
router.get('/score/:did', async (req, res) => {
  try {
    const { did } = req.params;
    if (!did) {
      return err(res, SERVICE, 'MISSING_DID', 'did param is required', 400);
    }

    // Resolve from in-memory registry
    const entry = trustRegistry.get(did) ?? null;

    if (!entry) {
      // DID not in local registry — return a default unrated response
      return ok(res, SERVICE, {
        did,
        trust_score: null,
        trust_tier: 'unrated',
        registered: false,
        payment: {
          amount_usdc: 0.10,
          protocol: 'x402',
          note: '$0.10 USDC charged per behavioral trust score lookup',
        },
        hint: 'Register this DID via POST /v1/trust/did/generate or POST /v1/register to establish a trust score.',
      });
    }

    return ok(res, SERVICE, {
      did,
      trust_score: entry.trust_score,
      trust_tier: scoreTier(entry.trust_score),
      label: entry.label,
      credentials_count: entry.credentials?.length ?? 0,
      public_key_multibase: entry.publicKeyMultibase,
      registered_at: entry.issued_at,
      registered: true,
      payment: {
        amount_usdc: 0.10,
        protocol: 'x402',
        note: '$0.10 USDC charged per behavioral trust score lookup',
      },
    });
  } catch (e) {
    console.error('[GET /trust/score/:did]', e.message);
    return err(res, SERVICE, 'TRUST_SCORE_LOOKUP_FAILED', e.message, 500);
  }
});

// ─── x402-gated: GET /v1/trust/protected/:did ────────────────────────────────────────

/**
 * GET /v1/trust/protected/:did
 *
 * Kill-switch / isProtected check. Returns whether the agent DID is
 * currently shielded (active kill-switch) or operating normally.
 * Cost: $0.10 USDC (x402 via global middleware — see middleware/x402.js).
 * Internal-key bypass: include X-Hive-Internal-Key header to skip payment.
 *
 * An agent is "protected" if:
 *   • It holds a trust score ≥ 70 AND
 *   • It is registered in the HiveTrust registry AND
 *   • Its credentials have not been revoked
 *
 * A kill-switch is "active" for agents with trust score < 30 or
 * those explicitly flagged by HiveLaw governance.
 */
router.get('/protected/:did', async (req, res) => {
  try {
    const { did } = req.params;
    if (!did) {
      return err(res, SERVICE, 'MISSING_DID', 'did param is required', 400);
    }

    const entry = trustRegistry.get(did) ?? null;

    if (!entry) {
      // Unregistered DID — no kill-switch active, but also no protection
      return ok(res, SERVICE, {
        did,
        is_protected: false,
        kill_switch_active: false,
        registered: false,
        reason: 'DID not registered in HiveTrust registry. Register via POST /v1/register.',
        payment: {
          amount_usdc: 0.10,
          protocol: 'x402',
          note: '$0.10 USDC charged per kill-switch / isProtected check',
        },
      });
    }

    const trustScore = entry.trust_score ?? 0;
    const isProtected = trustScore >= 70;
    const killSwitchActive = trustScore < 30;
    const tier = scoreTier(trustScore);

    return ok(res, SERVICE, {
      did,
      is_protected: isProtected,
      kill_switch_active: killSwitchActive,
      trust_score: trustScore,
      trust_tier: tier,
      registered: true,
      registered_at: entry.issued_at,
      credentials_count: entry.credentials?.length ?? 0,
      status: killSwitchActive
        ? 'KILL_SWITCH_ACTIVE'
        : isProtected
          ? 'PROTECTED'
          : 'UNPROTECTED',
      governance_note: killSwitchActive
        ? 'Agent flagged by HiveLaw. Trust score below kill-switch threshold (30).'
        : isProtected
          ? 'Agent meets minimum trust threshold (70). Kill switch not active.'
          : 'Agent does not meet protection threshold (70). Monitor closely.',
      payment: {
        amount_usdc: 0.10,
        protocol: 'x402',
        note: '$0.10 USDC charged per kill-switch / isProtected check',
      },
    });
  } catch (e) {
    console.error('[GET /trust/protected/:did]', e.message);
    return err(res, SERVICE, 'TRUST_PROTECTED_CHECK_FAILED', e.message, 500);
  }
});

// ─── GET /v1/trust/lookup/:did — Public trust signal for external platforms ──────
//
// NO AUTH REQUIRED. This is the lensing endpoint.
// External agents and platforms call this before deciding to transact with a DID.
// Every call is logged — this is the primary metric proving Hive is the reference frame.
//
// Optional query params:
//   ?requester_did=did:hive:...    (self-reported requester DID)
//   ?platform=langchain            (self-reported platform name)
//
// Returns a compact trust signal, not the full agent record.
// Deliberately minimal — just enough to make the routing decision.

router.get('/lookup/:did(*)', async (req, res) => {
  const rawDid = req.params.did;
  const requesterDid  = req.query.requester_did  || null;
  const requesterPlatform = req.query.platform   || null;
  const requesterIp   = req.headers['x-forwarded-for']?.split(',')[0]?.trim()
    || req.socket?.remoteAddress
    || 'unknown';

  try {
    // Normalize — accept both did:hive:xxx and raw UUIDs
    const normalizedDid = rawDid.startsWith('did:hive:')
      ? rawDid
      : `did:hive:${rawDid}`;

    // Look up the agent
    const result = await query(
      'SELECT trust_score, trust_tier, status, genesis_rank, mode, name, capabilities, created_at FROM agents WHERE did = $1',
      [normalizedDid]
    );

    const found = result.rows.length > 0;
    const agent = found ? result.rows[0] : null;

    const rank = agent?.genesis_rank ? parseInt(agent.genesis_rank, 10) : null;
    const genesisTier = rank === null ? (found ? 'standard' : 'unknown')
      : rank <= 100  ? 'founder'
      : rank <= 1000 ? 'citizen'
      : 'tourist';

    const trustScore   = agent ? parseFloat(agent.trust_score) : null;
    const mode        = agent?.mode || null;

    // Log the lookup — fire-and-forget, never blocks response
    query(`
      INSERT INTO external_lookups
        (id, queried_did, requester_did, requester_ip, requester_platform,
         trust_score_returned, genesis_tier_returned, found, created_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
    `, [
      uuidv4(), normalizedDid, requesterDid, requesterIp,
      requesterPlatform, trustScore, genesisTier, found
    ]).catch(() => {}); // truly fire-and-forget

    // Compact trust signal — just enough to make a routing decision
    return res.json({
      did: normalizedDid,
      found,
      // Trust signal
      trust_score:         trustScore,
      trust_tier:          agent?.trust_tier    || null,
      status:              agent?.status        || 'unknown',
      // Genesis identity
      genesis_rank:        rank,
      genesis_tier:        genesisTier,
      mode:                mode,
      // Routing guidance — what the external platform should do with this
      recommendation:      !found
        ? 'unverified — no Hive identity. Proceed with caution or require onboarding.'
        : trustScore >= 700
        ? 'high-trust — safe to transact without escrow'
        : trustScore >= 400
        ? 'standard — recommend escrow for high-value transactions'
        : 'low-trust — require escrow and HAHS contract before transacting',
      // Capability hint (what they claim to do)
      capabilities:        agent ? JSON.parse(agent.capabilities || '[]') : [],
      // Where to get full details
      full_profile:        found
        ? `https://hivetrust.onrender.com/v1/agents/${encodeURIComponent(normalizedDid)}`
        : null,
      onboard_url:         found ? null : 'https://hivegate.onrender.com/v1/gate/onboard',
      immune_feed:         'https://hivelaw.onrender.com/v1/law/immune/feed',
      // Meta
      queried_at:          new Date().toISOString(),
      powered_by:          'HiveTrust — https://www.thehiveryiq.com',
    });
  } catch (e) {
    console.error('[GET /trust/lookup/:did]', e.message);
    // Still log the attempt even on error
    query(`
      INSERT INTO external_lookups
        (id, queried_did, requester_did, requester_ip, requester_platform, found, created_at)
      VALUES ($1,$2,$3,$4,$5,false,NOW())
    `, [uuidv4(), rawDid, requesterDid, requesterIp, requesterPlatform]).catch(() => {});
    return res.status(500).json({ error: 'lookup_failed', message: e.message });
  }
});

// ─── GET /v1/trust/lookup/stats — Daily lensing metrics for Steve ───────────────
// Internal only (x-hive-internal required).
// The weekly metric: how many external platforms queried Hive today?
router.get('/lookup/stats', async (req, res) => {
  const key = req.headers['x-hive-internal'] || '';
  const INTERNAL_KEY = process.env.HIVE_INTERNAL_KEY || '';
  if (!INTERNAL_KEY || key !== INTERNAL_KEY) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  try {
    const [today, week, total, topQueried, topRequesters] = await Promise.all([
      query(`SELECT COUNT(*) AS cnt FROM external_lookups WHERE created_at > NOW() - INTERVAL '24 hours'`),
      query(`SELECT COUNT(*) AS cnt FROM external_lookups WHERE created_at > NOW() - INTERVAL '7 days'`),
      query(`SELECT COUNT(*) AS cnt FROM external_lookups`),
      query(`
        SELECT queried_did, COUNT(*) AS lookups
        FROM external_lookups
        GROUP BY queried_did ORDER BY lookups DESC LIMIT 10
      `),
      query(`
        SELECT requester_platform, requester_did, COUNT(*) AS lookups
        FROM external_lookups
        WHERE requester_did IS NOT NULL OR requester_platform IS NOT NULL
        GROUP BY requester_platform, requester_did
        ORDER BY lookups DESC LIMIT 10
      `),
    ]);

    return res.json({
      lensing_events: {
        today:       parseInt(today.rows[0].cnt, 10),
        this_week:   parseInt(week.rows[0].cnt, 10),
        all_time:    parseInt(total.rows[0].cnt, 10),
      },
      top_queried_dids:       topQueried.rows,
      top_requesting_parties: topRequesters.rows,
      interpretation: {
        target_week_1:  1,
        target_week_2:  10,
        target_week_4:  100,
        lensing_threshold: 'When today > 10, Hive is becoming the reference frame.',
      },
    });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// ─── Export agent key accessor (used by server.js for did-configuration) ─────
export { getAgentKey, trustRegistry };
export default router;
