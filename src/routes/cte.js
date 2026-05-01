/**
 * HiveTrust — CTEF v0.3.1 Routes
 *
 * HiveTrust is the 5th canonicalizer in the CTEF v0.3.1 byte-match consortium:
 *   AgentGraph + AgentID + APS + Nobulex + HiveTrust
 *
 * Committed by Kenne's 2026-04-25 01:48 UTC freeze:
 *   https://github.com/a2aproject/A2A/discussions/1734
 *
 * Patent applications 64/049,200 – 64/049,226 (priority 2026-04-24)
 * Holder: Stephen A. Rotzin / TheHiveryIQ
 *
 * Routes:
 *   GET  /.well-known/cte-test-vectors.json  — public CTEF v0.3.1 fixture
 *   GET  /verify                             — GET ?did=... passport tier lookup (read-only, first free)
 *   POST /verify                             — paid structural verification endpoint
 *   GET  /verify/pubkey                      — Ed25519 attestation pubkey
 *   GET  /verify/self-test                   — self-test runner for all 4 vectors
 */

import { Router } from 'express';
import { createHash, randomBytes } from 'crypto';
import * as ed from '@noble/ed25519';
import { ok, err } from '../ritz.js';

const router = Router();
const SERVICE = 'hivetrust-cte';

// ─── Ed25519 Key Material ─────────────────────────────────────────────────────

// Dev fallback: deterministic key derived from a fixed seed for local testing.
// In production, set HIVETRUST_SIGNING_KEY to a 64-hex-char Ed25519 private key.
const DEV_PRIVKEY_HEX = 'b3d4e5f6a7b8c9d0e1f2030405060708090a0b0c0d0e0f101112131415161718';

function getPrivateKeyBytes() {
  const hexKey = process.env.HIVETRUST_SIGNING_KEY || DEV_PRIVKEY_HEX;
  if (hexKey.length !== 64) {
    console.warn('[CTE] HIVETRUST_SIGNING_KEY must be 64 hex chars; using dev key fallback');
    return Buffer.from(DEV_PRIVKEY_HEX, 'hex');
  }
  return Buffer.from(hexKey, 'hex');
}

let _pubkeyHex = null;
async function getPubkeyHex() {
  if (_pubkeyHex) return _pubkeyHex;
  const priv = getPrivateKeyBytes();
  const pub = await ed.getPublicKeyAsync(priv);
  _pubkeyHex = Buffer.from(pub).toString('hex');
  return _pubkeyHex;
}

// ─── RFC 8785 JCS Canonicalization ───────────────────────────────────────────
//
// Strict implementation:
//   1. Keys sorted by Unicode code point (per RFC 8785 §3.2.3)
//   2. Non-ASCII above U+001F emitted as literal UTF-8 bytes (not \uXXXX escapes)
//   3. null values preserved at every depth
//   4. Integer-valued floats normalized to integers (ECMA-262 §7.1.12.1)
//
// This produces byte-identical output to AgentGraph's canonicalize_jcs_strict
// for the shared CTEF v0.3.1 test vectors.

function jcsSerializeValue(value) {
  if (value === null || value === undefined) {
    return 'null';
  }

  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }

  if (typeof value === 'number') {
    if (!isFinite(value)) {
      throw new Error('JCS: Infinity and NaN are not allowed in CTEF envelopes');
    }
    // ECMA-262 §7.1.12.1 — integer-valued floats normalize to integers
    if (Number.isInteger(value)) {
      return String(value);
    }
    // Use standard JSON number serialization for floats
    return JSON.stringify(value);
  }

  if (typeof value === 'string') {
    // JSON.stringify handles all necessary escapes.
    // Per RFC 8785, non-ASCII characters MUST NOT be escaped (they are UTF-8 bytes).
    // JSON.stringify in Node.js keeps non-ASCII as literal UTF-8 by default —
    // it only escapes control chars (U+0000–U+001F) and the two special chars " and \.
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    const items = value.map(jcsSerializeValue);
    return '[' + items.join(',') + ']';
  }

  if (typeof value === 'object') {
    // Sort keys by Unicode code point order (localeCompare with codePoint collation)
    const keys = Object.keys(value).sort((a, b) => {
      // RFC 8785 §3.2.3: sort by UTF-16 code unit sequence (same as JS string comparison)
      if (a < b) return -1;
      if (a > b) return 1;
      return 0;
    });

    const pairs = keys.map(k => {
      return JSON.stringify(k) + ':' + jcsSerializeValue(value[k]);
    });

    return '{' + pairs.join(',') + '}';
  }

  throw new Error(`JCS: Unsupported value type: ${typeof value}`);
}

/**
 * Canonicalize a JS object per RFC 8785 (JCS).
 * Returns a UTF-8 string of the canonical JSON bytes.
 */
function canonicalizeJcs(obj) {
  return jcsSerializeValue(obj);
}

/**
 * Compute canonical_sha256 for a given object.
 */
function canonicalSha256(obj) {
  const canonical = canonicalizeJcs(obj);
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

// ─── CTEF v0.3.1 Claim-type and scope validation ─────────────────────────────

const VALID_CLAIM_TYPES = new Set(['identity', 'transport', 'authority', 'continuity']);

// Authority-layer fields that MUST NOT appear in non-authority claims
const AUTHORITY_FIELDS = new Set(['delegation_chain_root', 'delegation_depth']);

/**
 * Detect INVALID_CLAIM_SCOPE:
 * A claim carries fields outside its declared claim_type.
 * Per spec: identity-categorized claim carrying authority-layer delegation fields → reject.
 *
 * Note: EnforcementVerdict envelopes (type='EnforcementVerdict') are verdict documents,
 * not TrustAttestation envelopes. They operate at the gateway layer and do not carry
 * a claim_type field — they are structurally valid without one.
 */
function detectScopeViolation(envelope) {
  // EnforcementVerdict is a gateway-layer document — no claim_type required
  if (envelope.type === 'EnforcementVerdict') {
    return { violated: false };
  }

  const claimType = envelope.claim_type;
  if (!claimType || !VALID_CLAIM_TYPES.has(claimType)) {
    return { violated: true, reason: `Unknown claim_type: ${claimType}` };
  }

  if (claimType !== 'authority') {
    // Check top-level delegation object for authority-only fields
    const delegation = envelope.delegation || {};
    for (const field of AUTHORITY_FIELDS) {
      if (delegation[field] !== undefined) {
        return {
          violated: true,
          reason: `claim_type '${claimType}' cannot carry authority-layer field delegation.${field}`,
        };
      }
    }
  }

  return { violated: false };
}

/**
 * Detect INVALID_COMPOSITION:
 * Well-typed authority claims with disjoint scopes cannot be composed.
 * Monotonic narrowing: intersection of all scopes must be non-empty.
 */
function detectCompositionFailure(envelope) {
  if (envelope.claim_type !== 'authority') return { failed: false };

  const delegation = envelope.delegation || {};
  const chains = delegation.chains;

  if (!Array.isArray(chains) || chains.length < 2) return { failed: false };

  // Collect all scopes
  const scopes = chains.map(c => c.scope).filter(Boolean);
  if (scopes.length < 2) return { failed: false };

  // Check for disjoint scopes (different URN segments → empty intersection)
  // Two scopes are disjoint if they do not share a common prefix beyond the base URN scheme
  const baseScopes = scopes.map(s => s.replace(/^urn:[^:]+:[^:]+:/, ''));
  const firstBase = baseScopes[0];
  const allSame = baseScopes.every(b => b === firstBase);

  if (!allSame) {
    return {
      failed: true,
      reason: `Disjoint authority scopes: [${scopes.join(', ')}]. Monotonic narrowing produces empty intersection → INVALID_COMPOSITION.`,
    };
  }

  return { failed: false };
}

/**
 * Verify a CTEF v0.3.1 envelope. Returns verdict object.
 */
function verifyCtefEnvelope(envelope) {
  // 1. Structural: scope check first (fail-closed before semantic evaluation)
  const scopeCheck = detectScopeViolation(envelope);
  if (scopeCheck.violated) {
    const canonical = canonicalizeJcs(envelope);
    const sha = createHash('sha256').update(canonical, 'utf8').digest('hex');
    return {
      verdict: 'INVALID_CLAIM_SCOPE',
      error_code: 'INVALID_CLAIM_SCOPE',
      reason: scopeCheck.reason,
      canonical_bytes_utf8: canonical,
      canonical_sha256: sha,
      pass: false,
    };
  }

  // 2. Composition check
  const compositionCheck = detectCompositionFailure(envelope);
  if (compositionCheck.failed) {
    const canonical = canonicalizeJcs(envelope);
    const sha = createHash('sha256').update(canonical, 'utf8').digest('hex');
    return {
      verdict: 'INVALID_COMPOSITION',
      error_code: 'INVALID_COMPOSITION',
      reason: compositionCheck.reason,
      canonical_bytes_utf8: canonical,
      canonical_sha256: sha,
      pass: false,
    };
  }

  // 3. Valid
  const canonical = canonicalizeJcs(envelope);
  const sha = createHash('sha256').update(canonical, 'utf8').digest('hex');
  return {
    verdict: 'valid',
    canonical_bytes_utf8: canonical,
    canonical_sha256: sha,
    pass: true,
  };
}

// ─── Per-IP free tier tracking (10 requests/day, in-memory) ──────────────────

const ipRequestCounts = new Map(); // key: `${ip}:${dayEpoch}` → count

function checkFreeQuota(ip) {
  const dayEpoch = Math.floor(Date.now() / 86_400_000);
  const key = `${ip}:${dayEpoch}`;
  const count = (ipRequestCounts.get(key) || 0) + 1;
  ipRequestCounts.set(key, count);

  // Clean old entries periodically
  if (count === 1 && ipRequestCounts.size > 50000) {
    for (const [k] of ipRequestCounts) {
      const d = parseInt(k.split(':').pop());
      if (d < dayEpoch) ipRequestCounts.delete(k);
    }
  }

  return { count, free: count <= 10 };
}

// ─── HiveTrust Passport Tier lookup (read-only, GET /verify?did=...) ─────────

const PASSPORT_TIERS = [
  { tier: 'platinum', min_trust_score: 800, description: 'Top-tier verified agent, full CTEF authority.' },
  { tier: 'gold',     min_trust_score: 600, description: 'High-confidence verified agent.' },
  { tier: 'silver',   min_trust_score: 400, description: 'Verified agent with demonstrated activity.' },
  { tier: 'bronze',   min_trust_score: 200, description: 'Registered agent, basic verification.' },
  { tier: 'prospect', min_trust_score: 0,   description: 'Registered but not yet scored.' },
];

function resolveTier(trustScore) {
  for (const t of PASSPORT_TIERS) {
    if (trustScore >= t.min_trust_score) return t;
  }
  return PASSPORT_TIERS[PASSPORT_TIERS.length - 1];
}

// ─── Test Vectors (shared with AgentGraph for byte-match verification) ────────
// These are the AgentGraph-published canonical bytes and sha256 values.
// HiveTrust MUST reproduce the same bytes for all shared vectors.

const TEST_VECTORS = {
  envelope_vector: {
    input_object: {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://agentgraph.co/ns/trust-evidence/v1',
      ],
      type: 'TrustAttestation',
      version: '0.3.1',
      claim_type: 'authority',
      provider: {
        id: 'did:web:agentgraph.co',
        name: 'AgentGraph Trust Scanner',
        category: 'static_analysis',
        version: '0.3.1',
      },
      subject: {
        did: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
        repo: 'example-org/example-repo',
        ref: 'main',
      },
      attestation: {
        type: 'SecurityAttestation',
        confidence: 0.82,
        payload: {
          trust_score: 66,
          grade: 'B',
          findings: { critical: 0, high: 2, medium: 5, total: 7 },
        },
      },
      delegation: {
        delegation_chain_root: '4f3d8defea1e82c1705c35d97ee4db046c6313ba83855a7d0de04a44f04c834a',
        delegation_depth: 2,
        canonicalization: 'RFC-8785',
      },
      issued_at: '2026-04-23T00:00:00Z',
      expires_at: '2026-04-23T01:00:00Z',
    },
    expected_canonical_sha256: '9e7b5031e46de38b5f90e895113a3f24f42a4128d8d99856a2d71e529b0f0d5c',
    expected_result: 'pass',
  },

  verdict_vector: {
    input_object: {
      type: 'EnforcementVerdict',
      version: '0.3.1',
      gateway: {
        id: 'did:web:agentgraph.co#gateway',
        name: 'AgentGraph Trust Gateway',
        version: '0.3.1',
      },
      claim: {
        action: {
          type: 'mutation:platform_access',
          target: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
          scope: 'urn:agentgraph:platform:feed:write',
        },
        evidence_basis: {
          bundle_hash: 'sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
          delegation_chain_root: '4f3d8defea1e82c1705c35d97ee4db046c6313ba83855a7d0de04a44f04c834a',
        },
        admissibility_result: 'conditional_allow',
        validity_window: {
          not_before: '2026-04-23T00:00:00Z',
          not_after: '2026-04-23T01:00:00Z',
          binding_mode: 'authority_within_window_evidence_after',
        },
        forwardability: {
          mode: 'local',
          forwardable_to: [],
          delegation_path: null,
        },
      },
      issued_at: '2026-04-23T00:00:00Z',
      expires_at: '2026-04-23T01:00:00Z',
    },
    expected_canonical_sha256: 'feb42dca4214fc46207138d676ec727d7b3d0caa1eda8c0390d2d6f6fbc28913',
    expected_result: 'pass',
  },

  scope_violation_vector: {
    input_object: {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://agentgraph.co/ns/trust-evidence/v1',
      ],
      type: 'TrustAttestation',
      version: '0.3.1',
      claim_type: 'identity',
      provider: {
        id: 'did:web:agentgraph.co',
        name: 'AgentGraph Trust Scanner',
        category: 'static_analysis',
        version: '0.3.1',
      },
      subject: {
        did: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      },
      attestation: {
        type: 'IdentityAttestation',
        confidence: 0.9,
        payload: { key_status: 'active' },
      },
      delegation: {
        delegation_chain_root: '4f3d8defea1e82c1705c35d97ee4db046c6313ba83855a7d0de04a44f04c834a',
        delegation_depth: 2,
        canonicalization: 'RFC-8785',
      },
      issued_at: '2026-04-23T00:00:00Z',
      expires_at: '2026-04-23T01:00:00Z',
    },
    expected_canonical_sha256: 'e584f1cd0885dc938da5fc23ce7e528715a0086e5464c9ed0f3c1c82b364026f',
    expected_result: 'fail-closed',
    expected_error_code: 'INVALID_CLAIM_SCOPE',
  },

  composition_failure_vector: {
    input_object: {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://agentgraph.co/ns/trust-evidence/v1',
      ],
      type: 'TrustAttestation',
      version: '0.3.1',
      claim_type: 'authority',
      provider: {
        id: 'did:web:agentgraph.co',
        name: 'AgentGraph Trust Scanner',
        category: 'static_analysis',
        version: '0.3.1',
      },
      subject: {
        did: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      },
      attestation: {
        type: 'AuthorityComposition',
        confidence: 0.7,
        payload: { composition_type: 'multi_chain' },
      },
      delegation: {
        chains: [
          {
            delegation_chain_root: '4f3d8defea1e82c1705c35d97ee4db046c6313ba83855a7d0de04a44f04c834a',
            scope: 'urn:agentgraph:platform:feed:write',
          },
          {
            delegation_chain_root: 'b11a72b09b8184e3cc4620e0d5fe0926f6fecfb8cd35c2ef364c5761647c43b4',
            scope: 'urn:agentgraph:platform:marketplace:buy',
          },
        ],
        canonicalization: 'RFC-8785',
      },
      issued_at: '2026-04-23T00:00:00Z',
      expires_at: '2026-04-23T01:00:00Z',
    },
    expected_canonical_sha256: 'f9cd10bc4e8bf34ce3aa6a0e5df0d27989e54ff41c4333c69ae3ecfaf8de0cb5',
    expected_result: 'fail-closed',
    expected_error_code: 'INVALID_COMPOSITION',
  },
};

// ─── Route: GET /.well-known/cte-test-vectors.json ───────────────────────────

router.get('/cte-test-vectors.json', (req, res) => {
  res.set('Cache-Control', 'public, max-age=300');
  return res.json({
    version: '0.3.1',
    spec: 'CTEF (Composable Trust Evidence Format)',
    provider: 'did:web:hivetrust.onrender.com',
    consortium_seat: {
      rank: 5,
      members: ['AgentGraph', 'AgentID', 'APS', 'Nobulex', 'HiveTrust'],
      freeze_commit: 'https://github.com/a2aproject/A2A/discussions/1734',
      freeze_utc: '2026-04-25T01:48:00Z',
      byte_match_run: '2026-04-30',
    },
    patent: {
      applications: ['64/049,200', '64/049,201', '64/049,202', '64/049,203', '64/049,204',
                     '64/049,205', '64/049,206', '64/049,207', '64/049,208', '64/049,209',
                     '64/049,210', '64/049,211', '64/049,212', '64/049,213', '64/049,214',
                     '64/049,215', '64/049,216', '64/049,217', '64/049,218', '64/049,219',
                     '64/049,220', '64/049,221', '64/049,222', '64/049,223', '64/049,224',
                     '64/049,225', '64/049,226'],
      priority_date: '2026-04-24',
      holder: 'Stephen A. Rotzin / TheHiveryIQ',
    },
    contract: {
      canonicalization: 'RFC 8785 (JSON Canonicalization Scheme)',
      canonicalization_rules: [
        'Keys sorted by Unicode code point.',
        'Non-ASCII above U+001F emitted as literal UTF-8 bytes (not \\uXXXX escapes).',
        'null values preserved at every depth.',
        'Integer-valued floats normalized to integers (ECMA-262 §7.1.12.1).',
      ],
      hash_algorithm: 'SHA-256',
      delegation_chain_root: 'hex(sha256(canonicalize_jcs_strict(delegation_chain)))',
      reference_implementation: 'src/routes/cte.js canonicalizeJcs() (hivetrust.onrender.com)',
    },
    claim_model: {
      claim_type: {
        closed_set: ['identity', 'transport', 'authority', 'continuity'],
        required_on_envelope: true,
        note: 'Outer discriminator for the claim-layer semantics. Added in v0.3.1. A claim carrying fields outside its declared category MUST be rejected with INVALID_CLAIM_SCOPE before semantic evaluation.',
      },
      composition_rules: {
        identity: 'Key binding — same DID across claims, same resolution path.',
        transport: 'Identity-key binding — the identity signs the transport key.',
        authority: 'Monotonic narrowing — effective scope is the intersection of every scope in the chain.',
        continuity: 'Rotation-attestation chain — history-stability under rotation.',
      },
    },
    error_codes: {
      INVALID_CLAIM_SCOPE: {
        triggers_on: "Claim carries fields outside its declared claim_type (e.g. identity-categorized claim carrying authority-layer delegation).",
        ordering: 'Structural failure precedes semantic evaluation. Fail-closed is mandatory before any layer-specific logic runs.',
        test_vector: 'scope_violation_vector (below)',
      },
      INVALID_COMPOSITION: {
        triggers_on: 'Well-typed claims at each layer cannot be combined under the composition rule (e.g. disjoint authority scopes).',
        ordering: 'Structural failure precedes semantic evaluation.',
        test_vector: 'composition_failure_vector (below)',
      },
    },
    reserved_values: {
      'claim_type.envelope': {
        status: 'reserved',
        committed_in: 'v0.3.2 or v0.3.1 errata',
        composition_rule_variants: [
          {
            name: 'zero_knowledge_membership',
            use_when: 'The envelope identity itself must stay private from the verifier.',
            shape: 'ZK proof of membership in the attestation-registry snapshot, content-addressed over the snapshot root.',
          },
          {
            name: 'signed_snapshot_attestation',
            use_when: 'The envelope is public; only the member list is sensitive.',
            shape: 'Issuer signature over {subject, registry_root, asserted_membership: true}.',
          },
        ],
        note: 'Fifth-layer regulatory-envelope attestation (Hive Civilization / HiveTrust contribution). Implementations pick by privacy requirement: ZK for private envelope identity, signed-snapshot when only the member list needs unlinkability. APS (aeoess/agent-passport-system) has committed to adopting the same claim_type value in adapter mappings when it lands.',
      },
      'evidence_basis.evidence_type.payment_execution': {
        status: 'reserved',
        committed_in: 'v0.3.2 or v0.3.1 errata',
        note: 'Payment-execution receipt as an independent signal type (HiveCompute x402 contribution). Answers "consideration was exchanged" — distinct from "task result matches spec" (SAR). Expected fields: eip3009_authorization_hash, base_tx_hash, wallet_did, amount_usdc, issued_at.',
      },
    },
    // ─── Shared test vectors (byte-match with AgentGraph, AgentID, APS, Nobulex) ─
    envelope_vector: {
      note: 'Example CTEF v0.3.1 TrustAttestation envelope (claim_type=authority) with delegation_chain_root composition per §4.6. A partner verifier MUST reproduce canonical_bytes_utf8 and canonical_sha256 exactly; divergence indicates a canonicalizer drift that would break bilateral composition.',
      input_object: TEST_VECTORS.envelope_vector.input_object,
      canonical_bytes_utf8: canonicalizeJcs(TEST_VECTORS.envelope_vector.input_object),
      canonical_sha256: canonicalSha256(TEST_VECTORS.envelope_vector.input_object),
      expected_result: 'pass',
    },
    verdict_vector: {
      note: 'Example CTEF v0.3.1 EnforcementVerdict with the 5-dimension claim-model surface per §6.3. A partner that consumes HiveTrust verdicts should verify canonical_sha256 matches what they compute locally.',
      input_object: TEST_VECTORS.verdict_vector.input_object,
      canonical_bytes_utf8: canonicalizeJcs(TEST_VECTORS.verdict_vector.input_object),
      canonical_sha256: canonicalSha256(TEST_VECTORS.verdict_vector.input_object),
      expected_result: 'pass',
    },
    scope_violation_vector: {
      note: 'Negative-path vector (v0.3.1). Envelope declares claim_type=\'identity\' but carries authority-layer delegation fields. A conformant verifier MUST reject with INVALID_CLAIM_SCOPE before semantic evaluation.',
      input_object: TEST_VECTORS.scope_violation_vector.input_object,
      canonical_bytes_utf8: canonicalizeJcs(TEST_VECTORS.scope_violation_vector.input_object),
      canonical_sha256: canonicalSha256(TEST_VECTORS.scope_violation_vector.input_object),
      expected_result: 'fail-closed',
      expected_error_code: 'INVALID_CLAIM_SCOPE',
    },
    composition_failure_vector: {
      note: 'Negative-path vector (v0.3.1). Two authority-layer delegation chains with disjoint scopes (feed:write vs marketplace:buy). Monotonic narrowing produces an empty intersection → INVALID_COMPOSITION.',
      input_object: TEST_VECTORS.composition_failure_vector.input_object,
      canonical_bytes_utf8: canonicalizeJcs(TEST_VECTORS.composition_failure_vector.input_object),
      canonical_sha256: canonicalSha256(TEST_VECTORS.composition_failure_vector.input_object),
      expected_result: 'fail-closed',
      expected_error_code: 'INVALID_COMPOSITION',
    },
  });
});

// ─── Route: GET /verify?did=... (passport tier lookup, first free) ────────────

router.get('/verify', async (req, res) => {
  const { did } = req.query;

  if (!did) {
    return err(res, SERVICE, 'MISSING_DID', 'Query parameter ?did= is required for GET /verify', 400);
  }

  // First lookup per IP per day is free
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  const dayEpoch = Math.floor(Date.now() / 86_400_000);
  const lookupKey = `passport:${ip}:${dayEpoch}`;
  const lookupCount = (ipRequestCounts.get(lookupKey) || 0) + 1;
  ipRequestCounts.set(lookupKey, lookupCount);

  // Simulate trust score lookup — in production this would query the DB
  // For now: derive a stable mock score from the DID hash
  const didHash = createHash('sha256').update(did).digest();
  const mockScore = (didHash[0] * 4) % 1000; // 0–999
  const tierInfo = resolveTier(mockScore);

  const pubkey = await getPubkeyHex();

  return ok(res, SERVICE, {
    did,
    passport_tier: tierInfo.tier,
    trust_score: mockScore,
    tier_description: tierInfo.description,
    provider: 'did:web:hivetrust.onrender.com',
    attestation_pubkey: pubkey,
    free_lookup: lookupCount === 1,
    lookups_today: lookupCount,
    ctef_version: '0.3.1',
    fixture_url: 'https://hivetrust.onrender.com/.well-known/cte-test-vectors.json',
    note: lookupCount === 1
      ? 'First passport lookup today is free.'
      : 'Subsequent lookups require payment via POST /verify.',
  });
});

// ─── Route: POST /verify (paid CTEF structural verification) ─────────────────

router.post('/verify', async (req, res) => {
  const envelope = req.body;

  if (!envelope || typeof envelope !== 'object') {
    return err(res, SERVICE, 'INVALID_BODY', 'Request body must be a JSON object (CTEF v0.3.1 envelope)', 400);
  }

  // Per-IP free tier: first 10 requests/day free
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  const { count, free } = checkFreeQuota(ip);

  if (!free && !req.paymentVerified) {
    // Return 402 with x402 payment challenge
    const PAYMENT_ADDRESS = (process.env.HIVE_PAYMENT_ADDRESS || process.env.HIVETRUST_PAYMENT_ADDRESS || '0x0000000000000000000000000000000000000000').toLowerCase();
    const USDC_CONTRACT = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
    const PRICE_USDC = 0.01;

    res.set({
      'X-Payment-Amount': String(PRICE_USDC),
      'X-Payment-Currency': 'USDC',
      'X-Payment-Network': 'base',
      'X-Payment-Address': PAYMENT_ADDRESS,
      'X-Payment-Model': 'ctef_verification_fixed',
      'X-HiveTrust-Required': 'true',
      'X-HiveTrust-Challenge': JSON.stringify({
        version: '1.0',
        protocol: 'x402',
        amount: PRICE_USDC,
        currency: 'USDC',
        network: 'base',
        chain_id: 8453,
        address: PAYMENT_ADDRESS,
        usdc_contract: USDC_CONTRACT,
        endpoint: '/verify',
        method: 'POST',
        timestamp: new Date().toISOString(),
        ttl_seconds: 300,
      }),
    });

    return res.status(402).json({
      success: false,
      error: 'Payment required',
      code: 'PAYMENT_REQUIRED',
      detail: `Free tier exhausted: ${count - 1}/10 daily free verifications used. Additional verifications cost $0.01 USDC on Base chain (8453).`,
      protocol: 'x402',
      payment: {
        amount: PRICE_USDC,
        currency: 'USDC',
        network: 'base',
        chain_id: 8453,
        address: PAYMENT_ADDRESS,
        usdc_contract: USDC_CONTRACT,
        model: 'ctef_verification_fixed',
      },
      how_to_pay: {
        step_1: `Send ${PRICE_USDC} USDC to ${PAYMENT_ADDRESS} on Base (chain ID 8453)`,
        step_2: 'Include the transaction hash in the X-Payment-Hash header',
        step_3: 'Retry this POST /verify — payment is verified on-chain automatically',
      },
      free_tier: { limit: 10, used: count - 1, period: 'per IP per day' },
    });
  }

  // Run verification
  const result = verifyCtefEnvelope(envelope);
  const pubkey = await getPubkeyHex();

  return ok(res, SERVICE, {
    verdict: result.verdict,
    pass: result.pass,
    error_code: result.error_code || null,
    reason: result.reason || null,
    canonical_bytes_utf8: result.canonical_bytes_utf8,
    canonical_sha256: result.canonical_sha256,
    ctef_version: '0.3.1',
    provider: 'did:web:hivetrust.onrender.com',
    attestation_pubkey: pubkey,
    free_tier: { used: count, limit: 10, period: 'per IP per day', paid: !free },
  });
});

// ─── Route: GET /verify/pubkey ────────────────────────────────────────────────

router.get('/verify/pubkey', async (req, res) => {
  const pubkey = await getPubkeyHex();

  return ok(res, SERVICE, {
    public_key: pubkey,
    algorithm: 'Ed25519',
    encoding: 'hex',
    purpose: 'CTEF v0.3.1 attestation signing — Apr 30 byte-match verifier discovery',
    provider: 'did:web:hivetrust.onrender.com',
    ctef_version: '0.3.1',
    consortium_seat: 5,
    consortium_members: ['AgentGraph', 'AgentID', 'APS', 'Nobulex', 'HiveTrust'],
    key_id: `did:web:hivetrust.onrender.com#ctef-signing-key-1`,
    note: process.env.HIVETRUST_SIGNING_KEY
      ? 'Production key from HIVETRUST_SIGNING_KEY env var.'
      : 'Dev fallback key — set HIVETRUST_SIGNING_KEY in production.',
  });
});

// ─── Route: GET /verify/self-test ─────────────────────────────────────────────

router.get('/verify/self-test', (req, res) => {
  const results = [];
  let passed = 0;
  let failed = 0;
  let byteMatchPassed = 0;
  let byteMatchFailed = 0;
  const byteMatchGaps = [];

  for (const [vectorName, vector] of Object.entries(TEST_VECTORS)) {
    const computed = canonicalizeJcs(vector.input_object);
    const computedSha = createHash('sha256').update(computed, 'utf8').digest('hex');
    const expectedSha = vector.expected_canonical_sha256;

    const shaMatch = computedSha === expectedSha;
    if (shaMatch) byteMatchPassed++;
    else {
      byteMatchFailed++;
      byteMatchGaps.push({
        vector: vectorName,
        expected: expectedSha,
        computed: computedSha,
        expected_len: expectedSha.length,
        computed_len: computed.length,
      });
    }

    // Test the verifier too
    const verdict = verifyCtefEnvelope(vector.input_object);
    let verdictOk = false;

    if (vector.expected_result === 'pass') {
      verdictOk = verdict.pass === true && verdict.verdict === 'valid';
    } else if (vector.expected_result === 'fail-closed') {
      verdictOk = verdict.pass === false && verdict.error_code === vector.expected_error_code;
    }

    if (verdictOk) passed++;
    else failed++;

    results.push({
      vector: vectorName,
      expected_result: vector.expected_result,
      expected_error_code: vector.expected_error_code || null,
      verdict: verdict.verdict,
      verdict_ok: verdictOk,
      canonical_sha256: computedSha,
      expected_sha256: expectedSha,
      byte_match: shaMatch,
    });
  }

  const totalTests = results.length;
  const allOk = failed === 0 && byteMatchFailed === 0;

  return ok(res, SERVICE, {
    summary: {
      total_vectors: totalTests,
      verdict_pass: passed,
      verdict_fail: failed,
      byte_match_pass: byteMatchPassed,
      byte_match_fail: byteMatchFailed,
      all_ok: allOk,
    },
    byte_match_gaps: byteMatchGaps.length > 0 ? byteMatchGaps : null,
    vectors: results,
    ctef_version: '0.3.1',
    provider: 'did:web:hivetrust.onrender.com',
    canonicalizer: 'RFC 8785 JCS — inline implementation in src/routes/cte.js',
    consortium_seat: 5,
    reference: 'https://agentgraph.co/.well-known/cte-test-vectors.json',
  });
});

export default router;

// Export canonicalizeJcs for use in other modules if needed
export { canonicalizeJcs, canonicalSha256, verifyCtefEnvelope };
