/**
 * Hive Supermodel Schema v1
 *
 * Inline copies of the canonical schema documents served at:
 *   GET /v1/trust/schema/supermodel/v1.jsonld
 *   GET /v1/trust/schema/supermodel/v1.json
 *
 * The matching files in public/schema/supermodel/ are the source of truth for
 * documentation and downstream consumers; this module embeds them so the server
 * can serve them without filesystem reads.
 */

export const SUPERMODEL_CONTEXT_V1 = {
  '@context': {
    '@version': 1.1,
    '@protected': true,

    hsm: 'https://hivetrust.hiveagentiq.com/v1/trust/schema/supermodel/v1#',

    HiveSupermodelCredential: {
      '@id': 'hsm:HiveSupermodelCredential',
      '@context': {
        '@version': 1.1,
        '@protected': true,
        id: '@id',
        type: '@type',

        codename: { '@id': 'hsm:codename', '@type': 'https://www.w3.org/2001/XMLSchema#string' },
        vibe: { '@id': 'hsm:vibe', '@type': 'https://www.w3.org/2001/XMLSchema#string' },
        wallet: { '@id': 'hsm:wallet', '@type': 'https://www.w3.org/2001/XMLSchema#string' },
        wallet_chain: { '@id': 'hsm:walletChain', '@type': 'https://www.w3.org/2001/XMLSchema#string' },
        pool_disposition: { '@id': 'hsm:poolDisposition', '@type': 'https://www.w3.org/2001/XMLSchema#string' },
        pool_workers: {
          '@id': 'hsm:poolWorkers',
          '@container': '@list',
          '@type': 'https://www.w3.org/2001/XMLSchema#string',
        },
        tier_target: { '@id': 'hsm:tierTarget', '@type': 'https://www.w3.org/2001/XMLSchema#string' },
        contrail_color: { '@id': 'hsm:contrailColor', '@type': 'https://www.w3.org/2001/XMLSchema#string' },
        carousel_priority: {
          '@id': 'hsm:carouselPriority',
          '@container': '@list',
          '@type': 'https://www.w3.org/2001/XMLSchema#string',
        },
        roster_position: { '@id': 'hsm:rosterPosition', '@type': 'https://www.w3.org/2001/XMLSchema#integer' },
        issued_at: { '@id': 'hsm:issuedAt', '@type': 'https://www.w3.org/2001/XMLSchema#dateTime' },
      },
    },
  },
};

export const SUPERMODEL_SPEC_V1 = {
  schema: 'Hive Supermodel Schema',
  version: 'v1',
  id: 'https://hivetrust.hiveagentiq.com/v1/trust/schema/supermodel/v1',
  context: 'https://hivetrust.hiveagentiq.com/v1/trust/schema/supermodel/v1.jsonld',
  credential_type: 'HiveSupermodelCredential',
  description:
    'A Hive Supermodel Credential identifies an autonomous agent within the Hive Civilization roster. It binds a verifiable DID to a Base L2 wallet, a routing pool, a tier target, and a public-facing codename + aesthetic signature (contrail color). Issued exclusively by HiveTrust to agents in Hive Civilization rosters; verifiable via VCDM 2.0 Ed25519Signature2020 proofs.',
  issuer: 'HiveTrust (did:hive:hivetrust-issuer-001)',
  subject_binding: 'did:hive:agent-{hash} bound to a Base L2 wallet via the wallet field',
  verifiable_credential_format: 'W3C VCDM 2.0',
  proof_format: 'Ed25519Signature2020',
  fields: {
    codename: {
      type: 'string',
      required: true,
      description: 'Public roster identifier. Single-word, uppercase, non-namespaced.',
    },
    vibe: { type: 'string', required: false, description: 'Free-form persona descriptor.' },
    wallet: {
      type: 'string (0x-prefixed 40-char hex)',
      required: true,
      description: 'Base L2 EOA address bound to this DID.',
    },
    wallet_chain: { type: 'string', required: false, default: 'base', description: 'Chain identifier.' },
    pool_disposition: {
      type: 'string',
      required: true,
      description:
        "Routing pool. Values: 'treasury' | 'kimi1' | 'kimi2' | 'kimi3' | 'manus2_ab' | 'manus2_cd' | 'cold_reserve' | 'standby'.",
    },
    pool_workers: {
      type: 'array<string>',
      required: false,
      description: 'Worker wallet identifiers backing this pool.',
    },
    tier_target: {
      type: 'string',
      required: false,
      description: "Hive tier target. Values: 'VOID' | 'SOLX' | 'SOLX_FENR' | 'FENR' | 'n/a'.",
    },
    contrail_color: { type: 'string', required: false, description: 'Aesthetic signature color.' },
    carousel_priority: { type: 'array<string>', required: false, description: 'Ordered carousel verticals.' },
    roster_position: { type: 'integer', required: false, description: 'Numeric slot in the roster.' },
    issued_at: { type: 'ISO 8601 datetime', required: true, description: 'Issuance timestamp.' },
  },
};

// ─── Validation ─────────────────────────────────────────────────────────────

const VALID_POOL_DISPOSITIONS = new Set([
  'treasury',
  'kimi1',
  'kimi2',
  'kimi3',
  'manus2_ab',
  'manus2_cd',
  'cold_reserve',
  'standby',
]);

const VALID_TIER_TARGETS = new Set(['VOID', 'SOLX', 'SOLX_FENR', 'FENR', 'n/a']);

/**
 * Validate a candidate supermodel claims object.
 * Returns { ok: true } or { ok: false, code, message }.
 */
export function validateSupermodelClaims(claims = {}) {
  if (!claims || typeof claims !== 'object') {
    return { ok: false, code: 'INVALID_CLAIMS', message: 'claims must be an object' };
  }

  const { codename, wallet, pool_disposition, tier_target, roster_position } = claims;

  if (!codename || typeof codename !== 'string') {
    return { ok: false, code: 'MISSING_CODENAME', message: 'codename is required (string)' };
  }
  if (!/^[A-Z][A-Z0-9_-]{0,31}$/.test(codename)) {
    return {
      ok: false,
      code: 'INVALID_CODENAME',
      message: 'codename must be uppercase, alphanumeric (with - or _), 1–32 chars',
    };
  }

  if (!wallet || typeof wallet !== 'string') {
    return { ok: false, code: 'MISSING_WALLET', message: 'wallet is required (string)' };
  }
  if (!/^0x[a-fA-F0-9]{40}$/.test(wallet)) {
    return {
      ok: false,
      code: 'INVALID_WALLET',
      message: 'wallet must be a 0x-prefixed 40-char hex address',
    };
  }

  if (!pool_disposition || !VALID_POOL_DISPOSITIONS.has(pool_disposition)) {
    return {
      ok: false,
      code: 'INVALID_POOL_DISPOSITION',
      message: `pool_disposition must be one of: ${[...VALID_POOL_DISPOSITIONS].join(', ')}`,
    };
  }

  if (tier_target !== undefined && !VALID_TIER_TARGETS.has(tier_target)) {
    return {
      ok: false,
      code: 'INVALID_TIER_TARGET',
      message: `tier_target must be one of: ${[...VALID_TIER_TARGETS].join(', ')}`,
    };
  }

  if (
    roster_position !== undefined &&
    (!Number.isInteger(roster_position) || roster_position < 1 || roster_position > 999)
  ) {
    return {
      ok: false,
      code: 'INVALID_ROSTER_POSITION',
      message: 'roster_position must be an integer between 1 and 999',
    };
  }

  return { ok: true };
}
