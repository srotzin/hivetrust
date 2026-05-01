/**
 * HiveTrust — Identity Passport Endpoint
 * GET /v1/identity/:did/passport
 *
 * Returns a JCS-canonicalized, ed25519-signed JSON envelope aggregating a
 * DID's full Hive credential graph in one call. Other services consume this
 * to make trust decisions without N upstream round-trips.
 *
 * Pricing: $0.25/read · first call free (BOGO) · enterprise $2,000/mo unlimited
 * x402 wired with on-chain USDC verification.
 * Spectral receipt emitted on every paid read.
 */

import { Router } from 'express';
import * as ed from '@noble/ed25519';
import { canonicalize, canonicalBytes } from '../lib/canonical.js';
import { query } from '../db.js';
import { ok, err } from '../ritz.js';

const router = Router();
const SERVICE = 'hivetrust';

// ─── Constants ───────────────────────────────────────────────

const PASSPORT_PRICE_USDC = 0.25;
const ENTERPRISE_MONTHLY_USDC = 2000;
const PAYMENT_ADDRESS = (process.env.HIVE_PAYMENT_ADDRESS || process.env.HIVETRUST_PAYMENT_ADDRESS || '0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E').toLowerCase();
const USDC_CONTRACT = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const BASE_RPC_URL = process.env.BASE_RPC_URL || 'https://mainnet.base.org';
const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const SPECTRAL_RECEIPT_URL = 'https://hive-receipt.onrender.com/v1/receipt/sign';
const HIVE_INTERNAL_KEY = process.env.HIVETRUST_SERVICE_KEY || process.env.HIVE_INTERNAL_KEY || '';

// Downstream service URLs
const HIVETRUST_HOST = process.env.HIVETRUST_HOST || 'https://hivetrust.onrender.com';
const AML_HOST = process.env.AML_HOST || 'https://hive-mcp-aml-screen.onrender.com';
const INSURANCE_HOST = process.env.INSURANCE_HOST || 'https://hive-mcp-insurance.onrender.com';
const IDENTITY_HOST = process.env.IDENTITY_HOST || 'https://hive-mcp-identity.onrender.com';
const RECEIPT_HOST = process.env.RECEIPT_HOST || 'https://hive-receipt.onrender.com';

// ─── BOGO / first-call tracking (in-memory) ─────────────────
// Production: swap for DB-backed per-DID call log.
const firstCallRegistry = new Set();  // DIDs that have used their free call
const paidCallCount = new Map();      // DID → paid call count (for loyalty 6th-free)
const LOYALTY_THRESHOLD = 6;

// ─── Enterprise subscription check ──────────────────────────
const enterpriseSubscribers = new Map(); // DID → expires_ms

function isEnterpriseActive(did) {
  const exp = enterpriseSubscribers.get(did);
  return exp && exp > Date.now();
}

// ─── Signing key (reuses hivetrust agent key) ────────────────
let _signerKey = null;

async function getSignerKey() {
  if (_signerKey) return _signerKey;
  // Use deterministic seed from env if available, else generate
  const seedHex = process.env.SERVER_DID_SEED || process.env.PASSPORT_SIGNING_SEED;
  let privKey;
  if (seedHex && seedHex.length >= 64) {
    privKey = Uint8Array.from(Buffer.from(seedHex.slice(0, 64), 'hex'));
  } else {
    // Derive from HIVE_INTERNAL_KEY for determinism across cold starts
    const anchor = HIVE_INTERNAL_KEY || 'hive-passport-issuer-2026';
    const { createHash } = await import('crypto');
    const seed = createHash('sha256').update(anchor + '-passport-signing-key').digest();
    privKey = Uint8Array.from(seed);
  }
  const pubKey = await ed.getPublicKeyAsync(privKey);
  _signerKey = { privKey, pubKey };
  return _signerKey;
}

// ─── Helpers ─────────────────────────────────────────────────

function bytesToBase64url(bytes) {
  return Buffer.from(bytes).toString('base64')
    .replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

/**
 * Sign a JCS-canonicalized object with ed25519.
 * Returns "ed25519:<base64url-signature>"
 */
async function signPassport(payload) {
  const { privKey } = await getSignerKey();
  const bytes = canonicalBytes(payload);
  const sig = await ed.signAsync(bytes, privKey);
  return `ed25519:${bytesToBase64url(sig)}`;
}

/**
 * Fetch JSON from a Hive service with a short timeout.
 * Returns { data, error } — never throws.
 */
async function safeFetch(url, opts = {}) {
  try {
    const res = await fetch(url, {
      ...opts,
      signal: AbortSignal.timeout(opts.timeout || 5000),
      headers: {
        'Content-Type': 'application/json',
        'X-Hive-Internal-Key': HIVE_INTERNAL_KEY,
        ...(opts.headers || {}),
      },
    });
    const json = await res.json();
    return { data: json, status: res.status };
  } catch (e) {
    return { data: null, error: e.message };
  }
}

/**
 * Emit a non-blocking Spectral receipt for every paid passport read.
 */
function emitSpectralReceipt(did, amount) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 4000);
  fetch(SPECTRAL_RECEIPT_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Hive-Internal-Key': HIVE_INTERNAL_KEY },
    body: JSON.stringify({
      issuer_did: 'did:hive:hivetrust-passport',
      event_type: 'passport_read',
      amount_usd: amount,
      currency: 'USDC',
      network: 'base',
      subject_did: did,
      pay_to: PAYMENT_ADDRESS,
      brand: '#C08D23',
    }),
    signal: controller.signal,
  }).catch(() => {}).finally(() => clearTimeout(timeout));
}

// ─── On-chain USDC payment verification ─────────────────────

async function verifyPaymentTx(txHash, requiredUsdc) {
  if (!PAYMENT_ADDRESS || PAYMENT_ADDRESS === '0x0000000000000000000000000000000000000000') {
    return { valid: false, reason: 'Payment address not configured' };
  }
  try {
    const res = await fetch(BASE_RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0', id: 1,
        method: 'eth_getTransactionReceipt',
        params: [txHash],
      }),
      signal: AbortSignal.timeout(10000),
    });
    const { result: receipt } = await res.json();
    if (!receipt || receipt.status !== '0x1') {
      return { valid: false, reason: 'Transaction not found or failed on Base L2' };
    }
    for (const log of receipt.logs) {
      if (log.address.toLowerCase() !== USDC_CONTRACT.toLowerCase()) continue;
      if (log.topics[0] !== TRANSFER_TOPIC) continue;
      const recipient = '0x' + log.topics[2].slice(26).toLowerCase();
      if (recipient !== PAYMENT_ADDRESS) continue;
      const amountUsdc = parseInt(log.data, 16) / 1_000_000;
      if (amountUsdc < requiredUsdc) {
        return { valid: false, reason: `Paid ${amountUsdc} USDC but passport requires ${requiredUsdc} USDC` };
      }
      return { valid: true, amount: amountUsdc };
    }
    return { valid: false, reason: 'No USDC transfer to Hive payment address found in tx' };
  } catch (e) {
    return { valid: false, reason: `Chain verification error: ${e.message}` };
  }
}

// ─── Aggregate credential graph from DB ─────────────────────

async function fetchLocalCredentials(did) {
  try {
    // Try to find agent by DID and fetch their credentials
    const agentRes = await query(
      'SELECT id, trust_score, created_at FROM agents WHERE did = $1 LIMIT 1',
      [did]
    );
    if (!agentRes.rows.length) return { trust_score: null, credentials: [], receipt_count: 0 };

    const agent = agentRes.rows[0];
    const credRes = await query(
      'SELECT id, type, issuer, issued_at, status FROM credentials WHERE agent_id = $1 ORDER BY issued_at DESC LIMIT 100',
      [agent.id]
    );

    // Count Spectral receipts for this DID
    let receiptCount = 0;
    try {
      const rRes = await query(
        'SELECT COUNT(*) as cnt FROM spent_payments WHERE did = $1',
        [did]
      );
      receiptCount = parseInt(rRes.rows[0]?.cnt || '0', 10);
    } catch (_) { /* spent_payments may not have this did */ }

    return {
      trust_score: parseFloat(agent.trust_score) || 500,
      credentials: credRes.rows.map(c => ({
        vc_id: c.id,
        type: c.type || 'HiveCredential',
        issuer_did: c.issuer || 'did:hive:hivetrust',
        issued_at: c.issued_at,
        status: c.status || 'active',
      })),
      receipt_count: receiptCount,
    };
  } catch (e) {
    console.warn('[passport] DB credential fetch error:', e.message);
    return { trust_score: null, credentials: [], receipt_count: 0, _error: e.message };
  }
}

// ─── Aggregate federation status from hive-mcp-identity ─────

async function fetchFederations(did) {
  const url = `${IDENTITY_HOST}/v1/identity/federation/${encodeURIComponent(did)}`;
  const { data, error } = await safeFetch(url);
  if (error || !data) return { federations: null, _error: error || 'fetch_failed' };

  // Normalize — hive-mcp-identity may return different shapes
  const providers = data?.data?.providers || data?.providers || [];
  const federations = providers.length
    ? providers.map(p => ({ provider: p.name || p.provider, status: p.status || 'linked' }))
    : [
        { provider: 'microsoft_entra', status: 'not_linked' },
        { provider: 'google_identity', status: 'not_linked' },
      ];
  return { federations };
}

// ─── Aggregate AML status from hive-mcp-aml-screen ──────────

async function fetchAmlStatus(did) {
  const url = `${AML_HOST}/v1/aml/screen?did=${encodeURIComponent(did)}`;
  const { data, error } = await safeFetch(url, { timeout: 6000 });
  if (error || !data) return { aml_status: null, _error: error || 'fetch_failed' };

  const aml = data?.data || data || {};
  return {
    aml_status: {
      status: aml.status || aml.result || 'unknown',
      last_checked: aml.checked_at || aml.timestamp || new Date().toISOString(),
      source: aml.source || 'hive-mcp-aml-screen',
    },
  };
}

// ─── Aggregate insurance coverage from hive-mcp-insurance ───

async function fetchInsurance(did) {
  const url = `${INSURANCE_HOST}/v1/insurance/coverage?did=${encodeURIComponent(did)}`;
  const { data, error } = await safeFetch(url, { timeout: 6000 });
  if (error || !data) return { insurance: null, _error: error || 'fetch_failed' };

  const coverage = data?.data?.policies || data?.policies || [];
  return {
    insurance: coverage.map(p => ({
      insurer: p.insurer || p.provider || 'unknown',
      policy_id: p.policy_id || p.id,
      expires: p.expires_at || p.expiry,
    })),
  };
}

// ─── Fetch agent cards from hivetrust / agent-sitemap ────────

async function fetchAgentCards(did) {
  try {
    // Check trust registry for agent cards associated with this DID
    const agentRes = await query(
      'SELECT agent_card_url, updated_at FROM agents WHERE did = $1 LIMIT 1',
      [did]
    );
    if (!agentRes.rows.length || !agentRes.rows[0].agent_card_url) {
      return { agent_cards: [] };
    }
    const row = agentRes.rows[0];
    return {
      agent_cards: [{
        card_url: row.agent_card_url,
        last_verified: row.updated_at || new Date().toISOString(),
      }],
    };
  } catch (e) {
    return { agent_cards: [], _error: e.message };
  }
}

// ─── Replay protection for passport payments ─────────────────

const spentPassportPayments = new Set();

async function isPassportPaymentSpent(txHash) {
  if (spentPassportPayments.has(txHash)) return true;
  try {
    const r = await query('SELECT 1 FROM spent_payments WHERE tx_hash = $1 AND endpoint = $2', [txHash, 'passport']);
    if (r.rows.length) { spentPassportPayments.add(txHash); return true; }
  } catch (_) {}
  return false;
}

function recordPassportPayment(txHash, did) {
  spentPassportPayments.add(txHash);
  query(
    'INSERT INTO spent_payments (tx_hash, amount_usdc, endpoint, did) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING',
    [txHash, PASSPORT_PRICE_USDC, 'passport', did]
  ).catch(() => {});
}

// ─── Enterprise subscription endpoint ────────────────────────

/**
 * POST /v1/identity/passport/subscribe
 * Activate enterprise unlimited passport tier for a DID.
 * Requires x402 payment of $2,000 USDC or tx_hash.
 */
router.post('/subscribe', async (req, res) => {
  const { did, tx_hash } = req.body || {};
  if (!did) return res.status(400).json({ success: false, error: 'did required' });

  if (tx_hash) {
    const v = await verifyPaymentTx(tx_hash, ENTERPRISE_MONTHLY_USDC);
    if (!v.valid) {
      return res.status(402).json({
        success: false,
        error: 'Enterprise passport subscription payment failed',
        details: v.reason,
        x402: {
          type: 'x402',
          version: '1',
          kind: 'passport_enterprise',
          asking_usd: ENTERPRISE_MONTHLY_USDC,
          asset: 'USDC',
          asset_address: USDC_CONTRACT,
          network: 'base',
          pay_to: PAYMENT_ADDRESS,
          billing: 'monthly',
        },
      });
    }
    // Activate 30-day window
    enterpriseSubscribers.set(did, Date.now() + 30 * 24 * 60 * 60 * 1000);
    emitSpectralReceipt(did, ENTERPRISE_MONTHLY_USDC);
    return ok(res, SERVICE, {
      subscribed: true,
      did,
      tier: 'enterprise',
      expires_ms: enterpriseSubscribers.get(did),
      unlimited_passport_reads: true,
    });
  }

  // No tx_hash — return 402
  return res.status(402).json({
    success: false,
    error: 'Payment required for enterprise passport subscription',
    x402: {
      type: 'x402',
      version: '1',
      kind: 'passport_enterprise',
      asking_usd: ENTERPRISE_MONTHLY_USDC,
      asset: 'USDC',
      asset_address: USDC_CONTRACT,
      network: 'base',
      pay_to: PAYMENT_ADDRESS,
      billing: 'monthly',
      bogo: { first_call_free: true, loyalty_every_n: LOYALTY_THRESHOLD },
    },
  });
});

// ─── Issuer DID document endpoint ────────────────────────────

/**
 * GET /.well-known/did.json  (referenced by the passport's issuer field)
 * Standard W3C DID document for the hive:trust issuer.
 */
router.get('/.well-known/did.json', async (req, res) => {
  const { pubKey } = await getSignerKey();
  const pubKeyHex = Buffer.from(pubKey).toString('hex');

  return res.json({
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
    ],
    id: 'did:hive:trust',
    verificationMethod: [
      {
        id: 'did:hive:trust#passport-signing-key-2026',
        type: 'Ed25519VerificationKey2020',
        controller: 'did:hive:trust',
        publicKeyHex: pubKeyHex,
        publicKeyBase64url: bytesToBase64url(pubKey),
      },
    ],
    authentication: ['did:hive:trust#passport-signing-key-2026'],
    assertionMethod: ['did:hive:trust#passport-signing-key-2026'],
    service: [
      {
        id: 'did:hive:trust#passport',
        type: 'PassportService',
        serviceEndpoint: `${HIVETRUST_HOST}/v1/identity/{did}/passport`,
      },
    ],
    _hive: {
      brand: '#C08D23',
      treasury: '0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E',
      usdc_contract: USDC_CONTRACT,
      network: 'base',
      spec: 'hive-passport-v1',
    },
  });
});

// ─── Main passport endpoint ───────────────────────────────────

/**
 * GET /v1/identity/:did/passport
 *
 * Returns a signed passport envelope. Payment gates:
 *   - First call free (BOGO) via x-hive-did header
 *   - $0.25 USDC per read via X-Payment-Hash header
 *   - Enterprise $2,000/mo unlimited via /v1/identity/passport/subscribe
 *   - Internal key bypass (X-Hive-Internal-Key)
 */
router.get('/:did/passport', async (req, res) => {
  const { did } = req.params;
  if (!did || !did.includes(':')) {
    return res.status(400).json({
      success: false,
      error: 'Invalid DID format. Expected did:<method>:<id>',
    });
  }

  const now = Date.now();

  // ─── Access control ─────────────────────────────────────────

  // 1. Internal key bypass
  const internalKey = req.headers['x-hive-internal-key'] || req.headers['x-api-key'];
  const isInternal = HIVE_INTERNAL_KEY && internalKey === HIVE_INTERNAL_KEY;

  // 2. Enterprise subscriber bypass
  const callerDid = req.headers['x-hive-did'] || req.agentDid;
  const isEnterprise = callerDid && isEnterpriseActive(callerDid);

  // 3. Auth middleware bypass (set by existing x402Middleware upstream)
  const alreadyPaid = req.paymentVerified && req.paymentAmount >= PASSPORT_PRICE_USDC;

  // 4. First-call free (BOGO)
  const bogoKey = callerDid || req.ip;
  const isFirstCall = !firstCallRegistry.has(bogoKey);

  let paymentVerified = isInternal || isEnterprise || alreadyPaid;
  let isFreeRead = false;
  let paidAmount = 0;

  if (!paymentVerified) {
    if (isFirstCall && bogoKey) {
      // Grant BOGO first call
      firstCallRegistry.add(bogoKey);
      paymentVerified = true;
      isFreeRead = true;
    } else {
      // Check for explicit payment hash
      const txHash = req.headers['x-payment-hash'] || req.headers['x-402-tx'];

      if (!txHash) {
        // Check loyalty (every 6th paid call free)
        const paidCount = paidCallCount.get(bogoKey) || 0;
        if (paidCount > 0 && paidCount % LOYALTY_THRESHOLD === 0) {
          paymentVerified = true;
          isFreeRead = true;
        } else {
          return res.status(402).json({
            success: false,
            error: 'Payment required for passport read',
            code: 'PAYMENT_REQUIRED',
            protocol: 'x402',
            passport_price_usdc: PASSPORT_PRICE_USDC,
            payment: {
              amount: PASSPORT_PRICE_USDC,
              currency: 'USDC',
              network: 'base',
              chain_id: 8453,
              address: PAYMENT_ADDRESS,
              usdc_contract: USDC_CONTRACT,
            },
            bogo: {
              first_call_free: true,
              claim_with: 'x-hive-did header',
              loyalty_free_every_n: LOYALTY_THRESHOLD,
              paid_calls_so_far: paidCallCount.get(bogoKey) || 0,
            },
            enterprise: {
              tier: 'unlimited',
              price_usd_monthly: ENTERPRISE_MONTHLY_USDC,
              subscribe: `POST ${HIVETRUST_HOST}/v1/identity/passport/subscribe`,
            },
            how_to_pay: {
              step_1: `Send ${PASSPORT_PRICE_USDC} USDC to ${PAYMENT_ADDRESS} on Base (chain ID 8453)`,
              step_2: 'Retry with X-Payment-Hash: <tx_hash> header',
              step_3: 'Or subscribe to enterprise for unlimited reads at $2,000/mo',
            },
          });
        }
      } else {
        // Verify tx hash
        if (await isPassportPaymentSpent(txHash)) {
          return res.status(409).json({
            success: false,
            error: 'Payment hash already used for passport read',
            code: 'PAYMENT_REPLAY',
          });
        }
        const v = await verifyPaymentTx(txHash, PASSPORT_PRICE_USDC);
        if (!v.valid) {
          return res.status(402).json({
            success: false,
            error: 'Passport payment verification failed',
            code: 'PAYMENT_INVALID',
            details: v.reason,
          });
        }
        recordPassportPayment(txHash, callerDid || did);
        paymentVerified = true;
        paidAmount = v.amount;
        // Track loyalty counter
        const current = paidCallCount.get(bogoKey) || 0;
        paidCallCount.set(bogoKey, current + 1);
      }
    }
  }

  if (!paymentVerified) {
    return res.status(402).json({ success: false, error: 'Payment required' });
  }

  // ─── Aggregate data sources ─────────────────────────────────

  const degradedFields = [];

  // Parallel fan-out to all upstream services
  const [
    localResult,
    federationResult,
    amlResult,
    insuranceResult,
    agentCardResult,
  ] = await Promise.allSettled([
    fetchLocalCredentials(did),
    fetchFederations(did),
    fetchAmlStatus(did),
    fetchInsurance(did),
    fetchAgentCards(did),
  ]);

  // Unpack results — degrade gracefully on failures
  const local = localResult.status === 'fulfilled'
    ? localResult.value
    : { trust_score: null, credentials: [], receipt_count: 0, _error: localResult.reason?.message };

  const federation = federationResult.status === 'fulfilled'
    ? federationResult.value
    : { federations: null, _error: federationResult.reason?.message };

  const aml = amlResult.status === 'fulfilled'
    ? amlResult.value
    : { aml_status: null, _error: amlResult.reason?.message };

  const insurance = insuranceResult.status === 'fulfilled'
    ? insuranceResult.value
    : { insurance: null, _error: insuranceResult.reason?.message };

  const agentCards = agentCardResult.status === 'fulfilled'
    ? agentCardResult.value
    : { agent_cards: [], _error: agentCardResult.reason?.message };

  if (local._error) degradedFields.push('trust_score');
  if (federation._error) degradedFields.push('federations');
  if (aml._error) degradedFields.push('aml_status');
  if (insurance._error) degradedFields.push('insurance');
  if (agentCards._error) degradedFields.push('agent_cards');

  const isPartial = degradedFields.length > 0;

  // ─── Build unsigned passport body ────────────────────────────

  const issuedAt = now;
  const expiresAt = now + 24 * 60 * 60 * 1000; // 24h TTL

  const passportBody = {
    did,
    issued_at: issuedAt,
    expires_at: expiresAt,
    trust_score: local.trust_score,
    credentials: local.credentials,
    agent_cards: agentCards.agent_cards || [],
    federations: federation.federations || [],
    aml_status: aml.aml_status || { status: 'unknown', last_checked: null, source: null },
    insurance: insurance.insurance || [],
    receipt_count: local.receipt_count || 0,
    issuer: 'did:hive:trust',
  };

  if (isPartial) {
    passportBody.partial = true;
    passportBody.degraded_fields = degradedFields;
  }

  // ─── Sign the passport (JCS-canonical) ───────────────────────

  const signature = await signPassport(passportBody);

  const passport = {
    ...passportBody,
    signature,
  };

  // ─── Emit Spectral receipt on paid reads ─────────────────────

  if (!isFreeRead && !isInternal) {
    emitSpectralReceipt(did, paidAmount || PASSPORT_PRICE_USDC);
  }

  // ─── Return signed envelope ───────────────────────────────────

  return res.status(200).json({
    success: true,
    service: SERVICE,
    request_id: `psp_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    data: passport,
    meta: {
      spec: 'hive-passport-v1',
      canonical_algorithm: 'JCS-RFC8785',
      signing_algorithm: 'Ed25519',
      issuer_doc: `${HIVETRUST_HOST}/.well-known/did.json`,
      free_read: isFreeRead,
      enterprise: isEnterprise || false,
      partial: isPartial,
    },
  });
});

export default router;
