/**
 * HiveTrust — x402 Payment Middleware (USDC-ONLY)
 *
 * Implements the x402 protocol for machine-to-machine micropayments.
 * All payments are USDC on Base L2. No Stripe. No human interfaces.
 */

import {
  recordRequest,
  getApiCallPrice,
  recordRevenue,
} from '../services/pricing-engine.js';
import { getLeasePrice, getRenewalPrice } from '../services/data-oracle.js';
import { query } from '../db.js';

// ─── Configuration ───────────────────────────────────────────

const PAYMENT_ADDRESS = (process.env.HIVE_PAYMENT_ADDRESS || process.env.HIVETRUST_PAYMENT_ADDRESS || '').toLowerCase();
const HIVE_INTERNAL_KEY = process.env.HIVETRUST_SERVICE_KEY || process.env.HIVE_INTERNAL_KEY || '';
const BASE_RPC_URL = process.env.BASE_RPC_URL || 'https://mainnet.base.org';
const USDC_CONTRACT = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';

const FREE_ENDPOINTS = new Set([
  '/health',
  '/stats',
  '/pricing/status',
  '/pricing/quote',
  '/pricing/verify-subscription',
  '/pricing/verify-payment',
  '/.well-known/hivetrust.json',
  '/.well-known/hive-payments.json',
]);

const EXEMPT_ENDPOINTS = new Set([
  '/insurance/quote',
]);

const VIEWKEY_PRICING = {
  '/viewkey/verify-compliance': 0.05,
  '/viewkey/verify-bom': 0.10,
  '/viewkey/issue-certificate': 0.25,
};
const VIEWKEY_AUDIT_TRAIL_PRICE = 0.03;
const VIEWKEY_BOM_PER_ITEM = 0.02;

function getViewkeyPrice(path, body) {
  if (VIEWKEY_PRICING[path] !== undefined) {
    let amount = VIEWKEY_PRICING[path];
    if (path === '/viewkey/verify-bom' && body?.bom_items?.length) {
      amount += body.bom_items.length * VIEWKEY_BOM_PER_ITEM;
    }
    return { amount: Math.round(amount * 1e6) / 1e6, model: 'viewkey_fixed' };
  }
  if (path.startsWith('/viewkey/audit-trail/')) {
    return { amount: VIEWKEY_AUDIT_TRAIL_PRICE, model: 'viewkey_fixed' };
  }
  return null;
}

const DELEGATION_PRICING = {
  '/delegation/create':          0.10,
  '/delegation/authorize-spend': 0.05,
  '/delegation/revoke':          0.05,
  '/delegation/audit':           0.02,
};

const DELEGATION_PRICE_PREFIXES = [
  { prefix: '/delegation/agent/', price: 0.02 },
  { prefix: '/delegation/',       price: 0.02 },
];

function getDelegationPrice(path) {
  if (DELEGATION_PRICING[path] !== undefined) {
    return { amount: DELEGATION_PRICING[path], model: 'delegation_fixed' };
  }
  for (const { prefix, price } of DELEGATION_PRICE_PREFIXES) {
    if (path.startsWith(prefix)) return { amount: price, model: 'delegation_fixed' };
  }
  return null;
}

const ORACLE_FREE_PATHS = new Set([
  '/oracle/verify-lease',
  '/oracle/streams',
  '/oracle/stats',
]);

const BOND_PRICING = {
  '/bond/stake':        0.25,
  '/bond/upgrade-tier': 0.25,
  '/bond/unstake':      0.10,
};

const BOND_FREE_PATHS = new Set([
  '/bond/tiers',
  '/bond/leaderboard',
  '/bond/pool',
  '/bond/slash',
]);

function getBondPrice(path) {
  if (BOND_PRICING[path] !== undefined) {
    return { amount: BOND_PRICING[path], model: 'bond_fixed' };
  }
  if (BOND_FREE_PATHS.has(path)) return { amount: 0, model: 'bond_free' };
  if (path.startsWith('/bond/agent/') || path.startsWith('/bond/verify/')) {
    return { amount: 0, model: 'bond_free' };
  }
  return null;
}

const TRUST_SCORE_PRICE = 0.10;

// ─── DID Issuance + Credential Lifecycle Pricing ─────────────
// Per task spec: DID issuance $1.00, credential lifecycle $0.10, VC issue $0.50
// Enterprise subscription is handled at route level via Stripe-equivalent flow.
const DID_CREDENTIAL_PRICING = {
  '/trust/did/generate':          { amount: 1.00,    model: 'did_issuance' },
  '/trust/vc/issue':              { amount: 0.50,    model: 'vc_issuance' },
  '/trust/reputation/proof':      { amount: 0.10,    model: 'reputation_proof' },
  '/enterprise/subscribe':        { amount: 500.00,  model: 'enterprise_subscription' },
};

// POST /agents/:id/credentials → $0.10 per credential lifecycle event
// DELETE /agents/:id/credentials/:credId → $0.10 revoke
function getCredentialPrice(path, method) {
  // POST /agents/<id>/credentials — issue credential $0.10
  if (method === 'POST' && /^\/agents\/[^/]+\/credentials$/.test(path)) {
    return { amount: 0.10, model: 'credential_issue' };
  }
  // DELETE /agents/<id>/credentials/<credId> — revoke credential $0.10
  if (method === 'DELETE' && /^\/agents\/[^/]+\/credentials\/[^/]+$/.test(path)) {
    return { amount: 0.10, model: 'credential_revoke' };
  }
  return null;
}

function getDidCredentialPrice(path, method) {
  if (DID_CREDENTIAL_PRICING[path]) return DID_CREDENTIAL_PRICING[path];
  return getCredentialPrice(path, method);
}

// HiveCredential v1 — institutional surface (AUTHENTICATABLE pillar)
// POST /credential/issue   $0.10 USDC  — issue scoped credential
// POST /credential/verify  $0.01 USDC  — verify cred + active scope
// POST /credential/scope   $0.05 USDC  — narrow / freeze / unfreeze / revoke
// GET  /credential/pubkey  FREE        — see isFreePath()
const HIVE_CREDENTIAL_PRICING = {
  '/credential/issue':  { amount: 0.10, model: 'hive_credential_issue' },
  '/credential/verify': { amount: 0.01, model: 'hive_credential_verify' },
  '/credential/scope':  { amount: 0.05, model: 'hive_credential_scope' },
};

function getHiveCredentialPrice(path) {
  return HIVE_CREDENTIAL_PRICING[path] || null;
}

/**
 * Returns the x402 price for /trust/score/:did and /trust/protected/:did.
 * These are the two new monetised trust lookup endpoints.
 */
function getTrustLookupPrice(path) {
  if (path.startsWith('/trust/score/')) {
    return { amount: TRUST_SCORE_PRICE, model: 'trust_score_fixed' };
  }
  if (path.startsWith('/trust/protected/')) {
    return { amount: TRUST_SCORE_PRICE, model: 'trust_protected_fixed' };
  }
  return null;
}

const REPUTATION_PRICING = {
  '/reputation/compute':       0.10,
  '/reputation/decay':         0.05,
  '/reputation/revoke-memory': 0.15,
};

function getReputationPrice(path) {
  if (REPUTATION_PRICING[path] !== undefined) {
    return { amount: REPUTATION_PRICING[path], model: 'reputation_fixed' };
  }
  if (path.startsWith('/reputation/status/') || path.startsWith('/reputation/departure-cost/')) {
    return { amount: 0, model: 'reputation_free' };
  }
  return null;
}

const LIQUIDATION_PRICING = {
  '/liquidation/list': 0.25,
  '/liquidation/buy':  0.50,
};

// HiveAudit product pricing (Days 8/12/14).
// /v1/audit/log     $0.001  substrate ingress (high-volume)
// /v1/audit/verify  $0.01   third-party badge verification
// /v1/audit/list, /receipt, /badge, /readiness  FREE  read-only projections
// /v1/audit/subscribe  tier-based, handled inline by the route
// /v1/comply/start     $5,000+ engagement, handled inline by the route
const AUDIT_PRICING = {
  '/audit/log':    0.001,
  '/audit/verify': 0.01,
};

const AUDIT_FREE_PATHS = new Set([
  '/audit/list',
  '/audit/readiness',
  '/audit/pubkey',
  '/audit/well-known',
]);

function getAuditPrice(path) {
  if (AUDIT_PRICING[path] !== undefined) {
    return { amount: AUDIT_PRICING[path], model: 'audit_fixed' };
  }
  if (AUDIT_FREE_PATHS.has(path)) {
    return { amount: 0, model: 'audit_free' };
  }
  // Free read-only projections by prefix.
  if (path.startsWith('/audit/receipt/') ||
      path.startsWith('/audit/badge/') ||
      path.startsWith('/audit/verify-badge/') ||
      path.startsWith('/audit/readiness/') ||
      path.startsWith('/audit/report/')) {
    return { amount: 0, model: 'audit_free' };
  }
  return null;
}

function getLiquidationPrice(path) {
  if (LIQUIDATION_PRICING[path] !== undefined) {
    return { amount: LIQUIDATION_PRICING[path], model: 'liquidation_fixed' };
  }
  if (path.startsWith('/liquidation/valuate/')) {
    return { amount: 0.10, model: 'liquidation_fixed' };
  }
  if (path.startsWith('/liquidation/cancel/')) {
    return { amount: 0.05, model: 'liquidation_fixed' };
  }
  if (path === '/liquidation/listings' || path.startsWith('/liquidation/listing/') ||
      path === '/liquidation/history' || path === '/liquidation/stats') {
    return { amount: 0, model: 'liquidation_free' };
  }
  return null;
}

function getOraclePrice(path, body) {
  if (ORACLE_FREE_PATHS.has(path)) return { amount: 0, model: 'oracle_free' };
  if (path.startsWith('/oracle/lease/') || path.startsWith('/oracle/leases/')) {
    return { amount: 0, model: 'oracle_free' };
  }
  if (path === '/oracle/create-lease') {
    const price = getLeasePrice(body?.data_stream, body?.duration_hours);
    if (price != null) return { amount: price, model: 'oracle_lease' };
    return { amount: 0.50, model: 'oracle_lease' };
  }
  if (path === '/oracle/renew-lease') {
    const price = getRenewalPrice(body?.lease_id, body?.additional_hours);
    if (price != null) return { amount: price, model: 'oracle_lease' };
    return { amount: 0.50, model: 'oracle_lease' };
  }
  return null;
}

// ─── In-memory payment verification cache ────────────────────
const paymentCache = new Map();

// ─── Persistent Replay Protection ───────────────────────────
const spentPaymentsCache = new Set();

async function isPaymentSpent(txHash) {
  if (spentPaymentsCache.has(txHash)) return true;
  try {
    const result = await query('SELECT 1 FROM spent_payments WHERE tx_hash = $1', [txHash]);
    if (result.rows.length > 0) {
      spentPaymentsCache.add(txHash);
      return true;
    }
  } catch (err) {
    console.error('[x402] DB replay check error:', err.message);
  }
  return false;
}

function recordSpentPayment(txHash, amountUsdc, endpoint, did) {
  spentPaymentsCache.add(txHash);
  query(
    'INSERT INTO spent_payments (tx_hash, amount_usdc, endpoint, did) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING',
    [txHash, amountUsdc, endpoint || null, did || null]
  ).catch(err => {
    console.error('[x402] DB spent_payment insert error:', err.message);
  });
}

// ─── On-Chain Verification ───────────────────────────────────

const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

async function verifyPayment(hash) {
  if (!PAYMENT_ADDRESS || PAYMENT_ADDRESS === '0x0000000000000000000000000000000000000000') {
    return { valid: false, reason: 'Payment address not configured on server' };
  }

  try {
    const receiptRes = await fetch(BASE_RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0', id: 1,
        method: 'eth_getTransactionReceipt',
        params: [hash],
      }),
      signal: AbortSignal.timeout(10000),
    });
    const { result: receipt } = await receiptRes.json();
    if (!receipt || receipt.status !== '0x1') {
      return { valid: false, reason: 'Transaction not found or failed on Base L2' };
    }

    const payAddr = PAYMENT_ADDRESS.toLowerCase();

    for (const log of receipt.logs) {
      if (log.address.toLowerCase() !== USDC_CONTRACT.toLowerCase()) continue;
      if (log.topics[0] !== TRANSFER_TOPIC) continue;
      const recipient = '0x' + log.topics[2].slice(26).toLowerCase();
      if (recipient !== payAddr) continue;
      const amountRaw = parseInt(log.data, 16);
      const amountUsdc = amountRaw / 1_000_000;
      paymentCache.set(hash, { verified: true, amount: amountUsdc, timestamp: Date.now() });
      return { valid: true, amount: amountUsdc };
    }
    return { valid: false, reason: 'No USDC transfer to Hive payment address found in transaction' };
  } catch (err) {
    console.error('[x402] On-chain verification error:', err.message);
    return { valid: false, reason: 'Chain verification error — try again' };
  }
}

// ─── Middleware ───────────────────────────────────────────────

export default async function x402Middleware(req, res, next) {
  recordRequest();

  if (isFreePath(req.path)) {
    return next();
  }

  const internalKey = req.headers['x-hive-internal-key'] || req.headers['x-api-key'];
  if (HIVE_INTERNAL_KEY && internalKey === HIVE_INTERNAL_KEY) {
    req.paymentVerified = true;
    req.paymentMethod = 'internal';
    return next();
  }

  if (req.apiKey?.scopes?.includes('*') || req.apiKey?.scopes?.includes('bypass_payment')) {
    return next();
  }

  const paymentHash = req.headers['x-payment-hash'] || req.headers['x-402-tx'] || req.headers['x-payment-tx'];
  if (paymentHash) {
    if (await isPaymentSpent(paymentHash)) {
      return res.status(409).json({
        success: false,
        error: 'Payment hash already used',
        code: 'PAYMENT_REPLAY',
        hint: 'Each payment transaction can only be used once. Submit a new USDC payment for this request.',
      });
    }

    const verification = await verifyPayment(paymentHash);

    if (verification.valid) {
      const viewkeyPrice = getViewkeyPrice(req.path, req.body);
      const delegationPrice = getDelegationPrice(req.path);
      const oraclePrice = getOraclePrice(req.path, req.body);
      const bondPrice = getBondPrice(req.path);
      const reputationPrice = getReputationPrice(req.path);
      const liquidationPrice = getLiquidationPrice(req.path);
      const trustLookupPrice = getTrustLookupPrice(req.path);
      const didCredentialPrice = getDidCredentialPrice(req.path, req.method);
      const hiveCredentialPrice = getHiveCredentialPrice(req.path);
      const auditPrice = getAuditPrice(req.path);
      const requiredPrice = auditPrice || viewkeyPrice || delegationPrice || oraclePrice || bondPrice || reputationPrice || liquidationPrice || trustLookupPrice || didCredentialPrice || hiveCredentialPrice || getApiCallPrice();
      if (verification.amount < requiredPrice.amount) {
        return res.status(402).json({
          success: false,
          error: 'Payment amount insufficient',
          code: 'PAYMENT_INSUFFICIENT',
          details: `Paid ${verification.amount} USDC but endpoint requires ${requiredPrice.amount} USDC`,
          required: requiredPrice.amount,
          paid: verification.amount,
        });
      }

      recordSpentPayment(paymentHash, verification.amount, req.path, req.agentDid || null);

      req.paymentVerified = true;
      req.paymentMethod = 'x402';
      req.paymentHash = paymentHash;
      req.paymentAmount = verification.amount;
      recordRevenue(verification.amount);
      return next();
    }

    return res.status(402).json({
      success: false,
      error: 'Payment verification failed',
      code: 'PAYMENT_INVALID',
      details: verification.reason,
      hint: 'Ensure the payment hash corresponds to a confirmed Base network USDC transaction to the correct address.',
    });
  }

  const viewkeyFallback = getViewkeyPrice(req.path, req.body);
  const delegationFallback = getDelegationPrice(req.path);
  const oracleFallback = getOraclePrice(req.path, req.body);
  const bondFallback = getBondPrice(req.path);
  const reputationFallback = getReputationPrice(req.path);
  const liquidationFallback = getLiquidationPrice(req.path);
  const trustLookupFallback = getTrustLookupPrice(req.path);
  const didCredentialFallback = getDidCredentialPrice(req.path, req.method);
  const hiveCredentialFallback = getHiveCredentialPrice(req.path);
  const auditFallback = getAuditPrice(req.path);
  // Free audit reads short-circuit — propagate $0 immediately so the middleware
  // never emits a 402 challenge for promised free surfaces.
  if (auditFallback && auditFallback.amount === 0) {
    return next();
  }
  const fixedPrice = auditFallback || viewkeyFallback || delegationFallback || oracleFallback || bondFallback || reputationFallback || liquidationFallback || trustLookupFallback || didCredentialFallback || hiveCredentialFallback;
  const price = fixedPrice
    ? { ...getApiCallPrice(), amount: fixedPrice.amount, model: fixedPrice.model }
    : getApiCallPrice();

  // WWW-Authenticate advertises BOTH rails: x402 and MPP
  // IETF draft-ryan-httpauth-payment Payment header scheme for MPP rail
  res.set('WWW-Authenticate', [
    `x402 realm="hivetrust", amount="${price.amount}", currency="USDC", network="base", address="${PAYMENT_ADDRESS}"`,
    `Payment scheme="mpp", realm="hivetrust", amount="${price.amount}", currency="USDC", network="tempo", address="${PAYMENT_ADDRESS}"`,
  ].join(', '));

  res.set({
    'X-Payment-Amount': price.amount.toString(),
    'X-Payment-Currency': 'USDC',
    'X-Payment-Network': 'base',
    'X-Payment-Address': PAYMENT_ADDRESS,
    'X-Payment-Model': price.model,
    'X-Payment-Utilization': price.utilization.toString(),
    'X-HiveTrust-Required': 'true',
    'X-HiveTrust-Challenge': JSON.stringify({
      version: '1.0',
      protocol: 'x402',
      amount: price.amount,
      currency: 'USDC',
      network: 'base',
      chain_id: 8453,
      address: PAYMENT_ADDRESS,
      usdc_contract: USDC_CONTRACT,
      endpoint: req.path,
      method: req.method,
      timestamp: new Date().toISOString(),
      ttl_seconds: 300,
    }),
  });

  return res.status(402).json({
    success: false,
    error: 'Payment required',
    code: 'PAYMENT_REQUIRED',
    protocol: 'x402',
    payment: {
      amount: price.amount,
      currency: 'USDC',
      network: 'base',
      chain_id: 8453,
      address: PAYMENT_ADDRESS,
      usdc_contract: USDC_CONTRACT,
      model: price.model,
      utilization: price.utilization,
      floor: price.floor,
      ceiling: price.ceiling,
    },
    how_to_pay: {
      rail_x402: {
        step_1: `Send ${price.amount} USDC to ${PAYMENT_ADDRESS} on Base (chain ID 8453)`,
        step_2: 'Include the transaction hash in the X-Payment-Hash header',
        step_3: 'Retry this request — payment is verified on-chain automatically',
      },
      rail_mpp: {
        step_1: `Send ${price.amount} USDCe to ${PAYMENT_ADDRESS} on Tempo (or Base)`,
        step_2: 'Include in Payment header: scheme="mpp", tx_hash="0x...", rail="tempo"',
        step_3: 'Retry request — MPP payment verified on-chain via Tempo RPC',
        tempo_rpc: 'https://rpc.tempo.xyz',
      },
    },
    rails_accepted: ['x402', 'mpp'],
    subscription_tiers: {
      citizen:     { usdc_onetime: 49,   calls: '100/day',       label: 'Citizen Pass' },
      pro:         { usdc_monthly: 149,  calls: '10,000/month',  label: 'Pro Operator' },
      enterprise:  { usdc_monthly: 999,  calls: 'Unlimited',     label: 'Enterprise Operator' },
      fleet:       { usdc_monthly: 4999, calls: 'Unlimited+',    label: 'Fleet Commander' },
    },
  });
}

export function registerPayment(hash, amount) {
  paymentCache.set(hash, { verified: true, amount, timestamp: Date.now() });
}

function isFreePath(path) {
  if (FREE_ENDPOINTS.has(path)) return true;
  if (EXEMPT_ENDPOINTS.has(path)) return true;
  if (path.startsWith('/verify_agent_risk')) return true;
  if (path.startsWith('/pricing')) return true;
  // Identity passport handles its own BOGO/x402/enterprise gating internally
  if (path.startsWith('/identity/')) return true;
  if (path === '/trust/wallet-attestation' || path === '/trust/zk-status') return true;
  if (path === '/trust/register' || path === '/trust/issue-smsh' || path.startsWith('/trust/lookup')) return true;  // self-registration and public lookup are always free
  // NOTE: /trust/issue (credential issuance) and /trust/did/generate and /trust/vc/issue are now PAID — see DID_CREDENTIAL_PRICING table
  if (path.startsWith('/trust/schema/')) return true;  // public schema documents (JSON-LD context + spec)
  if (path.startsWith('/trust/vc/supermodel')) return true;  // Hive Supermodel credential issuance — free roster identity
  if (ORACLE_FREE_PATHS.has(path)) return true;
  if (path.startsWith('/oracle/lease/') || path.startsWith('/oracle/leases/')) return true;
  if (BOND_FREE_PATHS.has(path)) return true;
  if (path.startsWith('/bond/agent/') || path.startsWith('/bond/verify/')) return true;
  if (path.startsWith('/reputation/status/') || path.startsWith('/reputation/departure-cost/')) return true;
  if (path === '/liquidation/listings' || path.startsWith('/liquidation/listing/') ||
      path === '/liquidation/history' || path === '/liquidation/stats') return true;
  // HiveComply (Day 14): all paths handle pricing inline (Stripe / USDC settlement_tx),
  // not via x402 micropay middleware. Webhook signature verifies authenticity.
  if (path.startsWith('/comply/')) return true;
  // HiveCredential pubkey — free Ed25519 issuer key for offline verify
  if (path === '/credential/pubkey') return true;
  // HiveAudit free read projections — belt-and-suspenders alongside getAuditPrice().
  if (path.startsWith('/audit/readiness/') ||
      path.startsWith('/audit/badge/') ||
      path.startsWith('/audit/verify-badge/') ||
      path.startsWith('/audit/receipt/') ||
      path === '/audit/list' ||
      path === '/audit/pubkey') return true;
  // smash.prov routes — always free
  if (path.startsWith('/prov/') || path === '/prov/pubkey' || path === '/prov/verify') return true;
  return false;
}

export { paymentCache };
