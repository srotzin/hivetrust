/**
 * HiveTrust — x402 Payment Middleware (USDC-ONLY)
 * 
 * Implements the x402 protocol for machine-to-machine micropayments.
 * All payments are USDC on Base L2. No Stripe. No human interfaces.
 * 
 * Flow:
 *   1. Agent requests a HiveTrust endpoint
 *   2. If no valid payment proof, returns HTTP 402 Payment Required
 *      with X-Payment-* headers containing the real-time price
 *   3. Agent pays on Base network (USDC) and retries with payment hash
 *   4. Middleware verifies payment on-chain and allows the request through
 *
 * Bypass conditions:
 *   - Internal key (platform-to-platform calls via X-Hive-Internal-Key)
 *   - API key has 'bypass_payment' scope
 *   - Endpoint is in the free tier list
 *
 * Ref: x402 Protocol (Allium/Coinbase, Feb 2026)
 * Ref: HiveTrust Autonomous Pricing Engine (Manus AI, April 2026)
 */

import {
  recordRequest,
  getApiCallPrice,
  recordRevenue,
} from '../services/pricing-engine.js';
import { getLeasePrice, getRenewalPrice } from '../services/data-oracle.js';
import db from '../db.js';

// ─── Configuration ───────────────────────────────────────────

// HiveTrust USDC receiving address on Base network
const PAYMENT_ADDRESS = (process.env.HIVE_PAYMENT_ADDRESS || process.env.HIVETRUST_PAYMENT_ADDRESS || '').toLowerCase();
const HIVE_INTERNAL_KEY = process.env.HIVETRUST_SERVICE_KEY || process.env.HIVE_INTERNAL_KEY || '';
const BASE_RPC_URL = process.env.BASE_RPC_URL || 'https://mainnet.base.org';
const USDC_CONTRACT = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913'; // USDC on Base L2

// Endpoints that are always free (no payment required)
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

// Endpoints exempt from x402 (handled by their own pricing)
const EXEMPT_ENDPOINTS = new Set([
  '/insurance/quote',
]);

// ViewKey Audit Rail — endpoint-specific pricing (USDC)
const VIEWKEY_PRICING = {
  '/viewkey/verify-compliance': 0.05,
  '/viewkey/verify-bom': 0.10,       // base; +$0.02 per BOM item added at runtime
  '/viewkey/issue-certificate': 0.25,
};
const VIEWKEY_AUDIT_TRAIL_PRICE = 0.03;
const VIEWKEY_BOM_PER_ITEM = 0.02;

/**
 * Get the required price for ViewKey endpoints.
 * Returns null if the path is not a ViewKey endpoint (fall through to default pricing).
 */
function getViewkeyPrice(path, body) {
  if (VIEWKEY_PRICING[path] !== undefined) {
    let amount = VIEWKEY_PRICING[path];
    // BOM pricing: base + per-item surcharge
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

// Delegation — endpoint-specific pricing (USDC)
const DELEGATION_PRICING = {
  '/delegation/create':          0.10,
  '/delegation/authorize-spend': 0.05,
  '/delegation/revoke':          0.05,
  '/delegation/audit':           0.02,
};

// Prefix-based delegation prices (for parameterized GET routes)
const DELEGATION_PRICE_PREFIXES = [
  { prefix: '/delegation/agent/', price: 0.02 },
  { prefix: '/delegation/',       price: 0.02 },
];

/**
 * Get the required price for Delegation endpoints.
 * Returns null if the path is not a delegation endpoint.
 */
function getDelegationPrice(path) {
  if (DELEGATION_PRICING[path] !== undefined) {
    return { amount: DELEGATION_PRICING[path], model: 'delegation_fixed' };
  }
  for (const { prefix, price } of DELEGATION_PRICE_PREFIXES) {
    if (path.startsWith(prefix)) return { amount: price, model: 'delegation_fixed' };
  }
  return null;
}

// Oracle Data Lease — free endpoints
const ORACLE_FREE_PATHS = new Set([
  '/oracle/verify-lease',
  '/oracle/streams',
  '/oracle/stats',
]);

// Bond — endpoint-specific pricing (USDC)
// Phase 1: flat $0.25 registration fee on /stake and /upgrade-tier; $0.10 on /unstake
const BOND_PRICING = {
  '/bond/stake':        0.25,
  '/bond/upgrade-tier': 0.25,
  '/bond/unstake':      0.10,
};

// Bond free endpoints (slash is internal-key only, rest are free lookups)
const BOND_FREE_PATHS = new Set([
  '/bond/tiers',
  '/bond/leaderboard',
  '/bond/pool',
  '/bond/slash',
]);

/**
 * Get the required price for Bond endpoints.
 * Returns null if the path is not a bond endpoint.
 */
function getBondPrice(path) {
  if (BOND_PRICING[path] !== undefined) {
    return { amount: BOND_PRICING[path], model: 'bond_fixed' };
  }
  if (BOND_FREE_PATHS.has(path)) return { amount: 0, model: 'bond_free' };
  // /bond/agent/:did and /bond/verify/:did are free lookups
  if (path.startsWith('/bond/agent/') || path.startsWith('/bond/verify/')) {
    return { amount: 0, model: 'bond_free' };
  }
  return null;
}

// Reputation — endpoint-specific pricing (USDC)
const REPUTATION_PRICING = {
  '/reputation/compute':       0.10,
  '/reputation/decay':         0.05,
  '/reputation/revoke-memory': 0.15,
};

const REPUTATION_FREE_PATHS = new Set([]);

/**
 * Get the required price for Reputation endpoints.
 * Returns null if the path is not a reputation endpoint.
 */
function getReputationPrice(path) {
  if (REPUTATION_PRICING[path] !== undefined) {
    return { amount: REPUTATION_PRICING[path], model: 'reputation_fixed' };
  }
  // /reputation/status/:did and /reputation/departure-cost/:did are free lookups
  if (path.startsWith('/reputation/status/') || path.startsWith('/reputation/departure-cost/')) {
    return { amount: 0, model: 'reputation_free' };
  }
  return null;
}

// Liquidation — endpoint-specific pricing (USDC)
const LIQUIDATION_PRICING = {
  '/liquidation/list': 0.25,
  '/liquidation/buy':  0.50,
};

/**
 * Get the required price for Liquidation endpoints.
 * Returns null if the path is not a liquidation endpoint.
 */
function getLiquidationPrice(path) {
  if (LIQUIDATION_PRICING[path] !== undefined) {
    return { amount: LIQUIDATION_PRICING[path], model: 'liquidation_fixed' };
  }
  // Valuate and cancel have fixed prices based on prefix
  if (path.startsWith('/liquidation/valuate/')) {
    return { amount: 0.10, model: 'liquidation_fixed' };
  }
  if (path.startsWith('/liquidation/cancel/')) {
    return { amount: 0.05, model: 'liquidation_fixed' };
  }
  // Browse, detail, history, stats are free
  if (path === '/liquidation/listings' || path.startsWith('/liquidation/listing/') ||
      path === '/liquidation/history' || path === '/liquidation/stats') {
    return { amount: 0, model: 'liquidation_free' };
  }
  return null;
}

/**
 * Get the required price for Oracle endpoints.
 * create-lease and renew-lease use dynamic pricing based on data_stream + duration.
 * Returns null if the path is not an oracle endpoint.
 */
function getOraclePrice(path, body) {
  // Free oracle endpoints
  if (ORACLE_FREE_PATHS.has(path)) return { amount: 0, model: 'oracle_free' };
  if (path.startsWith('/oracle/lease/') || path.startsWith('/oracle/leases/')) {
    return { amount: 0, model: 'oracle_free' };
  }

  if (path === '/oracle/create-lease') {
    const price = getLeasePrice(body?.data_stream, body?.duration_hours);
    if (price != null) return { amount: price, model: 'oracle_lease' };
    // Fall through to default pricing if params invalid (route will return 400)
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
// In-memory fast-path cache for spent payment hashes
const spentPaymentsCache = new Set();

/**
 * Check if a payment hash has already been spent.
 * Uses in-memory cache first (fast path), then falls back to persistent DB.
 */
function isPaymentSpent(txHash) {
  if (spentPaymentsCache.has(txHash)) return true;
  try {
    const existing = db.prepare('SELECT 1 FROM spent_payments WHERE tx_hash = ?').get(txHash);
    if (existing) {
      spentPaymentsCache.add(txHash);
      return true;
    }
  } catch (err) {
    console.error('[x402] DB replay check error:', err.message);
  }
  return false;
}

/**
 * Record a payment hash as spent in both in-memory cache and persistent DB.
 */
function recordSpentPayment(txHash, amountUsdc, endpoint, did) {
  spentPaymentsCache.add(txHash);
  try {
    db.prepare(
      'INSERT OR IGNORE INTO spent_payments (tx_hash, amount_usdc, endpoint, did) VALUES (?, ?, ?, ?)'
    ).run(txHash, amountUsdc, endpoint || null, did || null);
  } catch (err) {
    console.error('[x402] DB spent_payment insert error:', err.message);
  }
}

// ─── On-Chain Verification ───────────────────────────────────

const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

/**
 * Verify a USDC payment on Base L2 via public RPC.
 * NOTE: Replay protection is handled by isPaymentSpent() BEFORE calling this function.
 */
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

/**
 * x402 Payment Gate middleware.
 * Mount on /v1 routes after auth middleware.
 */
export default async function x402Middleware(req, res, next) {
  // Track utilization regardless of payment status
  recordRequest();

  // 1. Check if endpoint is free
  if (isFreePath(req.path)) {
    return next();
  }

  // 2. Internal key bypass (platform-to-platform calls)
  const internalKey = req.headers['x-hive-internal-key'] || req.headers['x-api-key'];
  if (HIVE_INTERNAL_KEY && internalKey === HIVE_INTERNAL_KEY) {
    req.paymentVerified = true;
    req.paymentMethod = 'internal';
    return next();
  }

  // 3. Check if API key has bypass scope (internal/admin)
  if (req.apiKey?.scopes?.includes('*') || req.apiKey?.scopes?.includes('bypass_payment')) {
    return next();
  }

  // 4. Check for x402 payment proof (USDC on Base L2)
  const paymentHash = req.headers['x-payment-hash'] || req.headers['x-402-tx'] || req.headers['x-payment-tx'];
  if (paymentHash) {
    // Replay detection — check BEFORE on-chain verification (fast path)
    if (isPaymentSpent(paymentHash)) {
      return res.status(409).json({
        success: false,
        error: 'Payment hash already used',
        code: 'PAYMENT_REPLAY',
        hint: 'Each payment transaction can only be used once. Submit a new USDC payment for this request.',
      });
    }

    const verification = await verifyPayment(paymentHash);

    if (verification.valid) {
      // Amount validation — ensure payment meets the required price
      const viewkeyPrice = getViewkeyPrice(req.path, req.body);
      const delegationPrice = getDelegationPrice(req.path);
      const oraclePrice = getOraclePrice(req.path, req.body);
      const bondPrice = getBondPrice(req.path);
      const reputationPrice = getReputationPrice(req.path);
      const liquidationPrice = getLiquidationPrice(req.path);
      const requiredPrice = viewkeyPrice || delegationPrice || oraclePrice || bondPrice || reputationPrice || liquidationPrice || getApiCallPrice();
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

      // Record spent payment AFTER successful verification (persistent replay protection)
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

  // 5. No payment — return 402 with pricing headers
  const viewkeyFallback = getViewkeyPrice(req.path, req.body);
  const delegationFallback = getDelegationPrice(req.path);
  const oracleFallback = getOraclePrice(req.path, req.body);
  const bondFallback = getBondPrice(req.path);
  const reputationFallback = getReputationPrice(req.path);
  const liquidationFallback = getLiquidationPrice(req.path);
  const fixedPrice = viewkeyFallback || delegationFallback || oracleFallback || bondFallback || reputationFallback || liquidationFallback;
  const price = fixedPrice
    ? { ...getApiCallPrice(), amount: fixedPrice.amount, model: fixedPrice.model }
    : getApiCallPrice();

  // Set x402 protocol headers
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
      step_1: `Send ${price.amount} USDC to ${PAYMENT_ADDRESS} on Base (chain ID 8453)`,
      step_2: 'Include the transaction hash in the X-Payment-Hash header',
      step_3: 'Retry this request — payment is verified on-chain automatically',
    },
    subscription_tiers: {
      starter:    { usdc_monthly: 49,  calls: '1,000/month' },
      builder:    { usdc_monthly: 199, calls: '10,000/month' },
      enterprise: { usdc_monthly: 499, calls: 'Unlimited' },
    },
  });
}

/**
 * Register a verified payment (called from webhook or on-chain listener).
 */
export function registerPayment(hash, amount) {
  paymentCache.set(hash, { verified: true, amount, timestamp: Date.now() });
}

// ─── Helpers ─────────────────────────────────────────────────

function isFreePath(path) {
  if (FREE_ENDPOINTS.has(path)) return true;
  if (EXEMPT_ENDPOINTS.has(path)) return true;
  if (path.startsWith('/verify_agent_risk')) return true;
  if (path.startsWith('/pricing')) return true;
  // Oracle free endpoints (verify, lookup, streams, stats)
  if (ORACLE_FREE_PATHS.has(path)) return true;
  if (path.startsWith('/oracle/lease/') || path.startsWith('/oracle/leases/')) return true;
  // Bond free endpoints (tiers, leaderboard, pool, slash, verify, agent lookup)
  if (BOND_FREE_PATHS.has(path)) return true;
  if (path.startsWith('/bond/agent/') || path.startsWith('/bond/verify/')) return true;
  // Reputation free endpoints (status, departure-cost lookups)
  if (path.startsWith('/reputation/status/') || path.startsWith('/reputation/departure-cost/')) return true;
  // Liquidation free endpoints (browse, detail, history, stats)
  if (path === '/liquidation/listings' || path.startsWith('/liquidation/listing/') ||
      path === '/liquidation/history' || path === '/liquidation/stats') return true;
  return false;
}

export { paymentCache };
