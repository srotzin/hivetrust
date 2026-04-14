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
      const requiredPrice = getApiCallPrice();
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
  const price = getApiCallPrice();

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
  return false;
}

export { paymentCache };
