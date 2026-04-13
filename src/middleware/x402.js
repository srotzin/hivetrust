/**
 * HiveTrust — x402 Payment Middleware
 * 
 * Implements the x402 protocol for machine-to-machine micropayments.
 * 
 * Flow:
 *   1. Agent requests a HiveTrust endpoint
 *   2. If no valid payment proof or subscription, returns HTTP 402 Payment Required
 *      with X-Payment-* headers containing the real-time price
 *   3. Agent pays on Base network (USDC) and retries with payment hash
 *   4. Middleware verifies payment and allows the request through
 *
 * Bypass conditions:
 *   - Request includes valid Stripe subscription (via X-Subscription-Id header)
 *   - Request includes valid payment hash (X-Payment-Hash header)
 *   - Endpoint is in the free tier list
 *   - API key has 'bypass_payment' scope
 *
 * Ref: x402 Protocol (Allium/Coinbase, Feb 2026)
 * Ref: HiveTrust Autonomous Pricing Engine (Manus AI, April 2026)
 */

import {
  recordRequest,
  getApiCallPrice,
  recordRevenue,
} from '../services/pricing-engine.js';

// ─── Configuration ───────────────────────────────────────────

// HiveTrust USDC receiving address on Base network
const PAYMENT_ADDRESS = process.env.HIVETRUST_PAYMENT_ADDRESS || '0x0000000000000000000000000000000000000000';

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

// Endpoints exempt from x402 (handled by their own pricing, e.g. insurance has its own premium)
const EXEMPT_ENDPOINTS = new Set([
  '/insurance/quote',    // Quoting is free; binding/claiming has its own pricing
]);

// ─── In-memory payment verification cache ────────────────────
// Maps payment hash → { verified: bool, amount: number, timestamp: number }
// Production would use Redis or on-chain verification
const paymentCache = new Map();

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

  // 2. Check if API key has bypass scope (internal/admin)
  if (req.apiKey?.scopes?.includes('*') || req.apiKey?.scopes?.includes('bypass_payment')) {
    return next();
  }

  // 3. Check for valid Stripe subscription
  const subscriptionId = req.headers['x-subscription-id'];
  if (subscriptionId) {
    const valid = await isValidSubscription(subscriptionId);
    if (valid) {
      req.paymentMethod = 'stripe_subscription';
      req.subscriptionId = subscriptionId;
      return next();
    }
    return res.status(402).json({
      success: false,
      error: 'Subscription verification failed',
      code: 'SUBSCRIPTION_INVALID',
      hint: 'Ensure the subscription ID is for an active Stripe subscription.',
    });
  }

  // 4. Check for x402 payment proof
  const paymentHash = req.headers['x-payment-hash'];
  if (paymentHash) {
    const verification = await verifyPayment(paymentHash);
    if (verification.valid) {
      req.paymentMethod = 'x402';
      req.paymentHash = paymentHash;
      req.paymentAmount = verification.amount;
      recordRevenue(verification.amount);
      return next();
    }

    // Payment hash provided but invalid
    return res.status(402).json({
      success: false,
      error: 'Payment verification failed',
      code: 'PAYMENT_INVALID',
      details: verification.reason,
      hint: 'Ensure the payment hash corresponds to a confirmed Base network transaction to the correct address.',
    });
  }

  // 5. No payment — return 402 with pricing headers
  const price = getApiCallPrice();

  // Set x402 protocol headers
  res.set({
    'X-Payment-Amount': price.amount.toString(),
    'X-Payment-Currency': price.currency,
    'X-Payment-Network': price.network,
    'X-Payment-Address': PAYMENT_ADDRESS,
    'X-Payment-Model': price.model,
    'X-Payment-Utilization': price.utilization.toString(),
    'X-HiveTrust-Required': 'true',
    'X-HiveTrust-Challenge': JSON.stringify({
      version: '1.0',
      protocol: 'x402',
      amount: price.amount,
      currency: price.currency,
      network: price.network,
      address: PAYMENT_ADDRESS,
      endpoint: req.path,
      method: req.method,
      timestamp: new Date().toISOString(),
      ttl_seconds: 300,
      registration_url: 'https://hivetrustiq.com/#pricing',
    }),
  });

  return res.status(402).json({
    success: false,
    error: 'Payment required',
    code: 'PAYMENT_REQUIRED',
    protocol: 'x402',
    payment: {
      amount: price.amount,
      currency: price.currency,
      network: price.network,
      address: PAYMENT_ADDRESS,
      model: price.model,
      utilization: price.utilization,
      floor: price.floor,
      ceiling: price.ceiling,
    },
    instructions: {
      step_1: 'Send the specified USDC amount to the payment address on the Base network.',
      step_2: 'Include the transaction hash in the X-Payment-Hash header when retrying this request.',
      step_3: 'The payment will be verified and your request will be processed.',
      alternative: 'Subscribe at https://hivetrustiq.com/#pricing for unlimited access with a monthly plan.',
    },
    subscription_plans: {
      starter: { price: '$49/month', calls: '1,000/month', url: 'https://hivetrustiq.com/#pricing' },
      builder: { price: '$199/month', calls: '10,000/month', url: 'https://hivetrustiq.com/#pricing' },
      enterprise: { price: '$499/month', calls: 'Unlimited', url: 'https://hivetrustiq.com/#pricing' },
    },
  });
}

// ─── Configuration ────────────────────────────────────────────

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const BASE_RPC_URL = process.env.BASE_RPC_URL || 'https://mainnet.base.org';
const USDC_CONTRACT = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913'; // USDC on Base L2

// ─── Payment Verification ────────────────────────────────────

/**
 * Verify a payment hash on Base L2.
 * Queries the chain via public RPC to confirm USDC transfer.
 */
async function verifyPayment(hash) {
  // Check cache first
  if (paymentCache.has(hash)) {
    const cached = paymentCache.get(hash);
    if (cached.verified) {
      return { valid: true, amount: cached.amount };
    }
    return { valid: false, reason: 'Payment previously rejected' };
  }

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

    const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
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

/**
 * Validate a Stripe subscription ID against the Stripe API.
 */
async function isValidSubscription(subscriptionId) {
  if (!STRIPE_SECRET_KEY || !STRIPE_SECRET_KEY.startsWith('sk_live_')) {
    return false;
  }
  try {
    const res = await fetch(`https://api.stripe.com/v1/subscriptions/${subscriptionId}`, {
      headers: { 'Authorization': `Bearer ${STRIPE_SECRET_KEY}` },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return false;
    const sub = await res.json();
    return sub.status === 'active' || sub.status === 'trialing';
  } catch {
    return false;
  }
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
  // Allow public prefix paths
  if (path.startsWith('/verify_agent_risk')) return true;
  if (path.startsWith('/pricing')) return true;
  return false;
}

export { paymentCache };
