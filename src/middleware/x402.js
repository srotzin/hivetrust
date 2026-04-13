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
  '/.well-known/hivetrust.json',
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
export default function x402Middleware(req, res, next) {
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
  if (subscriptionId && isValidSubscription(subscriptionId)) {
    req.paymentMethod = 'stripe_subscription';
    req.subscriptionId = subscriptionId;
    return next();
  }

  // 4. Check for x402 payment proof
  const paymentHash = req.headers['x-payment-hash'];
  if (paymentHash) {
    const verification = verifyPayment(paymentHash);
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

// ─── Payment Verification ────────────────────────────────────

/**
 * Verify a payment hash.
 * In production, this queries the Base network via CDP SDK.
 * For now, we support:
 *   - Cached verified payments
 *   - Test payment hashes (prefixed with 'test_')
 *   - TODO: On-chain verification via ethers/CDP
 */
function verifyPayment(hash) {
  // Check cache first
  if (paymentCache.has(hash)) {
    const cached = paymentCache.get(hash);
    if (cached.verified) {
      return { valid: true, amount: cached.amount };
    }
    return { valid: false, reason: 'Payment previously rejected' };
  }

  // Accept test payments in non-production (for development)
  if (hash.startsWith('test_pay_') && process.env.NODE_ENV !== 'production') {
    const amount = parseFloat(hash.split('_').pop()) || 0.001;
    paymentCache.set(hash, { verified: true, amount, timestamp: Date.now() });
    return { valid: true, amount };
  }

  // TODO: On-chain verification via CDP SDK
  // const tx = await cdpClient.getTransaction(hash);
  // if (tx.to === PAYMENT_ADDRESS && tx.value >= expectedAmount) { ... }

  return { valid: false, reason: 'Payment hash not found. Ensure the transaction is confirmed on the Base network.' };
}

/**
 * Validate a Stripe subscription ID.
 * In production, this calls the Stripe API.
 * For now, accepts any non-empty string as valid in dev mode.
 */
function isValidSubscription(subscriptionId) {
  // Accept test subscriptions in non-production
  if (subscriptionId.startsWith('sub_test_') && process.env.NODE_ENV !== 'production') {
    return true;
  }

  // TODO: Stripe API verification
  // const sub = await stripe.subscriptions.retrieve(subscriptionId);
  // return sub.status === 'active';

  return false;
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
