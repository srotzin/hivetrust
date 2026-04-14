/**
 * HiveTrust — Pricing API Routes
 * 
 * Public endpoints for agents to query real-time pricing,
 * engine status, and request quotes before paying.
 * 
 * All mounted at /v1/pricing/ in server.js.
 */

import { Router } from 'express';
import {
  getApiCallPrice,
  getInsurancePremium,
  getDutchAuctionPrice,
  getProtocolToll,
  getEngineStatus,
} from '../services/pricing-engine.js';
import { paymentCache } from '../middleware/x402.js';
import ipAllowlist from '../middleware/ip-allowlist.js';

// ─── Payment Configuration ──────────────────────────────────

const HIVE_PAYMENT_ADDRESS = (process.env.HIVE_PAYMENT_ADDRESS || process.env.HIVETRUST_PAYMENT_ADDRESS || '').toLowerCase();
const BASE_CHAIN_ID = 8453;
const USDC_CONTRACT = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913';

// USDC subscription tiers
const PLAN_TIERS = {
  starter:    { usdc_monthly: 49,  calls: '1,000/month' },
  builder:    { usdc_monthly: 199, calls: '10,000/month' },
  enterprise: { usdc_monthly: 499, calls: 'Unlimited' },
};

/**
 * Verify the X-Hive-Internal-Key header for cross-platform endpoints.
 * Enforced in ALL environments (no dev bypass).
 */
function requireInternalKey(req, res) {
  const expectedKey = process.env.HIVETRUST_SERVICE_KEY || process.env.HIVE_INTERNAL_KEY;
  if (!expectedKey) {
    res.status(403).json({
      success: false,
      error: 'Internal key not configured on server',
    });
    return false;
  }
  const key = req.headers['x-hive-internal-key'];
  if (!key || key !== expectedKey) {
    res.status(403).json({
      success: false,
      error: 'Missing or invalid X-Hive-Internal-Key header',
    });
    return false;
  }
  return true;
}

const router = Router();

// ─── GET /pricing/status — Full engine status ────────────────

router.get('/status', (req, res) => {
  const status = getEngineStatus();
  return res.json({
    success: true,
    data: status,
  });
});

// ─── GET /pricing/api-call — Current API call price ──────────

router.get('/api-call', (req, res) => {
  const price = getApiCallPrice();
  return res.json({
    success: true,
    data: price,
  });
});

// ─── POST /pricing/insurance-quote — Dynamic insurance premium ─

router.post('/insurance-quote', (req, res) => {
  const { trust_tier, trust_score, transaction_value, category } = req.body;

  if (!trust_tier || trust_score === undefined || !transaction_value) {
    return res.status(400).json({
      success: false,
      error: 'Required: trust_tier, trust_score, transaction_value',
    });
  }

  const premium = getInsurancePremium(
    trust_tier,
    parseFloat(trust_score),
    parseFloat(transaction_value),
    category
  );

  return res.json({
    success: true,
    data: premium,
  });
});

// ─── GET /pricing/auction — Dutch auction current price ──────

router.get('/auction', (req, res) => {
  const startTime = req.query.start_time
    ? parseInt(req.query.start_time)
    : Date.now() - 10000; // Default: auction started 10s ago

  const price = getDutchAuctionPrice(startTime);

  return res.json({
    success: true,
    data: price,
  });
});

// ─── POST /pricing/settlement-toll — Protocol toll calc ──────

router.post('/settlement-toll', (req, res) => {
  const { transaction_value } = req.body;

  if (!transaction_value || transaction_value <= 0) {
    return res.status(400).json({
      success: false,
      error: 'transaction_value must be a positive number (USDC)',
    });
  }

  const toll = getProtocolToll(parseFloat(transaction_value));

  return res.json({
    success: true,
    data: toll,
  });
});

// ─── GET /pricing/quote — Combined quote for an endpoint ─────

router.get('/quote', (req, res) => {
  const { endpoint, method } = req.query;
  const price = getApiCallPrice();
  const paymentAddress = HIVE_PAYMENT_ADDRESS || '0x0000000000000000000000000000000000000000';

  return res.json({
    success: true,
    data: {
      endpoint: endpoint || '/v1/*',
      method: method || 'ANY',
      price: {
        amount: price.amount,
        currency: price.currency,
        network: price.network,
        address: paymentAddress,
      },
      model: price.model,
      utilization: price.utilization,
      how_to_pay: {
        x402: {
          description: 'Send USDC to the payment address on Base, include tx hash in X-Payment-Hash header',
          headers: {
            'X-Payment-Hash': '<your_base_tx_hash>',
          },
        },
        subscription: {
          description: 'Monthly USDC subscription for unlimited access within tier',
          tiers: PLAN_TIERS,
          payment_address: HIVE_PAYMENT_ADDRESS,
          network: 'Base L2 (chain ID 8453)',
        },
      },
      protocol: 'x402',
      version: '1.0',
    },
  });
});

// ─── GET /pricing/verify-subscription — Cross-platform subscription verification ─

router.get('/verify-subscription', ipAllowlist, async (req, res) => {
  if (!requireInternalKey(req, res)) return;

  // Subscription verification is now handled via on-chain USDC payments.
  // This endpoint returns the available tiers and payment instructions.
  return res.json({
    success: true,
    data: {
      payment_method: 'USDC on Base L2',
      tiers: PLAN_TIERS,
      payment_address: HIVE_PAYMENT_ADDRESS,
      network: `eip155:${BASE_CHAIN_ID}`,
      usdc_contract: USDC_CONTRACT,
      instructions: 'Send the monthly USDC amount to the payment address on Base. Include the tx hash in X-Payment-Hash header for per-call access.',
    },
  });
});

// ─── POST /pricing/verify-payment — Cross-platform payment verification ──

router.post('/verify-payment', ipAllowlist, (req, res) => {
  if (!requireInternalKey(req, res)) return;

  const { hash, amount, source } = req.body;
  if (!hash) {
    return res.status(400).json({
      success: false,
      error: 'Required body field: hash (payment transaction hash)',
    });
  }

  // Check cache for verified payment
  if (paymentCache.has(hash)) {
    const cached = paymentCache.get(hash);
    return res.json({
      success: true,
      data: {
        valid: cached.verified,
        amount: cached.amount,
        network: 'base',
      },
    });
  }

  // Accept test payments only when explicitly enabled
  if (hash.startsWith('test_pay_') && process.env.ALLOW_TEST_PAYMENTS === 'true') {
    const testAmount = parseFloat(hash.split('_').pop()) || parseFloat(amount) || 0.001;
    paymentCache.set(hash, { verified: true, amount: testAmount, timestamp: Date.now() });
    return res.json({
      success: true,
      data: {
        valid: true,
        amount: testAmount,
        network: 'base',
      },
    });
  }

  // Payment hash not found
  return res.json({
    success: true,
    data: {
      valid: false,
      amount: 0,
      network: 'base',
    },
  });
});

export default router;
