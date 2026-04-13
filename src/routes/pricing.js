/**
 * HiveTrust — Pricing API Routes
 * 
 * Public endpoints for agents to query real-time pricing,
 * engine status, and request quotes before paying.
 * 
 * All mounted at /v1/pricing/ in server.js.
 */

import { Router } from 'express';
import Stripe from 'stripe';
import {
  getApiCallPrice,
  getInsurancePremium,
  getDutchAuctionPrice,
  getProtocolToll,
  getEngineStatus,
} from '../services/pricing-engine.js';
import { paymentCache } from '../middleware/x402.js';

// ─── Stripe Client ──────────────────────────────────────────

const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

// Map Stripe price IDs to plan names
const PRICE_TO_PLAN = {
  'price_1TLbA9LyXpiMYLtrrE5FvRtR': 'starter',
  'price_1TLbAFLyXpiMYLtrFqeX9naU': 'builder',
  'price_1TLbAFLyXpiMYLtrAQSLWpIo': 'enterprise',
};

/**
 * Verify the X-Hive-Internal-Key header for cross-platform endpoints.
 * Skipped in dev/test mode.
 */
function requireInternalKey(req, res) {
  if (process.env.NODE_ENV !== 'production') return true;
  const key = req.headers['x-hive-internal-key'];
  if (!key || key !== process.env.HIVE_INTERNAL_KEY) {
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
  const paymentAddress = process.env.HIVETRUST_PAYMENT_ADDRESS || '0x0000000000000000000000000000000000000000';

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
          description: 'Use a Stripe subscription for monthly access',
          headers: {
            'X-Subscription-Id': '<your_stripe_subscription_id>',
          },
          plans_url: 'https://hivetrustiq.com/#pricing',
        },
      },
      protocol: 'x402',
      version: '1.0',
    },
  });
});

// ─── GET /pricing/verify-subscription — Cross-platform subscription verification ─

router.get('/verify-subscription', async (req, res) => {
  if (!requireInternalKey(req, res)) return;

  const { id } = req.query;
  if (!id) {
    return res.status(400).json({
      success: false,
      error: 'Required query param: id (Stripe subscription ID)',
    });
  }

  // Accept test subscriptions in dev/test mode
  if (id.startsWith('sub_test_') && process.env.NODE_ENV !== 'production') {
    return res.json({
      success: true,
      data: { valid: true, plan: 'builder', status: 'active' },
    });
  }

  // Verify via Stripe API
  if (!stripe) {
    return res.status(503).json({
      success: false,
      error: 'Stripe is not configured (missing STRIPE_SECRET_KEY)',
    });
  }

  try {
    const subscription = await stripe.subscriptions.retrieve(id);
    const isActive = subscription.status === 'active' || subscription.status === 'trialing';
    let plan = 'starter'; // default

    // Resolve plan from subscription items
    const items = subscription.items?.data || [];
    for (const item of items) {
      const priceId = item.price?.id;
      if (priceId && PRICE_TO_PLAN[priceId]) {
        plan = PRICE_TO_PLAN[priceId];
        break;
      }
    }

    return res.json({
      success: true,
      data: {
        valid: isActive,
        plan,
        status: isActive ? 'active' : 'inactive',
      },
    });
  } catch (err) {
    // Stripe throws for invalid/not-found subscription IDs
    return res.json({
      success: true,
      data: { valid: false, plan: null, status: 'inactive' },
    });
  }
});

// ─── POST /pricing/verify-payment — Cross-platform payment verification ──

router.post('/verify-payment', (req, res) => {
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

  // Accept test payments in dev/test mode
  if (hash.startsWith('test_pay_') && process.env.NODE_ENV !== 'production') {
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
