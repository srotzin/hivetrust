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

export default router;
