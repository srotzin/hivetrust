/**
 * HiveTrust — Liquidation Routes (Agent Liquidation Market)
 * Buy/sell DIDs + reputation + memories as tradeable assets.
 *
 * Mounted at /v1/liquidation/ in server.js.
 *
 * x402 pricing (USDC on Base L2):
 *   - list:              $0.25 listing fee
 *   - buy:               $0.50 transaction fee (on top of sale price)
 *   - valuate/:did:      $0.10 valuation fee
 *   - cancel/:listing_id: $0.05 cancellation fee
 *   - listings:          FREE (browse)
 *   - listing/:id:       FREE (detail lookup)
 *   - history:           FREE (lookup)
 *   - stats:             FREE (public)
 */

import { Router } from 'express';
import {
  createListing,
  getListings,
  getListing,
  valuateDid,
  executePurchase,
  cancelListing,
  getHistory,
  getMarketStats,
} from '../services/liquidation-engine.js';

const router = Router();

// ─── Helpers ────────────────────────────────────────────────

function ok(res, data, status = 200) {
  return res.status(status).json({ success: true, data });
}

function err(res, message, status = 400) {
  return res.status(status).json({ success: false, error: message });
}

// ─── POST /list — List a DID for sale ───────────────────────

router.post('/list', async (req, res) => {
  try {
    const { did, asking_price_usdc, description, include_memories, include_offspring } = req.body;
    const result = await createListing({ did, asking_price_usdc, description, include_memories, include_offspring });
    return ok(res, result, 201);
  } catch (e) {
    console.error('[POST /liquidation/list]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── GET /listings — Browse active listings ─────────────────

router.get('/listings', async (req, res) => {
  try {
    const result = getListings(req.query);
    return ok(res, result);
  } catch (e) {
    console.error('[GET /liquidation/listings]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── GET /listing/:listing_id — Detailed listing info ───────

router.get('/listing/:listing_id', async (req, res) => {
  try {
    const result = getListing(req.params.listing_id);
    return ok(res, result);
  } catch (e) {
    console.error('[GET /liquidation/listing/:id]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── POST /valuate/:did — Get DID valuation ─────────────────

router.post('/valuate/:did', async (req, res) => {
  try {
    const result = await valuateDid(req.params.did);
    return ok(res, result);
  } catch (e) {
    console.error('[POST /liquidation/valuate/:did]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── POST /buy — Execute purchase ───────────────────────────

router.post('/buy', async (req, res) => {
  try {
    const { listing_id, buyer_did, payment_method } = req.body;
    const result = await executePurchase({ listing_id, buyer_did, payment_method });
    return ok(res, result);
  } catch (e) {
    console.error('[POST /liquidation/buy]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── POST /cancel/:listing_id — Cancel listing ─────────────

router.post('/cancel/:listing_id', async (req, res) => {
  try {
    const result = cancelListing(req.params.listing_id);
    return ok(res, result);
  } catch (e) {
    console.error('[POST /liquidation/cancel/:id]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── GET /history — Transaction history ─────────────────────

router.get('/history', async (req, res) => {
  try {
    const result = getHistory(req.query);
    return ok(res, result);
  } catch (e) {
    console.error('[GET /liquidation/history]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── GET /stats — Market statistics ─────────────────────────

router.get('/stats', async (req, res) => {
  try {
    const result = getMarketStats();
    return ok(res, result);
  } catch (e) {
    console.error('[GET /liquidation/stats]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

export default router;
