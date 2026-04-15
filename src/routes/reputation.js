/**
 * HiveTrust — Reputation Routes (Lock-In Hardening)
 * Composite scoring, decay, memory revocation, departure cost.
 *
 * Mounted at /v1/reputation/ in server.js.
 *
 * x402 pricing (USDC on Base L2):
 *   - compute:         $0.10 per computation
 *   - decay:           $0.05 per decay application
 *   - revoke-memory:   $0.15 per revocation
 *   - status/:did:     FREE (lookup)
 *   - departure-cost:  FREE (lookup)
 */

import { Router } from 'express';
import {
  computeReputation,
  applyDecay,
  getReputationStatus,
  revokeMemory,
  getDepartureCost,
} from '../services/reputation-engine.js';

const router = Router();

// ─── Helpers ────────────────────────────────────────────────

function ok(res, data, status = 200) {
  return res.status(status).json({ success: true, data });
}

function err(res, message, status = 400) {
  return res.status(status).json({ success: false, error: message });
}

// ─── POST /compute — Compute composite reputation score ─────

router.post('/compute', async (req, res) => {
  try {
    const { did } = req.body;
    const result = await computeReputation(did);
    return ok(res, result);
  } catch (e) {
    console.error('[POST /reputation/compute]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── POST /decay — Apply reputation decay ───────────────────

router.post('/decay', async (req, res) => {
  try {
    const { did, reason } = req.body;
    const result = await applyDecay(did, reason);
    return ok(res, result);
  } catch (e) {
    console.error('[POST /reputation/decay]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── GET /status/:did — Full reputation status ──────────────

router.get('/status/:did', async (req, res) => {
  try {
    const result = await getReputationStatus(req.params.did);
    return ok(res, result);
  } catch (e) {
    console.error('[GET /reputation/status/:did]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── POST /revoke-memory — Trigger memory revocation ────────

router.post('/revoke-memory', async (req, res) => {
  try {
    const { did, reason } = req.body;
    const result = await revokeMemory(did, reason);
    return ok(res, result);
  } catch (e) {
    console.error('[POST /reputation/revoke-memory]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── GET /departure-cost/:did — Calculate departure cost ────

router.get('/departure-cost/:did', async (req, res) => {
  try {
    const result = await getDepartureCost(req.params.did);
    return ok(res, result);
  } catch (e) {
    console.error('[GET /reputation/departure-cost/:did]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

export default router;
