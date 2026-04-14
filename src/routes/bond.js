/**
 * HiveTrust — Bond Routes (Trust Staking Layer)
 * Agents stake USDC to back their reputation. Slashing is permanent.
 *
 * Mounted at /v1/bond/ in server.js.
 *
 * x402 pricing (USDC on Base L2):
 *   - stake:         $0.25 flat registration fee (Phase 1 — declared amount tracked)
 *   - upgrade-tier:  $0.25 flat fee (Phase 1)
 *   - unstake:       $0.10 processing fee
 *   - slash:         FREE (internal — HiveLaw only)
 *   - agent/:did:    FREE (requireDID)
 *   - tiers:         FREE (public)
 *   - leaderboard:   FREE (requireDID)
 *   - pool:          FREE (requireDID)
 *   - verify/:did:   FREE (verification must be frictionless)
 */

import { Router } from 'express';
import {
  stakeBond,
  getAgentBondStatus,
  slashBond,
  unstakeBond,
  getTiers,
  getLeaderboard,
  getPoolStats,
  upgradeTier,
  verifyBond,
} from '../services/bond-engine.js';

const router = Router();

// ─── Helpers ────────────────────────────────────────────────

function ok(res, data, status = 200) {
  return res.status(status).json({ success: true, data });
}

function err(res, message, status = 400) {
  return res.status(status).json({ success: false, error: message });
}

// ─── POST /stake — Stake USDC to back agent reputation ──────

router.post('/stake', async (req, res) => {
  try {
    const { agent_did, amount_usdc, tier, lock_period_days } = req.body;
    const result = stakeBond({ agent_did, amount_usdc, tier, lock_period_days });
    return ok(res, result, 201);
  } catch (e) {
    console.error('[POST /bond/stake]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── GET /agent/:did — Get bond status for an agent ─────────

router.get('/agent/:did', async (req, res) => {
  try {
    const result = getAgentBondStatus(req.params.did);
    return ok(res, result);
  } catch (e) {
    console.error('[GET /bond/agent/:did]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── POST /slash — Slash an agent's stake (HiveLaw only) ────

router.post('/slash', async (req, res) => {
  try {
    const { agent_did, amount_usdc, reason, case_id, injured_party_did } = req.body;
    const result = slashBond({ agent_did, amount_usdc, reason, case_id, injured_party_did });
    return ok(res, result);
  } catch (e) {
    console.error('[POST /bond/slash]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── POST /unstake — Withdraw staked USDC after lock expires ─

router.post('/unstake', async (req, res) => {
  try {
    const { bond_id } = req.body;
    const result = unstakeBond({ bond_id });
    return ok(res, result);
  } catch (e) {
    console.error('[POST /bond/unstake]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── GET /tiers — List all bond tiers with requirements ─────

router.get('/tiers', async (req, res) => {
  try {
    const tiers = getTiers();
    return ok(res, { tiers });
  } catch (e) {
    console.error('[GET /bond/tiers]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── GET /leaderboard — Top staked agents ───────────────────

router.get('/leaderboard', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const agents = getLeaderboard(limit);
    return ok(res, { agents, count: agents.length });
  } catch (e) {
    console.error('[GET /bond/leaderboard]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── GET /pool — Staking pool statistics ────────────────────

router.get('/pool', async (req, res) => {
  try {
    const stats = getPoolStats();
    return ok(res, stats);
  } catch (e) {
    console.error('[GET /bond/pool]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── POST /upgrade-tier — Upgrade bond tier with more stake ─

router.post('/upgrade-tier', async (req, res) => {
  try {
    const { bond_id, additional_usdc } = req.body;
    const result = upgradeTier({ bond_id, additional_usdc });
    return ok(res, result);
  } catch (e) {
    console.error('[POST /bond/upgrade-tier]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── GET /verify/:did — Quick bond verification ─────────────
// Key integration point — other services call this to check bond status.

router.get('/verify/:did', async (req, res) => {
  try {
    const result = verifyBond(req.params.did);
    return ok(res, result);
  } catch (e) {
    console.error('[GET /bond/verify/:did]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

export default router;
