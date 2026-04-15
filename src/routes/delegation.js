/**
 * HiveTrust — Spend Delegation Routes
 * ZK-Spend Delegation Trees: scoped, revocable spending budgets.
 *
 * Mounted at /v1/delegation/ in server.js.
 *
 * x402 pricing (USDC on Base L2):
 *   - create:          $0.10
 *   - authorize-spend:  $0.05
 *   - revoke:           $0.05
 *   - lookup/audit:     $0.02
 */

import { Router } from 'express';
import {
  createDelegation,
  authorizeSpend,
  revokeDelegation,
  getDelegation,
  getDelegationsForAgent,
  getAuditTrail,
} from '../services/delegation.js';

const router = Router();

// ─── Helpers ────────────────────────────────────────────────

function ok(res, data, status = 200) {
  return res.status(status).json({ success: true, data });
}

function err(res, message, status = 400) {
  return res.status(status).json({ success: false, error: message });
}

// ─── POST /create — Create a new spend delegation ──────────

router.post('/create', async (req, res) => {
  try {
    const { grantor_did, grantee_did, budget_usdc, scope, expires_at, restrictions } = req.body;
    const delegation = await createDelegation({ grantor_did, grantee_did, budget_usdc, scope, expires_at, restrictions });
    return ok(res, delegation, 201);
  } catch (e) {
    console.error('[POST /delegation/create]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── POST /authorize-spend — Check & deduct a spend ────────

router.post('/authorize-spend', async (req, res) => {
  try {
    const { delegation_id, amount_usdc, vendor, category, tx_description, compliance_proof_hash } = req.body;
    const result = await authorizeSpend({ delegation_id, amount_usdc, vendor, category, tx_description, compliance_proof_hash });
    return ok(res, result);
  } catch (e) {
    console.error('[POST /delegation/authorize-spend]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── POST /revoke — Revoke a delegation immediately ────────

router.post('/revoke', async (req, res) => {
  try {
    const { delegation_id, grantor_did, reason } = req.body;
    const result = await revokeDelegation({ delegation_id, grantor_did, reason });
    return ok(res, result);
  } catch (e) {
    console.error('[POST /delegation/revoke]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── GET /:delegation_id — Full delegation state ───────────

router.get('/:delegation_id', async (req, res) => {
  try {
    const delegation = await getDelegation(req.params.delegation_id);
    if (!delegation) return err(res, 'Delegation not found', 404);
    return ok(res, delegation);
  } catch (e) {
    console.error('[GET /delegation/:id]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── GET /agent/:did — All delegations for a DID ───────────

router.get('/agent/:did', async (req, res) => {
  try {
    const did = req.params.did;
    const delegations = await getDelegationsForAgent(did);
    return ok(res, delegations);
  } catch (e) {
    console.error('[GET /delegation/agent/:did]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── POST /audit — Complete audit trail for a delegation ───

router.post('/audit', async (req, res) => {
  try {
    const { delegation_id } = req.body;
    if (!delegation_id) return err(res, 'delegation_id is required', 400);
    const trail = await getAuditTrail(delegation_id);
    return ok(res, trail);
  } catch (e) {
    console.error('[POST /delegation/audit]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

export default router;
