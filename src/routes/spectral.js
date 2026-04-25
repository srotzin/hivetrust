// HiveTrust — Spectral ZK Outbound Auth Issuer Routes.
//
// Mounted at /v1/trust/spectral by server.js. Auth middleware on /v1
// already gates these endpoints behind X-Hive-Internal-Key for service
// callers. Public-facing pubkey/snapshot endpoints are intentionally
// safe to expose.

import { Router } from 'express';
import { ok, err } from '../ritz.js';
import { issueTicket, getIssuerPubkey, snapshot, intentHash } from '../services/spectral-issuer.js';

const router = Router();
const SERVICE = 'hivetrust';

// ─── POST /v1/trust/spectral/issue ──────────────────────────────────────────
//
// Mints one Spectral ZK ticket. Caller (e.g. hive_rebalancer_dispatcher.py)
// must supply the live regime they observed from hivebank's /v1/admin/stats
// snapshot. Hivebank verifies the regime against its OWN live classifier on
// receipt — if they disagree, the ticket is rejected.
//
// Body:
//   { to, amount, reason, did, regime, exp_sec? }
//
// Returns:
//   { ticket, iss, epoch, exp, intent, nonce, regime }
//
router.post('/issue', async (req, res) => {
  const start = Date.now();
  try {
    const { to, amount, reason, did, regime, exp_sec } = req.body || {};
    const result = await issueTicket({ to, amount, reason, did, regime, exp_sec });

    return ok(res, SERVICE, result, {
      processing_ms: Date.now() - start,
      endpoint: '/v1/trust/spectral/issue',
    });
  } catch (e) {
    console.error('[spectral.issue]', e.code || 'ERR', e.message);
    const status = e.status || (e.code === 'NO_ISSUER_KEY' ? 503 : 500);
    return err(res, SERVICE, e.code || 'ISSUE_ERROR', e.message, status);
  }
});

// ─── GET /v1/trust/spectral/pubkey ──────────────────────────────────────────
//
// Returns the published Ed25519 verifier pubkey hivebank should configure as
// SPECTRAL_VERIFIER_PK_B64U. Idempotent. Safe to expose.
//
router.get('/pubkey', async (req, res) => {
  try {
    const result = await getIssuerPubkey();
    return ok(res, SERVICE, result, { endpoint: '/v1/trust/spectral/pubkey' });
  } catch (e) {
    console.error('[spectral.pubkey]', e.code || 'ERR', e.message);
    const status = e.code === 'NO_ISSUER_KEY' ? 503 : 500;
    return err(res, SERVICE, e.code || 'PUBKEY_ERROR', e.message, status);
  }
});

// ─── GET /v1/trust/spectral/snapshot ────────────────────────────────────────
//
// Issuer telemetry — counters and config. Mirrors hivebank's
// /v1/admin/stats.spectral_zk shape. Safe to expose.
//
router.get('/snapshot', (req, res) => {
  return ok(res, SERVICE, snapshot(), { endpoint: '/v1/trust/spectral/snapshot' });
});

// ─── POST /v1/trust/spectral/intent-hash ────────────────────────────────────
//
// Helper for clients that want to precompute the intent hash before calling
// /issue (e.g., to cross-check what hivebank will see). Pure function — no
// state, no signing.
//
router.post('/intent-hash', (req, res) => {
  const { to, amount, reason, did } = req.body || {};
  if (!to || amount === undefined) {
    return err(res, SERVICE, 'MISSING_FIELDS', 'to and amount are required', 400);
  }
  const intent = intentHash({ to, amount, reason, did });
  return ok(res, SERVICE, { intent }, { endpoint: '/v1/trust/spectral/intent-hash' });
});

export default router;
