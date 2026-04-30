// HiveAudit — Day 12 read surfaces.
//
// Pillar: DEFENSIBLE.
// All endpoints below are read-only projections of audit_receipts +
// audit_subscriptions. Mounted at /v1/audit/* alongside Day 8.

import { Router } from 'express';
import {
  computeReadinessScore,
  issueOrRefreshBadge,
  getCachedBadge,
  verifyBadgeDocument,
} from '../services/audit-readiness.js';
import { getIssuerPubkey } from '../services/spectral-issuer.js';

const router = Router();

// FREE — readiness score for any DID. Recomputed on every call (cheap).
router.get('/readiness/:did', async (req, res) => {
  const r = await computeReadinessScore(req.params.did);
  if (!r.success) return res.status(500).json({ ok: false, error: r.error });
  return res.json({ ok: true, ...r });
});

// FREE — badge SVG by DID. Issues if missing or expired, else returns cached.
router.get('/badge/:did', async (req, res) => {
  const did = req.params.did;
  const cached = await getCachedBadge(did);
  let badge;
  if (cached.success && cached.badge.expires_at > new Date().toISOString()) {
    badge = cached.badge;
  } else {
    const issued = await issueOrRefreshBadge(did);
    if (!issued.success) return res.status(500).json({ ok: false, error: issued.error });
    badge = {
      did: issued.did,
      score: issued.score,
      grade: issued.grade,
      receipts_count: issued.receipts_30d,
      badge_svg: issued.svg,
      badge_signature: issued.signature,
      issued_at: issued.issued_at,
      expires_at: issued.expires_at,
    };
  }

  // Negotiate format: SVG by default, JSON if Accept: application/json.
  const acceptsJson = (req.headers.accept || '').includes('application/json');
  if (acceptsJson) {
    return res.json({ ok: true, badge });
  }
  res.set('Content-Type', 'image/svg+xml');
  res.set('Cache-Control', 'public, max-age=3600');
  return res.send(badge.badge_svg);
});

// FREE — third-party badge sanity check via DID. Returns current vs cached.
router.get('/verify-badge/:did', async (req, res) => {
  const did = req.params.did;
  const cached = await getCachedBadge(did);
  if (!cached.success) {
    return res.status(404).json({ ok: false, error: 'no_badge_issued', did });
  }
  const result = await verifyBadgeDocument({
    did,
    score: cached.badge.score,
    grade: cached.badge.grade,
    issued_at: cached.badge.issued_at,
  });
  return res.json({ ok: result.success, did, ...result });
});

// $0.01 (gated by x402 middleware) — challenger-supplied badge document.
// The caller pays to assert "did this DID actually have this score on this date?"
// — this is the productized counterparty due diligence surface.
router.post('/verify', async (req, res) => {
  const result = await verifyBadgeDocument(req.body || {});
  if (!result.success) return res.status(400).json({ ok: false, error: result.error, verdict: result.verdict || 'invalid' });
  return res.json({ ok: true, ...result });
});

// FREE — issuer pubkey advertisement. Stable across deploys.
// Same key as /v1/compliance/pubkey on hive-gamification.
router.get('/pubkey', async (req, res) => {
  try {
    const pubkey = await getIssuerPubkey();
    return res.json({
      ok: true,
      algorithm: 'Ed25519',
      pubkey,
      pubkey_hex: pubkey,
      mirror: 'https://hive-gamification.onrender.com/v1/compliance/pubkey',
      note: 'Same Ed25519 key signs HiveTrust audit receipts and HiveGamification compliance attestations.',
    });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

export default router;
