// HiveAudit — Day 8 transactional substrate.
//
// /v1/audit/log    POST  $0.001  ingress for a single attested receipt
// /v1/audit/list   GET   FREE    DID-scoped tail of recent receipts (last 100)
// /v1/audit/receipt/:id  GET FREE single receipt by id
//
// This is the substrate. Day 12 (badges/verify/readiness) and Day 14
// (HiveComply) are read-only projections of audit_receipts.

import { Router } from 'express';
import { appendReceipt, listReceipts } from '../services/audit-receipts.js';
import { query } from '../db.js';

const router = Router();

router.post('/log', async (req, res) => {
  const body = req.body || {};
  // DID resolution: explicit body field wins, else fall back to authenticated DID.
  const did = body.did || req.authDid || req.headers['x-agent-did'];
  if (!did) {
    return res.status(400).json({ ok: false, error: 'missing_did' });
  }
  if (!body.request_hash || !body.response_hash) {
    return res.status(400).json({ ok: false, error: 'missing_required_field', required: ['request_hash', 'response_hash'] });
  }

  const result = await appendReceipt({
    did,
    request_hash: body.request_hash,
    response_hash: body.response_hash,
    actor_id: body.actor_id,
    upstream: body.upstream,
    model: body.model,
    epoch_id: body.epoch_id,
    sector: body.sector,
    revenue_usdc: body.revenue_usdc,
    settlement_tx: body.settlement_tx || req.x402SettlementTx,
    payload: body.payload,
    sign: body.sign !== false,
  });

  if (!result.success) {
    return res.status(500).json({ ok: false, error: result.error });
  }
  return res.status(201).json({
    ok: true,
    receipt_id: result.receipt_id,
    canonical_hash: result.canonical_hash,
    signature: result.signature,
    pubkey: result.pubkey,
    created_at: result.created_at,
  });
});

router.get('/list', async (req, res) => {
  const did = req.query.did || req.authDid;
  if (!did) {
    return res.status(400).json({ ok: false, error: 'missing_did' });
  }
  const result = await listReceipts({
    did,
    limit: req.query.limit,
    offset: req.query.offset,
    since: req.query.since,
  });
  if (!result.success) {
    return res.status(500).json({ ok: false, error: result.error });
  }
  return res.json({
    ok: true,
    did,
    count: result.count,
    receipts: result.receipts,
  });
});

router.get('/receipt/:id', async (req, res) => {
  try {
    const r = await query(`
      SELECT receipt_id, did, actor_id, upstream, model, request_hash, response_hash,
             canonical_hash, signature, pubkey, epoch_id, sector, revenue_usdc,
             settlement_tx, created_at
      FROM audit_receipts
      WHERE receipt_id = $1
    `, [req.params.id]);
    if (!r.rows.length) {
      return res.status(404).json({ ok: false, error: 'not_found' });
    }
    return res.json({ ok: true, receipt: r.rows[0] });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

export default router;
