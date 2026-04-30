// HiveComply — Day 14 routes.
//
// /v1/comply/quote        GET   FREE   pricing quote
// /v1/comply/start        POST  inline-priced  engagement intake ($5K+)
// /v1/comply/settle       POST  inline         attach USDC settlement_tx
// /v1/comply/engagement/:id GET FREE   read-only status
// /v1/comply/webhook/stripe POST FREE  stripe webhook for $5K filing transaction
//
// Pillar: DEFENSIBLE. Pricing is large-ticket (Stripe), not micropay.

import { Router } from 'express';
import { quoteEngagement, startEngagement, settleEngagement, getEngagement } from '../services/comply.js';
import { createHash, timingSafeEqual } from 'crypto';

const router = Router();

router.get('/quote', (req, res) => {
  const sector = req.query.sector || 'general';
  const rush = String(req.query.rush || '').toLowerCase() === 'true';
  const delta = String(req.query.delta || '').toLowerCase() === 'true';
  const q = quoteEngagement({ sector, rush, delta });
  return res.status(q.ok ? 200 : 400).json(q);
});

router.post('/start', async (req, res) => {
  const body = req.body || {};
  const did = body.did || req.authDid || req.headers['x-agent-did'];
  const result = await startEngagement({
    did,
    sector: body.sector || 'general',
    rush: !!body.rush,
    delta: !!body.delta,
    contact_email: body.contact_email,
    settlement_tx: body.settlement_tx || req.x402SettlementTx,
  });
  if (!result.ok) return res.status(400).json(result);
  return res.status(201).json(result);
});

router.post('/settle', async (req, res) => {
  const result = await settleEngagement({
    engagement_id: req.body?.engagement_id,
    settlement_tx: req.body?.settlement_tx,
    revenue_usdc: req.body?.revenue_usdc,
  });
  return res.status(result.ok ? 200 : 400).json(result);
});

router.get('/engagement/:id', async (req, res) => {
  const r = await getEngagement(req.params.id);
  return res.status(r.ok ? 200 : 404).json(r);
});

// Stripe webhook — verifies signature and marks the engagement paid.
// Stripe-Signature header: t=<ts>,v1=<hex_hmac>
router.post('/webhook/stripe', async (req, res) => {
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  const sigHeader = req.headers['stripe-signature'];

  if (!secret) {
    // Webhook secret not configured — refuse rather than silently accept.
    return res.status(503).json({ ok: false, error: 'webhook_not_configured' });
  }
  if (!sigHeader) {
    return res.status(400).json({ ok: false, error: 'missing_signature' });
  }

  // req.body is already parsed JSON by express.json() — for true Stripe parity we
  // should mount this on a raw-body route, but Day 14 ships with parsed-body
  // verification using the canonical-JSON of the payload. Stripe's helper
  // library can be swapped in once we're issuing webhook secrets to live
  // accounts.
  try {
    const parts = String(sigHeader).split(',').reduce((acc, p) => {
      const [k, v] = p.split('=');
      acc[k] = v;
      return acc;
    }, {});
    if (!parts.t || !parts.v1) {
      return res.status(400).json({ ok: false, error: 'malformed_signature' });
    }
    const payload = `${parts.t}.${JSON.stringify(req.body)}`;
    const expected = createHash('sha256').update(secret + payload).digest('hex');
    const provided = parts.v1;
    if (expected.length !== provided.length ||
        !timingSafeEqual(Buffer.from(expected), Buffer.from(provided))) {
      return res.status(400).json({ ok: false, error: 'signature_mismatch' });
    }

    const event = req.body;
    if (event.type === 'checkout.session.completed' || event.type === 'payment_intent.succeeded') {
      const engagement_id = event.data?.object?.metadata?.engagement_id;
      const settlement_tx = `stripe:${event.data?.object?.id}`;
      if (engagement_id) {
        const r = await settleEngagement({ engagement_id, settlement_tx });
        return res.json({ ok: r.ok, engagement_id, ...(r.ok ? {} : { error: r.error }) });
      }
    }
    return res.json({ ok: true, ignored: true, event_type: event.type });
  } catch (err) {
    return res.status(400).json({ ok: false, error: err.message });
  }
});

export default router;
