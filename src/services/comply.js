// HiveComply — Day 14 filing engagement service.
//
// Pillar: DEFENSIBLE.
// $5,000 base + optional $2,500 rush + $2,500 delta. Every filing
// auto-bundles a 30-day HiveAudit Professional trial via the
// audit_subscriptions table.
//
// Doctrine anchor: EU AI Act Article 12 (logging) + Article 13
// (transparency) become enforceable August 2026. HiveComply produces
// the regulator-shaped artifact + the underlying ZK-attested audit trail.
//
// Pricing is enforced inline (not via x402 middleware) because the engagement
// is a single $5K+ Stripe transaction, not a micropayment. x402 micropay
// gates the audit_log substrate; Stripe gates HiveComply.

import { query } from '../db.js';
import { v4 as uuidv4 } from 'uuid';
import { canonicalize, canonicalBytes } from '../lib/canonical.js';
import { issueTicket } from './spectral-issuer.js';
import { createHash } from 'crypto';

const BASE_FEE = 5000.00;
const RUSH_FEE = 2500.00;
const DELTA_FEE = 2500.00;

const SUPPORTED_SECTORS = new Set([
  'general', 'financial', 'healthcare', 'legal', 'government', 'manufacturing',
]);

/**
 * Quote a HiveComply engagement — returns total in USDC.
 * Rush surcharge: 14-day delivery instead of 30-day.
 * Delta filing: only available to subscribers active in the last 90 days.
 */
export function quoteEngagement({ sector = 'general', rush = false, delta = false }) {
  if (!SUPPORTED_SECTORS.has(sector)) {
    return { ok: false, error: 'unsupported_sector', supported: [...SUPPORTED_SECTORS] };
  }
  let total = BASE_FEE;
  if (rush) total += RUSH_FEE;
  if (delta) total = DELTA_FEE; // delta REPLACES base for active subscribers
  return {
    ok: true,
    sector,
    rush,
    delta,
    base_usdc: BASE_FEE,
    rush_usdc: rush ? RUSH_FEE : 0,
    delta_usdc: delta ? DELTA_FEE : 0,
    total_usdc: total,
    delivery_sla_days: rush ? 14 : 30,
    article: 'EU-AI-Act-12-13',
    bundled_trial: { product: 'HiveAudit', tier: 'professional', days: 30 },
  };
}

/**
 * Check if a DID qualifies for delta pricing (active sub in last 90 days).
 */
async function isDeltaEligible(did) {
  try {
    const r = await query(`
      SELECT 1 FROM audit_subscriptions
      WHERE did = $1
        AND tier IN ('professional', 'enterprise', 'federal')
        AND status = 'active'
        AND starts_at >= (NOW() - INTERVAL '90 days')::TEXT
      LIMIT 1
    `, [did]);
    return r.rows.length > 0;
  } catch (err) {
    console.warn('[comply] delta eligibility check failed:', err.message);
    return false;
  }
}

/**
 * Bundle a 30-day HiveAudit Professional trial.
 * Source = 'comply_bundle' so we can attribute trial conversions.
 */
async function bundleTrialSubscription(did, sector) {
  const sub_id = uuidv4();
  const now = new Date();
  const expires = new Date(now.getTime() + 30 * 86400 * 1000);
  try {
    await query(`
      INSERT INTO audit_subscriptions
        (subscription_id, did, tier, sector, retention_days, starts_at, expires_at,
         auto_renew, source, settlement_tx, revenue_usdc, status, created_at)
      VALUES ($1, $2, 'professional', $3, 90, $4, $5, FALSE, 'comply_bundle', NULL, 0, 'active', $6)
    `, [sub_id, did, sector, now.toISOString(), expires.toISOString(), now.toISOString()]);
    return sub_id;
  } catch (err) {
    console.error('[comply] trial bundle failed:', err.message);
    return null;
  }
}

/**
 * Start a HiveComply engagement. The actual payment is settled out-of-band
 * (Stripe Checkout for now; USDC receipt accepted via settlement_tx).
 * This function records the engagement, bundles the trial, and signs the
 * intake receipt.
 */
export async function startEngagement({ did, sector = 'general', rush = false, delta = false, contact_email, settlement_tx = null }) {
  if (!did) return { ok: false, error: 'missing_did' };
  if (!contact_email) return { ok: false, error: 'missing_contact_email' };

  // If caller asked for delta, verify eligibility — silently downgrade if not.
  let appliedDelta = delta;
  if (delta) {
    const eligible = await isDeltaEligible(did);
    if (!eligible) appliedDelta = false;
  }

  const quote = quoteEngagement({ sector, rush, delta: appliedDelta });
  if (!quote.ok) return quote;

  const engagement_id = uuidv4();
  const created_at = new Date().toISOString();

  // Bundle trial sub.
  const bundled_subscription_id = await bundleTrialSubscription(did, sector);

  // Sign the canonical intake receipt.
  const intake = {
    engagement_id, did, sector,
    rush, delta: appliedDelta,
    total_usdc: quote.total_usdc,
    article: 'EU-AI-Act-12-13',
    bundled_subscription_id,
    contact_email,
    created_at,
  };
  const canonical_hash = createHash('sha256').update(canonicalBytes(intake)).digest('hex');

  let signature = null;
  try {
    const t = await issueTicket({
      to: did, amount: quote.total_usdc, reason: 'comply_engagement_intake', did,
      regime: 'NORMAL_CYAN', exp_sec: 30 * 86400,
    });
    signature = t?.signature || null;
  } catch (err) {
    console.warn('[comply] intake sign failed:', err.message);
  }

  // Insert engagement row.
  try {
    await query(`
      INSERT INTO comply_engagements
        (engagement_id, did, sector, article, rush, delta, total_usdc,
         settlement_tx, bundled_subscription_id, status, created_at)
      VALUES ($1, $2, $3, 'EU-AI-Act-12-13', $4, $5, $6, $7, $8, $9, $10)
    `, [engagement_id, did, sector, rush, appliedDelta, quote.total_usdc,
        settlement_tx, bundled_subscription_id,
        settlement_tx ? 'paid' : 'pending', created_at]);
  } catch (err) {
    console.error('[comply] engagement insert failed:', err.message);
    return { ok: false, error: err.message };
  }

  return {
    ok: true,
    engagement_id,
    quote,
    delta_applied: appliedDelta,
    bundled_subscription_id,
    canonical_hash,
    signature,
    pubkey_url: 'https://hivetrust.onrender.com/v1/audit/pubkey',
    status: settlement_tx ? 'paid' : 'pending',
    next_step: settlement_tx
      ? 'Engagement intake complete. Filing kickoff email lands within 24h.'
      : 'Complete payment via Stripe Checkout or POST settlement_tx (USDC on Base) to /v1/comply/settle.',
    delivery_sla_days: quote.delivery_sla_days,
    article: 'EU-AI-Act-12-13',
    created_at,
  };
}

/**
 * Settle a pending engagement by attaching a USDC settlement_tx hash.
 * Stripe webhook calls a separate path; this is for x402/EIP-3009 flows.
 */
export async function settleEngagement({ engagement_id, settlement_tx, revenue_usdc }) {
  if (!engagement_id || !settlement_tx) {
    return { ok: false, error: 'missing_required_field' };
  }
  try {
    const r = await query(`
      UPDATE comply_engagements
      SET settlement_tx = $1, status = 'paid'
      WHERE engagement_id = $2 AND status = 'pending'
      RETURNING engagement_id, did, total_usdc, status
    `, [settlement_tx, engagement_id]);
    if (!r.rows.length) {
      return { ok: false, error: 'engagement_not_found_or_already_paid' };
    }
    return { ok: true, engagement: r.rows[0] };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

export async function getEngagement(engagement_id) {
  try {
    const r = await query(`
      SELECT engagement_id, did, sector, article, rush, delta, total_usdc,
             settlement_tx, bundled_subscription_id, status, delivered_at, created_at
      FROM comply_engagements WHERE engagement_id = $1
    `, [engagement_id]);
    if (!r.rows.length) return { ok: false, error: 'not_found' };
    return { ok: true, engagement: r.rows[0] };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}
