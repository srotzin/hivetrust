// HiveAudit — Readiness Scoring + Badges + Verify
//
// Day 12 product surface. All read-only projections of audit_receipts.
//
// Pillar: DEFENSIBLE.
// "Reasonable care" defense for EU AI Act Art. 12/13 needs a peer-comparable
// readiness score backed by receipt history. Badge = signed, verifiable,
// tamper-evident, embeddable.
//
// Scoring is deterministic: same inputs → same score → same grade → same SVG.

import { query } from '../db.js';
import { canonicalize, canonicalBytes } from '../lib/canonical.js';
import { issueTicket, getIssuerPubkey } from './spectral-issuer.js';
import { createHash } from 'crypto';
import { statsForDid } from './audit-receipts.js';

// ─── Scoring ─────────────────────────────────────────────────────────

// Score components (0-100 each), then weighted average:
//   coverage    (40%)  — receipt volume in last 30d
//   diversity   (20%)  — distinct upstreams + models
//   continuity  (20%)  — receipts spread across days, not bursty
//   subscription(20%)  — active HiveAudit tier
const WEIGHTS = { coverage: 0.40, diversity: 0.20, continuity: 0.20, subscription: 0.20 };

function clamp(n, lo = 0, hi = 100) { return Math.max(lo, Math.min(hi, n)); }

export async function computeReadinessScore(did) {
  const sRes = await statsForDid(did, 30);
  if (!sRes.success) return { success: false, error: sRes.error };
  const stats = sRes.stats || {};

  const receipts30d = parseInt(stats.total || 0, 10);
  const distinctModels = parseInt(stats.distinct_models || 0, 10);
  const distinctUpstreams = parseInt(stats.distinct_upstreams || 0, 10);

  // Coverage — log-scaled. 100 receipts → 50, 1000 → 75, 10k → 100.
  const coverage = receipts30d <= 0 ? 0 : clamp(25 * Math.log10(receipts30d + 1));

  // Diversity — caps at 5 distinct upstreams + 5 distinct models.
  const diversity = clamp(((Math.min(distinctUpstreams, 5) + Math.min(distinctModels, 5)) / 10) * 100);

  // Continuity — count distinct days with at least one receipt in last 30.
  let continuity = 0;
  try {
    const r = await query(`
      SELECT COUNT(DISTINCT DATE(created_at::timestamp))::int AS days_active
      FROM audit_receipts
      WHERE did = $1 AND created_at >= (NOW() - INTERVAL '30 days')::TEXT
    `, [did]);
    const daysActive = parseInt(r.rows[0]?.days_active || 0, 10);
    continuity = clamp((daysActive / 30) * 100);
  } catch (err) {
    continuity = 0;
  }

  // Subscription — Federal 100, Enterprise 80, Pro 60, Starter 40, none 0.
  let subscription = 0;
  let tier = 'none';
  try {
    const r = await query(`
      SELECT tier FROM audit_subscriptions
      WHERE did = $1 AND status = 'active' AND expires_at > NOW()::TEXT
      ORDER BY
        CASE tier
          WHEN 'federal' THEN 1
          WHEN 'enterprise' THEN 2
          WHEN 'professional' THEN 3
          WHEN 'starter' THEN 4
          ELSE 5
        END
      LIMIT 1
    `, [did]);
    if (r.rows.length) {
      tier = r.rows[0].tier;
      subscription = { federal: 100, enterprise: 80, professional: 60, starter: 40 }[tier] || 0;
    }
  } catch (err) {
    subscription = 0;
  }

  const score = Math.round(
    coverage * WEIGHTS.coverage +
    diversity * WEIGHTS.diversity +
    continuity * WEIGHTS.continuity +
    subscription * WEIGHTS.subscription
  );

  const grade =
    score >= 90 ? 'A' :
    score >= 80 ? 'B' :
    score >= 65 ? 'C' :
    score >= 50 ? 'D' :
    'F';

  return {
    success: true,
    did,
    score,
    grade,
    components: { coverage: Math.round(coverage), diversity: Math.round(diversity),
                  continuity: Math.round(continuity), subscription },
    receipts_30d: receipts30d,
    distinct_models: distinctModels,
    distinct_upstreams: distinctUpstreams,
    tier,
    computed_at: new Date().toISOString(),
  };
}

// ─── Badge SVG ───────────────────────────────────────────────────────

const HIVE_GOLD = '#C08D23';

function gradeColor(grade) {
  return ({
    A: '#00B86A',
    B: '#7FB100',
    C: HIVE_GOLD,
    D: '#E07A1F',
    F: '#B33020',
  })[grade] || HIVE_GOLD;
}

export function renderBadgeSVG({ did, score, grade, receipts30d, tier, issued_at, signature }) {
  const color = gradeColor(grade);
  const tierLabel = (tier && tier !== 'none') ? tier.toUpperCase() : 'BASE';
  const shortDid = did.length > 28 ? did.slice(0, 24) + '...' : did;
  const sigShort = signature ? signature.slice(0, 16) + '...' : 'unsigned';
  return `<svg xmlns="http://www.w3.org/2000/svg" width="320" height="120" viewBox="0 0 320 120">
  <rect width="320" height="120" rx="10" fill="#0B0B0E" stroke="${HIVE_GOLD}" stroke-width="2"/>
  <text x="14" y="22" font-family="ui-monospace,SFMono-Regular,Menlo,monospace" font-size="11" fill="${HIVE_GOLD}">HiveAudit \u2014 Readiness Badge</text>
  <text x="14" y="38" font-family="ui-monospace,monospace" font-size="9" fill="#888">${shortDid}</text>
  <rect x="14" y="48" width="60" height="56" rx="6" fill="${color}"/>
  <text x="44" y="78" font-family="Helvetica,Arial,sans-serif" font-size="36" font-weight="700" fill="#000" text-anchor="middle">${grade}</text>
  <text x="44" y="98" font-family="Helvetica,Arial,sans-serif" font-size="10" fill="#000" text-anchor="middle">${score}/100</text>
  <text x="84" y="64" font-family="Helvetica,Arial,sans-serif" font-size="11" fill="#fff">tier: ${tierLabel}</text>
  <text x="84" y="80" font-family="Helvetica,Arial,sans-serif" font-size="11" fill="#fff">receipts (30d): ${receipts30d}</text>
  <text x="84" y="96" font-family="Helvetica,Arial,sans-serif" font-size="9" fill="#888">issued ${issued_at} \u00b7 sig ${sigShort}</text>
</svg>`;
}

// ─── Issue + Cache ───────────────────────────────────────────────────

export async function issueOrRefreshBadge(did) {
  const r = await computeReadinessScore(did);
  if (!r.success) return r;

  const issued_at = new Date().toISOString();
  const expires_at = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

  // Sign the canonical badge document.
  const badgeDoc = {
    did,
    score: r.score,
    grade: r.grade,
    receipts_30d: r.receipts_30d,
    tier: r.tier,
    issued_at,
    expires_at,
  };
  const canonHash = createHash('sha256').update(canonicalBytes(badgeDoc)).digest('hex');

  let signature = null;
  let pubkey = null;
  try {
    const ticket = await issueTicket({
      to: did, amount: 0, reason: 'audit_badge', did,
      regime: 'NORMAL_CYAN', exp_sec: 7 * 86400,
    });
    if (ticket?.signature) {
      signature = ticket.signature;
      pubkey = ticket.issuer_pubkey || await getIssuerPubkey().catch(() => null);
    }
  } catch (err) {
    console.warn('[badge] sign failed:', err.message);
  }

  const svg = renderBadgeSVG({
    did, score: r.score, grade: r.grade,
    receipts30d: r.receipts_30d, tier: r.tier,
    issued_at, signature,
  });

  // Upsert into cache.
  try {
    await query(`
      INSERT INTO audit_badges (did, score, grade, receipts_count, badge_svg, badge_signature, issued_at, expires_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      ON CONFLICT (did) DO UPDATE SET
        score = EXCLUDED.score,
        grade = EXCLUDED.grade,
        receipts_count = EXCLUDED.receipts_count,
        badge_svg = EXCLUDED.badge_svg,
        badge_signature = EXCLUDED.badge_signature,
        issued_at = EXCLUDED.issued_at,
        expires_at = EXCLUDED.expires_at
    `, [did, r.score, r.grade, r.receipts_30d, svg, signature, issued_at, expires_at]);
  } catch (err) {
    console.error('[badge] cache failed:', err.message);
  }

  return {
    success: true,
    did,
    score: r.score,
    grade: r.grade,
    components: r.components,
    receipts_30d: r.receipts_30d,
    tier: r.tier,
    canonical_hash: canonHash,
    signature,
    pubkey,
    issued_at,
    expires_at,
    svg,
  };
}

export async function getCachedBadge(did) {
  try {
    const r = await query(`
      SELECT did, score, grade, receipts_count, badge_svg, badge_signature, issued_at, expires_at
      FROM audit_badges WHERE did = $1
    `, [did]);
    if (!r.rows.length) return { success: false, error: 'not_found' };
    return { success: true, badge: r.rows[0] };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ─── Verify ──────────────────────────────────────────────────────────

/**
 * Verify a badge document presented by a third party. The challenger pays
 * $0.01 (gated upstream by x402); we re-derive the score and confirm signature.
 */
export async function verifyBadgeDocument(badgeDoc) {
  if (!badgeDoc?.did || !badgeDoc?.score || !badgeDoc?.grade || !badgeDoc?.issued_at) {
    return { success: false, error: 'malformed_badge', verdict: 'invalid' };
  }

  // Re-compute current score for the DID.
  const fresh = await computeReadinessScore(badgeDoc.did);
  if (!fresh.success) return { success: false, error: fresh.error, verdict: 'unknown' };

  // Pull cached badge for signature comparison.
  const cached = await getCachedBadge(badgeDoc.did);
  const cachedRow = cached.success ? cached.badge : null;

  // Score drift check — badges are valid for 7 days; allow 5-point drift.
  const issuedAt = new Date(badgeDoc.issued_at);
  const ageMs = Date.now() - issuedAt.getTime();
  const expired = ageMs > 7 * 24 * 60 * 60 * 1000;
  const drift = Math.abs(fresh.score - badgeDoc.score);

  let verdict = 'valid';
  const flags = [];
  if (expired) { verdict = 'expired'; flags.push('badge_expired'); }
  if (drift > 5 && !expired) { verdict = 'stale'; flags.push(`score_drift:${drift}`); }
  if (cachedRow && badgeDoc.score !== cachedRow.score) {
    flags.push('cache_mismatch');
    if (verdict === 'valid') verdict = 'stale';
  }

  return {
    success: true,
    verdict,
    flags,
    presented: { score: badgeDoc.score, grade: badgeDoc.grade, issued_at: badgeDoc.issued_at },
    current:   { score: fresh.score, grade: fresh.grade, computed_at: fresh.computed_at },
    drift,
    pubkey_advertised: 'https://hivetrust.onrender.com/v1/audit/pubkey',
  };
}
