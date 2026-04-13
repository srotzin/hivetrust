/**
 * HiveTrust — Trust Scoring Engine
 *
 * Five-pillar composite score (0–1000):
 *  1. Transaction Success Rate  35%  — SLA completions vs disputes
 *  2. Capital Staked            25%  — USDC in collateral pool
 *  3. Network Centrality        15%  — simplified PageRank of tx graph
 *  4. Identity Strength         15%  — checksum stability, DID, key age, ZKPs
 *  5. Compliance                10%  — EU AI Act, NIST, fidelity probes
 *
 * Tiers:
 *  unverified   0–199
 *  provisional  200–399
 *  standard     400–599
 *  elevated     600–799
 *  sovereign    800–1000
 */

import db from '../db.js';
import { v4 as uuidv4 } from 'uuid';
import * as audit from './audit.js';

// ─── Constants ────────────────────────────────────────────────

const WEIGHTS = {
  transaction: 0.35,
  capital:     0.25,
  centrality:  0.15,
  identity:    0.15,
  compliance:  0.10,
};

const TIERS = [
  { name: 'sovereign',   min: 800, max: 1000 },
  { name: 'elevated',    min: 600, max: 799  },
  { name: 'standard',    min: 400, max: 599  },
  { name: 'provisional', min: 200, max: 399  },
  { name: 'unverified',  min: 0,   max: 199  },
];

// Capital staking tiers: USDC → pillar score
const CAPITAL_CURVE = [
  { threshold: 100_000, score: 100 },
  { threshold: 50_000,  score: 85  },
  { threshold: 10_000,  score: 65  },
  { threshold: 1_000,   score: 40  },
  { threshold: 100,     score: 20  },
  { threshold: 0,       score: 5   },
];

// ─── Tier Helper ─────────────────────────────────────────────

function scoreTier(score) {
  for (const t of TIERS) {
    if (score >= t.min) return t.name;
  }
  return 'unverified';
}

// ─── Pillar Computations ─────────────────────────────────────

/**
 * Pillar 1: Transaction Success Rate (0–100)
 * Based on behavioral events for the agent.
 */
function computeTransactionPillar(agentId) {
  const events = db.prepare(`
    SELECT event_type, COUNT(*) as cnt
    FROM behavioral_events
    WHERE agent_id = ?
    GROUP BY event_type
  `).all(agentId);

  const counts = {};
  for (const e of events) counts[e.event_type] = e.cnt;

  const successes = (counts['transaction_complete'] || 0) + (counts['sla_met'] || 0);
  const failures  = (counts['transaction_failed']   || 0) + (counts['sla_violated'] || 0);
  const disputes  = (counts['dispute_filed']        || 0);
  const total     = successes + failures + disputes;

  if (total === 0) {
    return { score: 50, details: { successes: 0, failures: 0, disputes: 0, total: 0, note: 'no_history' } };
  }

  const successRate = successes / total;
  const disputeRate = disputes / total;

  // Start from success rate, penalise disputes more aggressively
  let raw = successRate * 100 - disputeRate * 40;
  raw = Math.max(0, Math.min(100, raw));

  const reasonCodes = [];
  if (successRate < 0.5) reasonCodes.push('LOW_SUCCESS_RATE');
  if (disputeRate > 0.1) reasonCodes.push('HIGH_DISPUTE_RATE');
  if (total < 5)         reasonCodes.push('INSUFFICIENT_HISTORY');

  return {
    score: raw,
    details: { successes, failures, disputes, total, successRate, disputeRate },
    reasonCodes,
  };
}

/**
 * Pillar 2: Capital Staked (0–100)
 * Looks at active insurance policies as a proxy for staked capital.
 */
function computeCapitalPillar(agentId) {
  const policies = db.prepare(`
    SELECT SUM(coverage_amount_usdc) as total_coverage,
           SUM(premium_usdc) as total_premium,
           COUNT(*) as policy_count
    FROM insurance_policies
    WHERE agent_id = ? AND status = 'active'
  `).get(agentId);

  const stakedUsdc = (policies?.total_coverage || 0) + (policies?.total_premium || 0);

  let score = 5;
  for (const tier of CAPITAL_CURVE) {
    if (stakedUsdc >= tier.threshold) { score = tier.score; break; }
  }

  const reasonCodes = [];
  if (stakedUsdc === 0)     reasonCodes.push('NO_CAPITAL_STAKED');
  if (stakedUsdc < 1000)    reasonCodes.push('LOW_CAPITAL_STAKED');

  return {
    score,
    details: { stakedUsdc, policyCount: policies?.policy_count || 0 },
    reasonCodes,
  };
}

/**
 * Pillar 3: Network Centrality (0–100)
 * Simplified PageRank approximation from the transaction graph.
 * Counts unique counterparties and transaction volume as centrality proxies.
 */
function computeCentralityPillar(agentId) {
  const txData = db.prepare(`
    SELECT
      COUNT(DISTINCT counterparty_id) as unique_counterparties,
      SUM(CASE WHEN transaction_value > 0 THEN transaction_value ELSE 0 END) as total_volume,
      COUNT(*) as total_events
    FROM behavioral_events
    WHERE agent_id = ? AND counterparty_id IS NOT NULL
  `).get(agentId);

  const uniqueCounterparties = txData?.unique_counterparties || 0;
  const totalVolume = txData?.total_volume || 0;

  // Simple PageRank proxy: log-scaled counterparty count + volume bonus
  let score = 5;
  if (uniqueCounterparties > 0) {
    const counterpartyScore = Math.min(50, Math.log2(uniqueCounterparties + 1) * 12);
    const volumeScore = totalVolume > 0 ? Math.min(50, Math.log10(totalVolume + 1) * 15) : 0;
    score = Math.min(100, counterpartyScore + volumeScore);
  }

  const reasonCodes = [];
  if (uniqueCounterparties < 3) reasonCodes.push('LOW_NETWORK_CONNECTIONS');

  return {
    score,
    details: { uniqueCounterparties, totalVolume },
    reasonCodes,
  };
}

/**
 * Pillar 4: Identity Strength (0–100)
 * Checksum stability, DID anchor, key age, ZKP credentials.
 */
function computeIdentityPillar(agentId) {
  const agent = db.prepare('SELECT * FROM agents WHERE id = ?').get(agentId);
  if (!agent) return { score: 0, details: { error: 'agent_not_found' }, reasonCodes: ['AGENT_NOT_FOUND'] };

  let score = 0;
  const reasonCodes = [];

  // DID anchor: +25
  if (agent.did) score += 25;
  else reasonCodes.push('NO_DID_ANCHOR');

  // Public key present: +15
  if (agent.public_key) score += 15;
  else reasonCodes.push('NO_PUBLIC_KEY');

  // Checksum present (IETF A-JWT): +15
  if (agent.checksum) score += 15;
  else reasonCodes.push('NO_CHECKSUM');

  // Key age bonus (older = more stable): up to +20
  const createdAt = new Date(agent.created_at);
  const ageMs = Date.now() - createdAt.getTime();
  const ageDays = ageMs / (1000 * 60 * 60 * 24);
  const ageBonus = Math.min(20, ageDays / 18.25); // full bonus at 1 year
  score += ageBonus;

  // ZKP / identity credentials: +15 per credential, up to +25
  const idCreds = db.prepare(`
    SELECT COUNT(*) as cnt FROM credentials
    WHERE agent_id = ? AND credential_type = 'identity_verification' AND status = 'active'
  `).get(agentId);
  const zkpScore = Math.min(25, (idCreds?.cnt || 0) * 15);
  score += zkpScore;
  if ((idCreds?.cnt || 0) === 0) reasonCodes.push('NO_IDENTITY_CREDENTIALS');

  // Version stability: fewer major changes = higher stability (up to 5 bonus)
  const versionCount = db.prepare('SELECT COUNT(*) as cnt FROM agent_versions WHERE agent_id = ?').get(agentId);
  if ((versionCount?.cnt || 0) <= 3) score += 5;

  score = Math.min(100, Math.max(0, score));

  return {
    score,
    details: {
      hasDid: Boolean(agent.did),
      hasPublicKey: Boolean(agent.public_key),
      hasChecksum: Boolean(agent.checksum),
      ageDays: Math.round(ageDays),
      identityCredentials: idCreds?.cnt || 0,
      versionCount: versionCount?.cnt || 0,
    },
    reasonCodes,
  };
}

/**
 * Pillar 5: Compliance (0–100)
 * EU AI Act class, NIST alignment, compliance certifications.
 */
function computeCompliancePillar(agentId) {
  const agent = db.prepare('SELECT eu_ai_act_class, nist_ai_rmf_aligned FROM agents WHERE id = ?').get(agentId);
  if (!agent) return { score: 0, details: {}, reasonCodes: ['AGENT_NOT_FOUND'] };

  let score = 0;
  const reasonCodes = [];

  // EU AI Act class scoring
  const euScores = {
    minimal_risk:    40,
    limited_risk:    30,
    high_risk:       15,
    unacceptable:    0,
  };
  const euScore = euScores[agent.eu_ai_act_class] ?? 20;
  score += euScore;
  if (agent.eu_ai_act_class === 'high_risk') reasonCodes.push('EU_HIGH_RISK_CLASS');
  if (agent.eu_ai_act_class === 'unacceptable') reasonCodes.push('EU_UNACCEPTABLE_CLASS');

  // NIST AI RMF alignment: +25
  if (agent.nist_ai_rmf_aligned) score += 25;
  else reasonCodes.push('NOT_NIST_ALIGNED');

  // Compliance certifications: +10 each, up to 35
  const compCreds = db.prepare(`
    SELECT COUNT(*) as cnt FROM credentials
    WHERE agent_id = ? AND credential_type = 'compliance_certification' AND status = 'active'
  `).get(agentId);
  const compBonus = Math.min(35, (compCreds?.cnt || 0) * 10);
  score += compBonus;
  if ((compCreds?.cnt || 0) === 0) reasonCodes.push('NO_COMPLIANCE_CERTIFICATIONS');

  score = Math.min(100, Math.max(0, score));

  return {
    score,
    details: {
      euAiActClass: agent.eu_ai_act_class,
      nistAligned: Boolean(agent.nist_ai_rmf_aligned),
      complianceCertifications: compCreds?.cnt || 0,
    },
    reasonCodes,
  };
}

// ─── Composite Score ─────────────────────────────────────────

function computeComposite(pillars) {
  return Math.round(
    pillars.transaction.score * WEIGHTS.transaction * 10 +
    pillars.capital.score     * WEIGHTS.capital     * 10 +
    pillars.centrality.score  * WEIGHTS.centrality  * 10 +
    pillars.identity.score    * WEIGHTS.identity    * 10 +
    pillars.compliance.score  * WEIGHTS.compliance  * 10
  );
}

function buildReasonCodes(pillars, score, tier) {
  const codes = [
    ...(pillars.transaction.reasonCodes || []),
    ...(pillars.capital.reasonCodes     || []),
    ...(pillars.centrality.reasonCodes  || []),
    ...(pillars.identity.reasonCodes    || []),
    ...(pillars.compliance.reasonCodes  || []),
  ];
  if (tier === 'unverified')  codes.push('TIER_UNVERIFIED');
  if (tier === 'provisional') codes.push('TIER_PROVISIONAL');
  return [...new Set(codes)];
}

function buildFlags(pillars, agent) {
  const flags = [];
  if (pillars.transaction.score < 20)  flags.push('VERY_LOW_TRANSACTION_SCORE');
  if (pillars.identity.score < 20)     flags.push('WEAK_IDENTITY');
  if (pillars.compliance.score < 20)   flags.push('COMPLIANCE_GAP');
  if (agent?.status === 'suspended')   flags.push('AGENT_SUSPENDED');
  if ((agent?.trust_score || 0) < 200) flags.push('BELOW_THRESHOLD');
  return flags;
}

function verdictFromScore(score, flags) {
  if (score >= 400 && !flags.includes('AGENT_SUSPENDED')) return 'ALLOW';
  if (score >= 200) return 'FLAG';
  return 'BLOCK';
}

function maxTransactionFromScore(score) {
  if (score >= 800) return -1;          // unlimited
  if (score >= 600) return 100_000;
  if (score >= 400) return 10_000;
  if (score >= 200) return 1_000;
  return 100;
}

// ─── Public API ───────────────────────────────────────────────

/**
 * Compute and persist a new trust score for the agent.
 *
 * @param {string} agentId
 * @returns {{ success: boolean, scoreRecord?: object, error?: string }}
 */
export function computeTrustScore(agentId) {
  try {
    const agent = db.prepare('SELECT * FROM agents WHERE id = ?').get(agentId);
    if (!agent) return { success: false, error: 'Agent not found' };

    const pillars = {
      transaction: computeTransactionPillar(agentId),
      capital:     computeCapitalPillar(agentId),
      centrality:  computeCentralityPillar(agentId),
      identity:    computeIdentityPillar(agentId),
      compliance:  computeCompliancePillar(agentId),
    };

    const score   = Math.max(0, Math.min(1000, computeComposite(pillars)));
    const tier    = scoreTier(score);
    const reasons = buildReasonCodes(pillars, score, tier);
    const flags   = buildFlags(pillars, agent);
    const verdict = verdictFromScore(score, flags);
    const maxTx   = maxTransactionFromScore(score);

    const id = uuidv4();

    db.prepare(`
      INSERT INTO trust_scores (
        id, agent_id, score, tier,
        identity_score, behavior_score, fidelity_score, compliance_score, provenance_score,
        identity_details, behavior_details, fidelity_details, compliance_details, provenance_details,
        reason_codes, flags, verdict, max_transaction, human_review_required,
        score_version, model_version, computed_at
      ) VALUES (
        ?, ?,  ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        '1.0', '1.0', datetime('now')
      )
    `).run(
      id, agentId, score, tier,
      pillars.identity.score,
      pillars.transaction.score,
      pillars.centrality.score,
      pillars.compliance.score,
      pillars.capital.score,
      JSON.stringify(pillars.identity.details),
      JSON.stringify(pillars.transaction.details),
      JSON.stringify(pillars.centrality.details),
      JSON.stringify(pillars.compliance.details),
      JSON.stringify(pillars.capital.details),
      JSON.stringify(reasons),
      JSON.stringify(flags),
      verdict,
      maxTx,
      flags.includes('AGENT_SUSPENDED') || score < 200 ? 1 : 0
    );

    // Update agent's cached trust score and tier
    db.prepare(`
      UPDATE agents SET trust_score = ?, trust_tier = ?, updated_at = datetime('now') WHERE id = ?
    `).run(score, tier, agentId);

    audit.log('system', 'system', 'score.compute', 'trust_score', id,
      { agentId, score, tier, verdict });

    return {
      success: true,
      scoreRecord: {
        id, agentId, score, tier, verdict,
        pillars: {
          transaction: { score: pillars.transaction.score, details: pillars.transaction.details },
          capital:     { score: pillars.capital.score,     details: pillars.capital.details     },
          centrality:  { score: pillars.centrality.score,  details: pillars.centrality.details  },
          identity:    { score: pillars.identity.score,    details: pillars.identity.details    },
          compliance:  { score: pillars.compliance.score,  details: pillars.compliance.details  },
        },
        reason_codes: reasons,
        flags,
        max_transaction: maxTx,
        human_review_required: flags.includes('AGENT_SUSPENDED') || score < 200,
        computed_at: new Date().toISOString(),
      },
    };
  } catch (err) {
    console.error('[trust-scoring] computeTrustScore failed:', err.message);
    return { success: false, error: err.message };
  }
}

/**
 * Get the latest trust score for an agent.
 *
 * @param {string} agentId
 * @returns {{ success: boolean, scoreRecord?: object, error?: string }}
 */
export function getTrustScore(agentId) {
  try {
    const row = db.prepare(`
      SELECT * FROM trust_scores WHERE agent_id = ? ORDER BY computed_at DESC LIMIT 1
    `).get(agentId);

    if (!row) {
      // No score yet — compute on first request
      return computeTrustScore(agentId);
    }

    return { success: true, scoreRecord: deserializeScore(row) };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Get score history for an agent.
 *
 * @param {string} agentId
 * @param {number} [limit=30]
 * @returns {{ success: boolean, history?: object[], error?: string }}
 */
export function getScoreHistory(agentId, limit = 30) {
  try {
    const rows = db.prepare(`
      SELECT * FROM trust_scores WHERE agent_id = ? ORDER BY computed_at DESC LIMIT ?
    `).all(agentId, limit);

    return {
      success: true,
      history: rows.map(deserializeScore),
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Lightweight risk check for payment processors.
 * Returns quickly without full pillar recomputation — uses latest cached score.
 *
 * @param {string} agentId
 * @returns {{ success: boolean, verdict?: string, score?: number, tier?: string, flags?: string[], error?: string }}
 */
export function quickRiskCheck(agentId) {
  try {
    const agent = db.prepare('SELECT id, status, trust_score, trust_tier FROM agents WHERE id = ?').get(agentId);
    if (!agent) return { success: false, error: 'Agent not found', verdict: 'BLOCK' };

    const latest = db.prepare(`
      SELECT score, tier, verdict, flags, max_transaction, human_review_required, computed_at
      FROM trust_scores WHERE agent_id = ? ORDER BY computed_at DESC LIMIT 1
    `).get(agentId);

    const score = latest?.score ?? agent.trust_score ?? 0;
    const tier  = latest?.tier  ?? agent.trust_tier  ?? 'unverified';
    const flags = JSON.parse(latest?.flags || '[]');

    // Force BLOCK on suspended agents regardless of score
    let verdict;
    if (agent.status === 'deactivated' || agent.status === 'suspended') {
      verdict = 'BLOCK';
      flags.push('AGENT_INACTIVE');
    } else {
      verdict = verdictFromScore(score, flags);
    }

    audit.log('system', 'system', 'score.quick_risk_check', 'agent', agentId, { verdict, score, tier });

    return {
      success: true,
      agentId,
      verdict,
      score,
      tier,
      flags,
      max_transaction: maxTransactionFromScore(score),
      human_review_required: Boolean(latest?.human_review_required),
      score_age_seconds: latest?.computed_at
        ? Math.round((Date.now() - new Date(latest.computed_at).getTime()) / 1000)
        : null,
    };
  } catch (err) {
    console.error('[trust-scoring] quickRiskCheck failed:', err.message);
    return { success: false, error: err.message, verdict: 'FLAG' };
  }
}

// ─── Serialization Helper ─────────────────────────────────────

function deserializeScore(row) {
  if (!row) return null;
  return {
    ...row,
    identity_details:   JSON.parse(row.identity_details   || '{}'),
    behavior_details:   JSON.parse(row.behavior_details   || '{}'),
    fidelity_details:   JSON.parse(row.fidelity_details   || '{}'),
    compliance_details: JSON.parse(row.compliance_details || '{}'),
    provenance_details: JSON.parse(row.provenance_details || '{}'),
    reason_codes:       JSON.parse(row.reason_codes       || '[]'),
    flags:              JSON.parse(row.flags              || '[]'),
    human_review_required: Boolean(row.human_review_required),
  };
}
