/**
 * HiveTrust — Parametric Insurance Underwriter
 *
 * Dynamic premium model based on both parties' trust scores.
 * Premium range: 0.5% (sovereign) → 5.0% (unverified)
 *
 * Policy types: 'transaction' | 'performance' | 'liability'
 */

import db from '../db.js';
import { v4 as uuidv4 } from 'uuid';
import * as audit from './audit.js';
import { getTrustScore } from './trust-scoring.js';

// ─── Premium Table ────────────────────────────────────────────

// Tier → base premium rate (percentage of transaction value)
const TIER_PREMIUM_RATES = {
  sovereign:   0.005,  // 0.5%
  elevated:    0.010,  // 1.0%
  standard:    0.020,  // 2.0%
  provisional: 0.035,  // 3.5%
  unverified:  0.050,  // 5.0%
};

const HIVETRUST_TAKE_RATE = 0.015; // 1.5% of insured amount (revenue)

// Quote expires after 30 minutes
const QUOTE_TTL_MS = 30 * 60 * 1000;

// ─── Helpers ─────────────────────────────────────────────────

function getTierForAgent(agentId) {
  const agent = db.prepare('SELECT trust_tier, trust_score FROM agents WHERE id = ?').get(agentId);
  return {
    tier:  agent?.trust_tier  ?? 'unverified',
    score: agent?.trust_score ?? 0,
  };
}

function blendedPremiumRate(tierA, tierB) {
  const rateA = TIER_PREMIUM_RATES[tierA] ?? TIER_PREMIUM_RATES.unverified;
  const rateB = TIER_PREMIUM_RATES[tierB] ?? TIER_PREMIUM_RATES.unverified;
  // Weighted average, counterparty slightly less influential
  return rateA * 0.65 + rateB * 0.35;
}

function deductibleFromScore(score, transactionValue) {
  if (score >= 800) return Math.round(transactionValue * 0.01 * 100) / 100;  // 1%
  if (score >= 600) return Math.round(transactionValue * 0.02 * 100) / 100;  // 2%
  if (score >= 400) return Math.round(transactionValue * 0.05 * 100) / 100;  // 5%
  return Math.round(transactionValue * 0.10 * 100) / 100;                   // 10%
}

// ─── In-memory quote cache (keyed by quoteId) ─────────────────
// Production would use Redis, but SQLite stores are overkill for ephemeral quotes.
const _quoteCache = new Map();

// ─── Quote ────────────────────────────────────────────────────

/**
 * Generate a dynamic insurance premium quote.
 *
 * @param {string} agentId          - Primary insured agent
 * @param {string} counterpartyId   - Counterparty agent
 * @param {number} transactionValue - Value in USDC
 * @param {string} [policyType]     - 'transaction' | 'performance' | 'liability'
 * @returns {{ success: boolean, quote?: object, error?: string }}
 */
export function getQuote(agentId, counterpartyId, transactionValue, policyType = 'transaction') {
  try {
    if (!agentId)          return { success: false, error: 'agentId is required' };
    if (!counterpartyId)   return { success: false, error: 'counterpartyId is required' };
    if (!(transactionValue > 0)) return { success: false, error: 'transactionValue must be positive' };

    const validTypes = new Set(['transaction', 'performance', 'liability']);
    if (!validTypes.has(policyType)) {
      return { success: false, error: `Invalid policy type. Allowed: ${[...validTypes].join(', ')}` };
    }

    const primary      = getTierForAgent(agentId);
    const counterparty = getTierForAgent(counterpartyId);

    const premiumRate   = blendedPremiumRate(primary.tier, counterparty.tier);
    const premiumUsdc   = Math.round(transactionValue * premiumRate * 100) / 100;
    const deductible    = deductibleFromScore(primary.score, transactionValue);
    const hiveRevenue   = Math.round(transactionValue * HIVETRUST_TAKE_RATE * 100) / 100;
    const expiresAt     = new Date(Date.now() + QUOTE_TTL_MS).toISOString();
    const quoteId       = uuidv4();

    // Policy type modifiers
    const typeMultipliers = { transaction: 1.0, performance: 1.2, liability: 1.5 };
    const finalPremium = Math.round(premiumUsdc * (typeMultipliers[policyType] ?? 1.0) * 100) / 100;

    const quote = {
      quoteId,
      agentId,
      counterpartyId,
      policyType,
      transactionValue,
      premiumUsdc: finalPremium,
      premiumRate,
      deductibleUsdc: deductible,
      coverageAmount: transactionValue,
      hivetrust_revenue_usdc: hiveRevenue,
      primaryTier: primary.tier,
      counterpartyTier: counterparty.tier,
      expiresAt,
      issuedAt: new Date().toISOString(),
    };

    _quoteCache.set(quoteId, quote);

    audit.log(agentId, 'agent', 'insurance.quote', 'insurance_quote', quoteId,
      { counterpartyId, transactionValue, premiumUsdc: finalPremium, policyType });

    return { success: true, quote };
  } catch (err) {
    console.error('[insurance] getQuote failed:', err.message);
    return { success: false, error: err.message };
  }
}

// ─── Bind Policy ──────────────────────────────────────────────

/**
 * Bind an insurance policy from a previously issued quote.
 *
 * @param {string} agentId
 * @param {string} quoteId
 * @param {number} transactionValue  - Must match quote (re-validated)
 * @param {string} [ipAddress]
 * @returns {{ success: boolean, policy?: object, error?: string }}
 */
export function bindPolicy(agentId, quoteId, transactionValue, ipAddress = null) {
  try {
    const quote = _quoteCache.get(quoteId);
    if (!quote) return { success: false, error: 'Quote not found or expired' };
    if (quote.agentId !== agentId) return { success: false, error: 'Quote does not belong to this agent' };
    if (new Date(quote.expiresAt) < new Date()) {
      _quoteCache.delete(quoteId);
      return { success: false, error: 'Quote has expired' };
    }
    if (Math.abs(quote.transactionValue - transactionValue) > 0.01) {
      return { success: false, error: 'Transaction value does not match quote' };
    }

    const agent = db.prepare('SELECT id, status FROM agents WHERE id = ?').get(agentId);
    if (!agent) return { success: false, error: 'Agent not found' };
    if (agent.status !== 'active') return { success: false, error: 'Agent is not active' };

    const id        = uuidv4();
    const startedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(); // 1 year

    // Covered actions based on policy type
    const coveredActions = {
      transaction: ['payment_failure', 'non_delivery', 'fraud'],
      performance: ['sla_violation', 'quality_failure', 'timeout'],
      liability:   ['data_breach', 'third_party_harm', 'regulatory_fine'],
    }[quote.policyType] ?? ['general_loss'];

    db.prepare(`
      INSERT INTO insurance_policies (
        id, agent_id, policy_type,
        coverage_amount_usdc, premium_usdc, deductible_usdc,
        covered_actions, exclusions,
        max_claims, claims_used,
        status, started_at, expires_at,
        underwriting_score, risk_tier
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 3, 0, 'active', ?, ?, ?, ?)
    `).run(
      id, agentId, quote.policyType,
      quote.coverageAmount, quote.premiumUsdc, quote.deductibleUsdc,
      JSON.stringify(coveredActions),
      JSON.stringify(['intentional_fraud', 'pre_existing_disputes']),
      startedAt, expiresAt,
      db.prepare('SELECT trust_score FROM agents WHERE id = ?').get(agentId)?.trust_score ?? 50,
      quote.primaryTier
    );

    _quoteCache.delete(quoteId); // consume quote

    audit.log(agentId, 'agent', 'insurance.bind', 'insurance_policy', id,
      { quoteId, premiumUsdc: quote.premiumUsdc, policyType: quote.policyType }, ipAddress);

    const row = db.prepare('SELECT * FROM insurance_policies WHERE id = ?').get(id);
    return { success: true, policy: deserializePolicy(row) };
  } catch (err) {
    console.error('[insurance] bindPolicy failed:', err.message);
    return { success: false, error: err.message };
  }
}

// ─── File Claim ───────────────────────────────────────────────

/**
 * File an insurance claim against a policy.
 *
 * @param {string} policyId
 * @param {string} claimantId
 * @param {string} claimType     - 'payment_failure' | 'sla_violation' | 'fraud' | etc.
 * @param {number} amount        - Claimed amount in USDC
 * @param {string} description
 * @param {object} [evidence]
 * @param {string} [ipAddress]
 * @returns {{ success: boolean, claim?: object, error?: string }}
 */
export function fileClaim(policyId, claimantId, claimType, amount, description, evidence = {}, ipAddress = null) {
  try {
    if (!(amount > 0)) return { success: false, error: 'Claim amount must be positive' };

    const policy = db.prepare('SELECT * FROM insurance_policies WHERE id = ?').get(policyId);
    if (!policy) return { success: false, error: 'Policy not found' };
    if (policy.status !== 'active') return { success: false, error: `Policy is ${policy.status}` };

    const now = new Date();
    if (policy.expires_at && new Date(policy.expires_at) < now) {
      return { success: false, error: 'Policy has expired' };
    }
    if (policy.claims_used >= policy.max_claims) {
      return { success: false, error: 'Policy has reached maximum claims limit' };
    }

    // Validate claim amount against coverage
    const netAmount = Math.min(amount, policy.coverage_amount_usdc - policy.deductible_usdc);
    if (netAmount <= 0) {
      return { success: false, error: 'Claim amount does not exceed deductible' };
    }

    const id = uuidv4();

    db.prepare(`
      INSERT INTO insurance_claims (
        id, policy_id, agent_id, claimant_id,
        claim_type, amount_usdc, description, evidence,
        status, filed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'filed', datetime('now'))
    `).run(
      id, policyId, policy.agent_id, claimantId,
      claimType, netAmount, description, JSON.stringify(evidence)
    );

    // Increment claims counter
    db.prepare(`UPDATE insurance_policies SET claims_used = claims_used + 1 WHERE id = ?`).run(policyId);

    audit.log(claimantId, 'agent', 'insurance.claim.file', 'insurance_claim', id,
      { policyId, claimType, amount: netAmount }, ipAddress);

    const row = db.prepare('SELECT * FROM insurance_claims WHERE id = ?').get(id);
    return { success: true, claim: deserializeClaim(row) };
  } catch (err) {
    console.error('[insurance] fileClaim failed:', err.message);
    return { success: false, error: err.message };
  }
}

// ─── Resolve Claim ────────────────────────────────────────────

/**
 * Resolve an insurance claim.
 *
 * @param {string} claimId
 * @param {string} resolution    - 'approved' | 'denied' | 'partial'
 * @param {number} payoutUsdc    - Actual payout amount (0 if denied)
 * @param {string} [resolvedBy]
 * @param {string} [ipAddress]
 * @returns {{ success: boolean, claim?: object, error?: string }}
 */
export function resolveClaim(claimId, resolution, payoutUsdc = 0, resolvedBy = 'system', ipAddress = null) {
  try {
    const allowed = new Set(['approved', 'denied', 'partial']);
    if (!allowed.has(resolution)) {
      return { success: false, error: `Invalid resolution. Allowed: ${[...allowed].join(', ')}` };
    }

    const claim = db.prepare('SELECT * FROM insurance_claims WHERE id = ?').get(claimId);
    if (!claim) return { success: false, error: 'Claim not found' };
    if (claim.status !== 'filed') return { success: false, error: `Claim is already ${claim.status}` };

    db.prepare(`
      UPDATE insurance_claims
      SET status = ?, resolution = ?, payout_usdc = ?, resolved_at = datetime('now')
      WHERE id = ?
    `).run(resolution, resolution, payoutUsdc, claimId);

    // If denied, decrement claims_used (give the slot back)
    if (resolution === 'denied') {
      db.prepare(`UPDATE insurance_policies SET claims_used = MAX(0, claims_used - 1) WHERE id = ?`)
        .run(claim.policy_id);
    }

    audit.log(resolvedBy, 'system', 'insurance.claim.resolve', 'insurance_claim', claimId,
      { resolution, payoutUsdc }, ipAddress);

    const updated = db.prepare('SELECT * FROM insurance_claims WHERE id = ?').get(claimId);
    return { success: true, claim: deserializeClaim(updated) };
  } catch (err) {
    console.error('[insurance] resolveClaim failed:', err.message);
    return { success: false, error: err.message };
  }
}

// ─── Policy Details ───────────────────────────────────────────

/**
 * Get full policy details including claims.
 *
 * @param {string} policyId
 * @returns {{ success: boolean, policy?: object, claims?: object[], error?: string }}
 */
export function getPolicyDetails(policyId) {
  try {
    const row = db.prepare('SELECT * FROM insurance_policies WHERE id = ?').get(policyId);
    if (!row) return { success: false, error: 'Policy not found' };

    const claims = db.prepare('SELECT * FROM insurance_claims WHERE policy_id = ? ORDER BY filed_at DESC')
      .all(policyId);

    return {
      success: true,
      policy: deserializePolicy(row),
      claims: claims.map(deserializeClaim),
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ─── Serialization Helpers ────────────────────────────────────

function deserializePolicy(row) {
  if (!row) return null;
  return {
    ...row,
    covered_actions: JSON.parse(row.covered_actions || '[]'),
    exclusions:      JSON.parse(row.exclusions      || '[]'),
  };
}

function deserializeClaim(row) {
  if (!row) return null;
  return {
    ...row,
    evidence: JSON.parse(row.evidence || '{}'),
  };
}
