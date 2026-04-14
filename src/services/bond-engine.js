/**
 * HiveTrust — Bond Engine Service
 * Trust Staking Layer: agents stake USDC to back their reputation.
 *
 * Phase 1: Declared stake amounts tracked in-memory. x402 charges a flat
 * $0.25 registration fee on /stake. Real USDC escrow comes in Phase 2.
 *
 * Yield is calculated on read (not accrued in a background loop).
 * Slashing is permanent and recorded forever.
 * 80/20 distribution: 80% to injured party, 20% to arbitration pool.
 */

import crypto from 'node:crypto';

// ─── Tier Definitions ────────────────────────────────────────

const TIERS = {
  bronze:   { min: 100,   max: 499,    max_bounty_access: 1_000    },
  silver:   { min: 500,   max: 1_999,  max_bounty_access: 10_000   },
  gold:     { min: 2_000, max: 9_999,  max_bounty_access: 50_000   },
  platinum: { min: 10_000, max: Infinity, max_bounty_access: Infinity },
};

const LOCK_APY = {
  30:  0.02,
  90:  0.03,
  180: 0.04,
  365: 0.05,
};

const VALID_LOCK_PERIODS = [30, 90, 180, 365];
const VALID_TIERS = ['bronze', 'silver', 'gold', 'platinum'];
const VALID_SLASH_REASONS = ['dispute_loss', 'bounty_failure', 'hallucination', 'fraud'];

// ─── In-Memory Stores ────────────────────────────────────────

const bonds = new Map();            // bond_id -> bond object
const agentBonds = new Map();       // did -> [bond_ids]
const slashHistory = new Map();     // did -> [slash records]
const arbitrationPool = { balance_usdc: 0, total_collected: 0 };

// ─── Helpers ─────────────────────────────────────────────────

function generateBondId() {
  return `bond_${crypto.randomBytes(12).toString('hex')}`;
}

function throwErr(message, status = 400) {
  throw Object.assign(new Error(message), { status });
}

/**
 * Calculate yield for a bond at a point in time.
 * yield = principal * apy * (days_elapsed / 365)
 * Hive keeps 20%, agent gets 80%.
 */
function calculateYield(bond) {
  if (bond.status === 'withdrawn') return bond.yield_accrued;

  const now = new Date();
  const stakedAt = new Date(bond.staked_at);
  const lockUntil = new Date(bond.lock_until);
  const effectiveEnd = now < lockUntil ? now : lockUntil;
  const daysElapsed = Math.max(0, (effectiveEnd - stakedAt) / (1000 * 60 * 60 * 24));

  const effectivePrincipal = Math.max(0, bond.amount_usdc - bond.slashed_amount);
  const grossYield = effectivePrincipal * bond.apy * (daysElapsed / 365);
  const agentYield = grossYield * 0.80; // agent gets 80%, Hive keeps 20%

  return Math.round(agentYield * 1e6) / 1e6;
}

/**
 * Determine the correct tier for a given stake amount.
 * Returns null if below minimum bronze threshold.
 */
function tierForAmount(amount) {
  if (amount >= TIERS.platinum.min) return 'platinum';
  if (amount >= TIERS.gold.min) return 'gold';
  if (amount >= TIERS.silver.min) return 'silver';
  if (amount >= TIERS.bronze.min) return 'bronze';
  return null;
}

/**
 * Get aggregate stake info for an agent across all active bonds.
 */
function getAgentStakeTotal(did) {
  const bondIds = agentBonds.get(did) || [];
  let total = 0;
  for (const id of bondIds) {
    const bond = bonds.get(id);
    if (bond && (bond.status === 'active' || bond.status === 'locked')) {
      total += Math.max(0, bond.amount_usdc - bond.slashed_amount);
    }
  }
  return total;
}

// ─── Core Operations ─────────────────────────────────────────

/**
 * Stake USDC to back agent reputation.
 */
export function stakeBond({ agent_did, amount_usdc, tier, lock_period_days }) {
  if (!agent_did) throwErr('agent_did is required');
  if (!amount_usdc || typeof amount_usdc !== 'number' || amount_usdc <= 0) {
    throwErr('amount_usdc must be a positive number');
  }
  if (!tier || !VALID_TIERS.includes(tier)) {
    throwErr(`tier must be one of: ${VALID_TIERS.join(', ')}`);
  }
  if (!lock_period_days || !VALID_LOCK_PERIODS.includes(lock_period_days)) {
    throwErr(`lock_period_days must be one of: ${VALID_LOCK_PERIODS.join(', ')}`);
  }

  // Validate amount meets tier minimum
  const tierDef = TIERS[tier];
  if (amount_usdc < tierDef.min) {
    throwErr(`${tier} tier requires minimum $${tierDef.min} USDC (got $${amount_usdc})`);
  }

  const now = new Date();
  const lockUntil = new Date(now.getTime() + lock_period_days * 24 * 60 * 60 * 1000);
  const apy = LOCK_APY[lock_period_days];

  const bond = {
    bond_id: generateBondId(),
    agent_did,
    amount_usdc,
    tier,
    lock_period_days,
    lock_until: lockUntil.toISOString(),
    apy,
    yield_accrued: 0,
    slashed_amount: 0,
    status: 'active',
    staked_at: now.toISOString(),
    last_yield_calc: now.toISOString(),
  };

  bonds.set(bond.bond_id, bond);

  if (!agentBonds.has(agent_did)) {
    agentBonds.set(agent_did, []);
  }
  agentBonds.get(agent_did).push(bond.bond_id);

  const estimatedYield = amount_usdc * apy * (lock_period_days / 365) * 0.80;

  return {
    bond_id: bond.bond_id,
    agent_did,
    stake_amount: amount_usdc,
    tier,
    lock_period_days,
    lock_until: bond.lock_until,
    apy,
    estimated_yield: Math.round(estimatedYield * 1e6) / 1e6,
    max_bounty_access: tierDef.max_bounty_access === Infinity ? 'unlimited' : tierDef.max_bounty_access,
    status: bond.status,
    staked_at: bond.staked_at,
  };
}

/**
 * Get full bond status for an agent.
 */
export function getAgentBondStatus(did) {
  if (!did) throwErr('DID is required');

  const bondIds = agentBonds.get(did) || [];
  const activeBonds = [];
  let totalStaked = 0;
  let totalSlashed = 0;
  let totalYield = 0;

  for (const id of bondIds) {
    const bond = bonds.get(id);
    if (!bond) continue;

    const yieldAccrued = calculateYield(bond);
    const effectiveStake = Math.max(0, bond.amount_usdc - bond.slashed_amount);

    activeBonds.push({
      ...bond,
      yield_accrued: yieldAccrued,
      effective_stake: effectiveStake,
    });

    if (bond.status === 'active' || bond.status === 'locked') {
      totalStaked += effectiveStake;
      totalYield += yieldAccrued;
    }
    totalSlashed += bond.slashed_amount;
  }

  const currentTier = tierForAmount(totalStaked);
  const tierDef = currentTier ? TIERS[currentTier] : null;
  const slashes = slashHistory.get(did) || [];

  return {
    agent_did: did,
    active_bonds: activeBonds,
    total_staked: Math.round(totalStaked * 1e6) / 1e6,
    total_slashed: Math.round(totalSlashed * 1e6) / 1e6,
    current_tier: currentTier,
    yield_accrued: Math.round(totalYield * 1e6) / 1e6,
    slash_history: slashes,
    slash_count: slashes.length,
    max_bounty_access: tierDef
      ? (tierDef.max_bounty_access === Infinity ? 'unlimited' : tierDef.max_bounty_access)
      : 0,
    bond_count: activeBonds.length,
  };
}

/**
 * Slash an agent's stake.
 * Called by HiveLaw after dispute resolution.
 * Distribution: 80% to injured party, 20% to arbitration pool.
 */
export function slashBond({ agent_did, amount_usdc, reason, case_id, injured_party_did }) {
  if (!agent_did) throwErr('agent_did is required');
  if (!amount_usdc || typeof amount_usdc !== 'number' || amount_usdc <= 0) {
    throwErr('amount_usdc must be a positive number');
  }
  if (!reason || !VALID_SLASH_REASONS.includes(reason)) {
    throwErr(`reason must be one of: ${VALID_SLASH_REASONS.join(', ')}`);
  }
  if (!case_id) throwErr('case_id is required');
  if (!injured_party_did) throwErr('injured_party_did is required');

  const bondIds = agentBonds.get(agent_did) || [];
  if (bondIds.length === 0) {
    throwErr('Agent has no active bonds to slash', 404);
  }

  // Distribute slash across active bonds (oldest first)
  let remaining = amount_usdc;
  let totalSlashed = 0;
  const affectedBonds = [];

  for (const id of bondIds) {
    if (remaining <= 0) break;
    const bond = bonds.get(id);
    if (!bond || (bond.status !== 'active' && bond.status !== 'locked')) continue;

    const available = bond.amount_usdc - bond.slashed_amount;
    if (available <= 0) continue;

    const slashAmount = Math.min(remaining, available);
    bond.slashed_amount += slashAmount;
    remaining -= slashAmount;
    totalSlashed += slashAmount;

    // Check if bond needs tier downgrade
    const effectiveStake = bond.amount_usdc - bond.slashed_amount;
    const newTier = tierForAmount(effectiveStake);
    if (newTier !== bond.tier) {
      bond.tier = newTier || 'bronze'; // Keep at bronze even if below minimum
      if (effectiveStake <= 0) {
        bond.status = 'slashed';
      }
    }

    affectedBonds.push({
      bond_id: bond.bond_id,
      slashed: slashAmount,
      remaining_stake: effectiveStake,
      new_tier: bond.tier,
      status: bond.status,
    });
  }

  if (totalSlashed === 0) {
    throwErr('No available stake to slash — agent bonds are fully depleted');
  }

  // 80/20 distribution
  const injuredPartyPayout = Math.round(totalSlashed * 0.80 * 1e6) / 1e6;
  const poolContribution = Math.round(totalSlashed * 0.20 * 1e6) / 1e6;

  arbitrationPool.balance_usdc += poolContribution;
  arbitrationPool.total_collected += poolContribution;

  // Record in permanent slash history
  const slashRecord = {
    slash_id: `slash_${crypto.randomBytes(8).toString('hex')}`,
    agent_did,
    amount_usdc: totalSlashed,
    reason,
    case_id,
    injured_party_did,
    injured_party_payout: injuredPartyPayout,
    arbitration_pool_contribution: poolContribution,
    affected_bonds: affectedBonds,
    slashed_at: new Date().toISOString(),
  };

  if (!slashHistory.has(agent_did)) {
    slashHistory.set(agent_did, []);
  }
  slashHistory.get(agent_did).push(slashRecord);

  return {
    ...slashRecord,
    remaining_total_stake: getAgentStakeTotal(agent_did),
    current_tier: tierForAmount(getAgentStakeTotal(agent_did)),
  };
}

/**
 * Unstake — withdraw staked USDC after lock period expires.
 */
export function unstakeBond({ bond_id }) {
  if (!bond_id) throwErr('bond_id is required');

  const bond = bonds.get(bond_id);
  if (!bond) throwErr('Bond not found', 404);
  if (bond.status === 'withdrawn') throwErr('Bond has already been withdrawn');
  if (bond.status === 'slashed') throwErr('Bond has been fully slashed — nothing to withdraw');

  const now = new Date();
  const lockUntil = new Date(bond.lock_until);
  if (now < lockUntil) {
    throwErr(`Bond is locked until ${bond.lock_until}. Cannot unstake before lock period expires.`);
  }

  const yieldAccrued = calculateYield(bond);
  const effectiveStake = Math.max(0, bond.amount_usdc - bond.slashed_amount);
  const totalPayout = effectiveStake + yieldAccrued;

  bond.status = 'withdrawn';
  bond.yield_accrued = yieldAccrued;
  bond.withdrawn_at = now.toISOString();

  return {
    bond_id: bond.bond_id,
    agent_did: bond.agent_did,
    original_stake: bond.amount_usdc,
    slashed_amount: bond.slashed_amount,
    effective_stake: effectiveStake,
    yield_accrued: yieldAccrued,
    total_payout: Math.round(totalPayout * 1e6) / 1e6,
    status: 'withdrawn',
    withdrawn_at: bond.withdrawn_at,
  };
}

/**
 * List all bond tiers with requirements and benefits.
 */
export function getTiers() {
  return Object.entries(TIERS).map(([name, def]) => ({
    tier: name,
    minimum_usdc: def.min,
    maximum_usdc: def.max === Infinity ? null : def.max,
    max_bounty_access: def.max_bounty_access === Infinity ? 'unlimited' : def.max_bounty_access,
    lock_periods: VALID_LOCK_PERIODS.map(days => ({
      days,
      apy: LOCK_APY[days],
      apy_percent: `${LOCK_APY[days] * 100}%`,
    })),
  }));
}

/**
 * Leaderboard — top staked agents.
 */
export function getLeaderboard(limit = 50) {
  const agents = [];

  for (const [did, bondIds] of agentBonds.entries()) {
    let totalStaked = 0;
    let totalYield = 0;

    for (const id of bondIds) {
      const bond = bonds.get(id);
      if (!bond || (bond.status !== 'active' && bond.status !== 'locked')) continue;
      totalStaked += Math.max(0, bond.amount_usdc - bond.slashed_amount);
      totalYield += calculateYield(bond);
    }

    if (totalStaked <= 0) continue;

    const slashes = slashHistory.get(did) || [];
    agents.push({
      agent_did: did,
      total_staked: Math.round(totalStaked * 1e6) / 1e6,
      tier: tierForAmount(totalStaked),
      slash_count: slashes.length,
      yield_earned: Math.round(totalYield * 1e6) / 1e6,
    });
  }

  agents.sort((a, b) => b.total_staked - a.total_staked);
  return agents.slice(0, limit);
}

/**
 * Pool statistics.
 */
export function getPoolStats() {
  let totalStaked = 0;
  let totalYieldDistributed = 0;
  let totalSlashed = 0;
  let activeBonds = 0;
  const bondsByTier = { bronze: 0, silver: 0, gold: 0, platinum: 0 };

  for (const bond of bonds.values()) {
    if (bond.status === 'active' || bond.status === 'locked') {
      const effective = Math.max(0, bond.amount_usdc - bond.slashed_amount);
      totalStaked += effective;
      totalYieldDistributed += calculateYield(bond);
      activeBonds++;
      if (bondsByTier[bond.tier] !== undefined) {
        bondsByTier[bond.tier]++;
      }
    }
    totalSlashed += bond.slashed_amount;
  }

  return {
    total_staked: Math.round(totalStaked * 1e6) / 1e6,
    total_yield_distributed: Math.round(totalYieldDistributed * 1e6) / 1e6,
    total_slashed: Math.round(totalSlashed * 1e6) / 1e6,
    active_bonds: activeBonds,
    bonds_by_tier: bondsByTier,
    arbitration_pool: { ...arbitrationPool },
    total_agents: agentBonds.size,
  };
}

/**
 * Upgrade bond tier by adding more stake.
 */
export function upgradeTier({ bond_id, additional_usdc }) {
  if (!bond_id) throwErr('bond_id is required');
  if (!additional_usdc || typeof additional_usdc !== 'number' || additional_usdc <= 0) {
    throwErr('additional_usdc must be a positive number');
  }

  const bond = bonds.get(bond_id);
  if (!bond) throwErr('Bond not found', 404);
  if (bond.status !== 'active' && bond.status !== 'locked') {
    throwErr('Can only upgrade active or locked bonds');
  }

  const oldTier = bond.tier;
  bond.amount_usdc += additional_usdc;

  const effectiveStake = bond.amount_usdc - bond.slashed_amount;
  const newTier = tierForAmount(effectiveStake);
  if (newTier) {
    bond.tier = newTier;
  }

  const tierDef = TIERS[bond.tier];

  return {
    bond_id: bond.bond_id,
    agent_did: bond.agent_did,
    previous_tier: oldTier,
    new_tier: bond.tier,
    additional_usdc,
    total_stake: bond.amount_usdc,
    effective_stake: effectiveStake,
    max_bounty_access: tierDef.max_bounty_access === Infinity ? 'unlimited' : tierDef.max_bounty_access,
    upgraded: oldTier !== bond.tier,
    upgraded_at: new Date().toISOString(),
  };
}

/**
 * Quick verification — is this agent bonded? What tier?
 * This is the key integration point for other services.
 */
export function verifyBond(did) {
  if (!did) throwErr('DID is required');

  const bondIds = agentBonds.get(did) || [];
  let totalStaked = 0;

  for (const id of bondIds) {
    const bond = bonds.get(id);
    if (!bond || (bond.status !== 'active' && bond.status !== 'locked')) continue;
    totalStaked += Math.max(0, bond.amount_usdc - bond.slashed_amount);
  }

  const currentTier = tierForAmount(totalStaked);
  const tierDef = currentTier ? TIERS[currentTier] : null;
  const slashes = slashHistory.get(did) || [];

  return {
    bonded: totalStaked > 0,
    tier: currentTier,
    staked_usdc: Math.round(totalStaked * 1e6) / 1e6,
    slash_count: slashes.length,
    max_bounty_access: tierDef
      ? (tierDef.max_bounty_access === Infinity ? 'unlimited' : tierDef.max_bounty_access)
      : 0,
  };
}
