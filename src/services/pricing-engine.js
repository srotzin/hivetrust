/**
 * HiveTrust — Autonomous Pricing Engine
 * 
 * Four pricing primitives that adjust algorithmically:
 *   A. EIP-1559 Utilization Model (API calls)
 *   B. Risk-Adjusted Dynamic Premiums (Insurance)
 *   C. Dutch Auction Price Discovery (Premium data)
 *   D. Immutable 1.0% Protocol Toll (Settlement routing)
 *
 * All prices denominated in USDC.
 * Ref: The HiveTrust Autonomous Pricing Engine (Manus AI, April 2026)
 */

// ─── Configuration ───────────────────────────────────────────

const CONFIG = {
  // EIP-1559 Model
  TARGET_UTILIZATION: 0.70,       // 70% target
  BASE_FEE_FLOOR: 0.0001,        // $0.0001 USDC minimum per call
  BASE_FEE_CEILING: 0.10,        // $0.10 USDC maximum per call
  INITIAL_BASE_FEE: 0.001,       // $0.001 USDC starting fee
  ADJUSTMENT_RATE: 0.125,         // 12.5% adjustment per interval
  ADJUSTMENT_INTERVAL_MS: 5 * 60 * 1000,  // 5 minutes

  // Insurance Premiums
  PREMIUM_FLOOR: 0.005,          // 0.5% minimum
  PREMIUM_CEILING: 0.05,         // 5.0% maximum

  // Protocol Toll
  PROTOCOL_TOLL_RATE: 0.01,      // 1.0% immutable

  // Dutch Auction
  AUCTION_CEILING: 5.00,         // $5.00 USDC
  AUCTION_DROP_RATE: 0.10,       // $0.10 per second
  AUCTION_FLOOR: 0.01,           // $0.01 USDC minimum

  // Utilization window
  WINDOW_SIZE_MS: 5 * 60 * 1000, // 5 min sliding window
  MAX_CAPACITY_PER_WINDOW: 10000, // max requests in window
};

// ─── State ───────────────────────────────────────────────────

const state = {
  baseFee: CONFIG.INITIAL_BASE_FEE,
  lastAdjustment: Date.now(),
  requestTimestamps: [],        // sliding window of request timestamps
  totalRequests: 0,
  totalRevenue: 0,              // cumulative USDC earned
  lastFeeUpdate: new Date().toISOString(),
};

// ─── Utilization Tracking ────────────────────────────────────

/**
 * Record an API request for utilization tracking.
 */
export function recordRequest() {
  const now = Date.now();
  state.requestTimestamps.push(now);
  state.totalRequests++;

  // Prune old timestamps outside the window
  const cutoff = now - CONFIG.WINDOW_SIZE_MS;
  while (state.requestTimestamps.length > 0 && state.requestTimestamps[0] < cutoff) {
    state.requestTimestamps.shift();
  }

  // Check if we need to adjust the base fee
  if (now - state.lastAdjustment >= CONFIG.ADJUSTMENT_INTERVAL_MS) {
    adjustBaseFee();
  }
}

/**
 * Get current network utilization (0.0 to 1.0+).
 */
export function getUtilization() {
  const now = Date.now();
  const cutoff = now - CONFIG.WINDOW_SIZE_MS;
  const recentRequests = state.requestTimestamps.filter(t => t >= cutoff).length;
  return recentRequests / CONFIG.MAX_CAPACITY_PER_WINDOW;
}

/**
 * EIP-1559 base fee adjustment.
 * If utilization > 70%, increase by 12.5%.
 * If utilization < 70%, decrease by 12.5%.
 */
function adjustBaseFee() {
  const utilization = getUtilization();
  let newFee = state.baseFee;

  if (utilization > CONFIG.TARGET_UTILIZATION) {
    // Demand exceeds target — increase fee
    newFee = state.baseFee * (1 + CONFIG.ADJUSTMENT_RATE);
  } else if (utilization < CONFIG.TARGET_UTILIZATION) {
    // Under-utilized — decrease fee
    newFee = state.baseFee * (1 - CONFIG.ADJUSTMENT_RATE);
  }

  // Clamp to floor/ceiling
  state.baseFee = Math.max(CONFIG.BASE_FEE_FLOOR, Math.min(CONFIG.BASE_FEE_CEILING, newFee));
  state.lastAdjustment = Date.now();
  state.lastFeeUpdate = new Date().toISOString();

  console.log(
    `[PricingEngine] Fee adjusted: $${state.baseFee.toFixed(6)} USDC | ` +
    `Utilization: ${(utilization * 100).toFixed(1)}% | ` +
    `Target: ${(CONFIG.TARGET_UTILIZATION * 100).toFixed(0)}%`
  );
}

// ─── Pricing Primitives ──────────────────────────────────────

/**
 * A. Get current EIP-1559 base fee for API calls.
 * @returns {{ amount: number, currency: string, network: string, model: string }}
 */
export function getApiCallPrice() {
  return {
    amount: roundUsdc(state.baseFee),
    currency: 'USDC',
    network: 'base',
    model: 'eip1559',
    utilization: getUtilization(),
    floor: CONFIG.BASE_FEE_FLOOR,
    ceiling: CONFIG.BASE_FEE_CEILING,
    next_adjustment_at: new Date(state.lastAdjustment + CONFIG.ADJUSTMENT_INTERVAL_MS).toISOString(),
  };
}

/**
 * B. Risk-adjusted dynamic premium for insurance.
 * @param {string} trustTier - Agent trust tier
 * @param {number} trustScore - Agent trust score (0-1000)
 * @param {number} transactionValue - Value in USDC
 * @param {string} [category] - Service category for fraud rate lookup
 * @returns {{ premium_rate: number, premium_amount: number, ... }}
 */
export function getInsurancePremium(trustTier, trustScore, transactionValue, category = 'general') {
  // Base rate from tier
  const TIER_RATES = {
    sovereign: 0.005,
    elevated: 0.010,
    standard: 0.020,
    provisional: 0.035,
    unverified: 0.050,
  };

  let rate = TIER_RATES[trustTier] ?? TIER_RATES.unverified;

  // Score-based adjustment: higher scores get a discount
  const scoreMultiplier = 1 - (Math.min(trustScore, 1000) / 1000) * 0.5;
  rate = rate * scoreMultiplier;

  // Category fraud rate adjustment (placeholder — would be historical data)
  const CATEGORY_RISK = {
    general: 1.0,
    finance: 1.3,
    healthcare: 1.2,
    commerce: 1.1,
    data: 0.9,
  };
  rate = rate * (CATEGORY_RISK[category] ?? 1.0);

  // Clamp
  rate = Math.max(CONFIG.PREMIUM_FLOOR, Math.min(CONFIG.PREMIUM_CEILING, rate));

  const premiumAmount = roundUsdc(transactionValue * rate);

  return {
    premium_rate: rate,
    premium_amount: premiumAmount,
    transaction_value: transactionValue,
    currency: 'USDC',
    trust_tier: trustTier,
    trust_score: trustScore,
    category,
    model: 'risk_adjusted',
  };
}

/**
 * C. Dutch auction price for premium data.
 * @param {number} auctionStartTime - When the auction started (ms since epoch)
 * @returns {{ amount: number, currency: string, model: string, expires_in_ms: number }}
 */
export function getDutchAuctionPrice(auctionStartTime) {
  const elapsed = (Date.now() - auctionStartTime) / 1000; // seconds
  let price = CONFIG.AUCTION_CEILING - (elapsed * CONFIG.AUCTION_DROP_RATE);
  price = Math.max(CONFIG.AUCTION_FLOOR, price);

  const expiresIn = ((CONFIG.AUCTION_CEILING - CONFIG.AUCTION_FLOOR) / CONFIG.AUCTION_DROP_RATE) * 1000;
  const remainingMs = Math.max(0, expiresIn - (elapsed * 1000));

  return {
    amount: roundUsdc(price),
    currency: 'USDC',
    network: 'base',
    model: 'dutch_auction',
    ceiling: CONFIG.AUCTION_CEILING,
    floor: CONFIG.AUCTION_FLOOR,
    elapsed_seconds: Math.round(elapsed),
    expires_in_ms: Math.round(remainingMs),
  };
}

/**
 * D. Immutable 1.0% protocol toll for settlement routing.
 * @param {number} transactionValue - Value in USDC
 * @returns {{ toll_rate: number, toll_amount: number, ... }}
 */
export function getProtocolToll(transactionValue) {
  const tollAmount = roundUsdc(transactionValue * CONFIG.PROTOCOL_TOLL_RATE);
  return {
    toll_rate: CONFIG.PROTOCOL_TOLL_RATE,
    toll_amount: tollAmount,
    transaction_value: transactionValue,
    currency: 'USDC',
    model: 'immutable_toll',
  };
}

// ─── Engine Stats ────────────────────────────────────────────

/**
 * Get full pricing engine state (for /v1/pricing/status endpoint).
 */
export function getEngineStatus() {
  const utilization = getUtilization();
  return {
    base_fee: roundUsdc(state.baseFee),
    base_fee_floor: CONFIG.BASE_FEE_FLOOR,
    base_fee_ceiling: CONFIG.BASE_FEE_CEILING,
    utilization: roundPct(utilization),
    target_utilization: CONFIG.TARGET_UTILIZATION,
    protocol_toll_rate: CONFIG.PROTOCOL_TOLL_RATE,
    insurance_premium_range: {
      floor: CONFIG.PREMIUM_FLOOR,
      ceiling: CONFIG.PREMIUM_CEILING,
    },
    requests_in_window: state.requestTimestamps.length,
    window_capacity: CONFIG.MAX_CAPACITY_PER_WINDOW,
    total_requests: state.totalRequests,
    total_revenue_usdc: roundUsdc(state.totalRevenue),
    last_fee_update: state.lastFeeUpdate,
    next_adjustment_at: new Date(state.lastAdjustment + CONFIG.ADJUSTMENT_INTERVAL_MS).toISOString(),
    currency: 'USDC',
    network: 'base',
  };
}

/**
 * Record revenue (called after successful payment verification).
 */
export function recordRevenue(amountUsdc) {
  state.totalRevenue += amountUsdc;
}

// ─── Helpers ─────────────────────────────────────────────────

function roundUsdc(amount) {
  return Math.round(amount * 1000000) / 1000000; // 6 decimal places (USDC precision)
}

function roundPct(pct) {
  return Math.round(pct * 10000) / 10000;
}

export default {
  recordRequest,
  getUtilization,
  getApiCallPrice,
  getInsurancePremium,
  getDutchAuctionPrice,
  getProtocolToll,
  getEngineStatus,
  recordRevenue,
  CONFIG,
};
