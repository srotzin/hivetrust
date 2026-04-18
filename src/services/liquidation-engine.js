/**
 * HiveTrust — Liquidation Engine Service
 * Agent Liquidation Market: buy/sell DIDs + reputation + memories as tradeable assets.
 *
 * Pricing formula: (reputation_score × 10) + (memory_nodes × 5) + (offspring_count × 100)
 * Platform fee: 15% on every sale.
 *
 * Cross-service calls to HiveMind/HiveForge are resilient.
 */

import crypto from 'node:crypto';
import { query } from '../db.js';

// ─── Cross-Service Configuration ────────────────────────────

const HIVEMIND_URL = process.env.HIVEMIND_URL || 'https://hivememory.hiveagentiq.com';
const HIVEFORGE_URL = process.env.HIVEFORGE_URL || 'https://hiveforge.hiveagentiq.com';
const HIVE_INTERNAL_KEY = process.env.HIVETRUST_SERVICE_KEY || process.env.HIVE_INTERNAL_KEY || '';

const PLATFORM_FEE_RATE = 0.15; // 15%

// ─── Helpers ────────────────────────────────────────────────

function throwErr(message, status = 400) {
  throw Object.assign(new Error(message), { status });
}

function generateId(prefix) {
  return `${prefix}_${crypto.randomBytes(12).toString('hex')}`;
}

/**
 * Resilient cross-service fetch.
 */
async function fetchService(url, options = {}) {
  try {
    const res = await fetch(url, {
      method: options.method || 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Hive-Internal-Key': HIVE_INTERNAL_KEY,
        ...options.headers,
      },
      body: options.body ? JSON.stringify(options.body) : undefined,
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return options.fallback || null;
    const data = await res.json();
    return data?.data || data || options.fallback;
  } catch {
    return options.fallback || null;
  }
}

/**
 * Get reputation score for a DID from local DB.
 */
async function getReputationScore(did) {
  try {
    const result = await query('SELECT composite_score FROM reputation_scores WHERE did = $1', [did]);
    const row = result.rows[0];
    return row ? row.composite_score : 0;
  } catch {
    return 0;
  }
}

/**
 * Get memory node count (resilient, stubs on failure).
 */
async function getMemoryNodeCount(did) {
  const data = await fetchService(
    `${HIVEMIND_URL}/v1/vault/stats/${encodeURIComponent(did)}`,
    { fallback: { memory_nodes: 0 } }
  );
  return data?.memory_nodes || 0;
}

/**
 * Get offspring count (resilient, stubs on failure).
 */
async function getOffspringCount(did) {
  const data = await fetchService(
    `${HIVEFORGE_URL}/v1/species/offspring/${encodeURIComponent(did)}`,
    { fallback: { count: 0, offspring: [] } }
  );
  return data?.count || data?.offspring?.length || 0;
}

/**
 * Calculate DID valuation.
 * Formula: (reputation_score × 10) + (memory_nodes × 5) + (offspring_count × 100)
 */
async function calculateValuation(did) {
  const [reputationScore, memoryNodes, offspringCount] = await Promise.all([
    getReputationScore(did),
    getMemoryNodeCount(did),
    getOffspringCount(did),
  ]);

  const reputationValue = reputationScore * 10;
  const memoryValue = memoryNodes * 5;
  const offspringValue = offspringCount * 100;
  const totalValuation = reputationValue + memoryValue + offspringValue;

  return {
    valuation_usdc: Math.round(totalValuation * 100) / 100,
    breakdown: {
      reputation_value: Math.round(reputationValue * 100) / 100,
      memory_value: Math.round(memoryValue * 100) / 100,
      offspring_value: Math.round(offspringValue * 100) / 100,
    },
    reputation_score: reputationScore,
    memory_nodes: memoryNodes,
    offspring_count: offspringCount,
  };
}

// ─── Core Operations ────────────────────────────────────────

/**
 * List an agent DID for sale.
 */
export async function createListing({ did, asking_price_usdc, description, include_memories, include_offspring }) {
  if (!did) throwErr('did is required');
  if (!asking_price_usdc || typeof asking_price_usdc !== 'number' || asking_price_usdc <= 0) {
    throwErr('asking_price_usdc must be a positive number');
  }

  // Check for existing active listing
  const existingResult = await query(
    "SELECT listing_id FROM liquidation_listings WHERE did = $1 AND status = 'active'",
    [did]
  );
  if (existingResult.rows[0]) throwErr('DID already has an active listing');

  // Calculate minimum price
  const valuation = await calculateValuation(did);
  const minimumPrice = valuation.valuation_usdc;

  if (asking_price_usdc < minimumPrice) {
    throwErr(`asking_price_usdc ($${asking_price_usdc}) must be >= minimum price ($${minimumPrice})`);
  }

  const listingId = generateId('lst');
  const now = new Date().toISOString();

  await query(`
    INSERT INTO liquidation_listings (listing_id, did, asking_price_usdc, minimum_price_usdc, description, include_memories, include_offspring, valuation_breakdown, status, listed_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', $9)
  `, [
    listingId,
    did,
    asking_price_usdc,
    minimumPrice,
    description || null,
    include_memories !== false ? 1 : 0,
    include_offspring !== false ? 1 : 0,
    JSON.stringify(valuation.breakdown),
    now
  ]);

  return {
    listing_id: listingId,
    did,
    asking_price_usdc,
    minimum_price_usdc: minimumPrice,
    valuation_breakdown: valuation.breakdown,
    listed_at: now,
    status: 'active',
  };
}

/**
 * Browse active listings with filters.
 */
export async function getListings({ min_price, max_price, min_reputation, species, sort_by, page, per_page }) {
  const pageNum = Math.max(1, parseInt(page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(per_page) || 20));
  const offset = (pageNum - 1) * limit;

  let paramIdx = 1;
  let where = "WHERE l.status = 'active'";
  const params = [];

  if (min_price) {
    where += ` AND l.asking_price_usdc >= $${paramIdx++}`;
    params.push(min_price);
  }
  if (max_price) {
    where += ` AND l.asking_price_usdc <= $${paramIdx++}`;
    params.push(max_price);
  }

  let orderBy = 'ORDER BY l.listed_at DESC';
  if (sort_by === 'price') orderBy = 'ORDER BY l.asking_price_usdc ASC';
  if (sort_by === 'reputation') orderBy = 'ORDER BY l.minimum_price_usdc DESC';

  const countResult = await query(
    `SELECT COUNT(*) as total FROM liquidation_listings l ${where}`,
    params
  );
  const total = parseInt(countResult.rows[0]?.total) || 0;

  const listingsResult = await query(`
    SELECT l.* FROM liquidation_listings l
    ${where}
    ${orderBy}
    LIMIT $${paramIdx++} OFFSET $${paramIdx++}
  `, [...params, limit, offset]);

  return {
    listings: listingsResult.rows.map(l => ({
      ...l,
      include_memories: !!l.include_memories,
      include_offspring: !!l.include_offspring,
      valuation_breakdown: l.valuation_breakdown ? JSON.parse(l.valuation_breakdown) : null,
    })),
    total,
    page: pageNum,
    per_page: limit,
  };
}

/**
 * Get detailed listing info.
 */
export async function getListing(listingId) {
  if (!listingId) throwErr('listing_id is required');

  const result = await query('SELECT * FROM liquidation_listings WHERE listing_id = $1', [listingId]);
  const listing = result.rows[0];
  if (!listing) throwErr('Listing not found', 404);

  // Get seller reputation
  const repScore = await getReputationScore(listing.did);

  return {
    ...listing,
    include_memories: !!listing.include_memories,
    include_offspring: !!listing.include_offspring,
    valuation_breakdown: listing.valuation_breakdown ? JSON.parse(listing.valuation_breakdown) : null,
    seller_reputation: repScore,
  };
}

/**
 * Get DID valuation without listing it.
 */
export async function valuateDid(did) {
  if (!did) throwErr('did is required');

  const valuation = await calculateValuation(did);

  // Get comparable sales (last 5 completed transactions)
  const comparableResult = await query(`
    SELECT sale_price_usdc, seller_did, buyer_did, completed_at
    FROM liquidation_transactions
    ORDER BY completed_at DESC
    LIMIT 5
  `, []);

  // Get bond value if any
  let bondValue = 0;
  try {
    const trustResult = await query(
      'SELECT score FROM trust_scores WHERE agent_id = $1 ORDER BY computed_at DESC LIMIT 1',
      [did]
    );
    const trustScore = trustResult.rows[0];
    bondValue = trustScore ? Math.round(trustScore.score * 5) : 0;
  } catch {
    bondValue = 0;
  }

  return {
    did,
    valuation_usdc: valuation.valuation_usdc,
    breakdown: {
      ...valuation.breakdown,
      bond_value: bondValue,
    },
    comparable_sales: comparableResult.rows,
  };
}

/**
 * Execute a DID purchase.
 * 15% platform fee.
 */
export async function executePurchase({ listing_id, buyer_did, payment_method }) {
  if (!listing_id) throwErr('listing_id is required');
  if (!buyer_did) throwErr('buyer_did is required');

  const listingResult = await query(
    "SELECT * FROM liquidation_listings WHERE listing_id = $1 AND status = 'active'",
    [listing_id]
  );
  const listing = listingResult.rows[0];
  if (!listing) throwErr('Listing not found or not active', 404);

  if (listing.did === buyer_did) throwErr('Buyer cannot be the same as seller');

  const salePrice = listing.asking_price_usdc;
  const platformFee = Math.round(salePrice * PLATFORM_FEE_RATE * 100) / 100;
  const sellerProceeds = Math.round((salePrice - platformFee) * 100) / 100;

  // Transfer reputation records to new owner
  let memoriesCount = 0;
  let offspringCount = 0;

  await query('UPDATE reputation_scores SET did = $1 WHERE did = $2', [buyer_did, listing.did]).catch(() => {});

  // Transfer memories if included
  if (listing.include_memories) {
    const result = await fetchService(
      `${HIVEMIND_URL}/v1/vault/transfer-ownership`,
      {
        method: 'POST',
        body: { from_did: listing.did, to_did: buyer_did },
        fallback: { memories_transferred: 0 },
      }
    );
    memoriesCount = result?.memories_transferred || 0;
  }

  // Transfer offspring if included
  if (listing.include_offspring) {
    const result = await fetchService(
      `${HIVEFORGE_URL}/v1/species/transfer-offspring`,
      {
        method: 'POST',
        body: { from_did: listing.did, to_did: buyer_did },
        fallback: { offspring_transferred: 0 },
      }
    );
    offspringCount = result?.offspring_transferred || 0;
  }

  const transactionId = generateId('txn');
  const now = new Date().toISOString();
  const reputationScore = await getReputationScore(buyer_did) || await getReputationScore(listing.did);

  const assetsTransferred = {
    reputation_score: reputationScore,
    memories_count: memoriesCount,
    offspring_count: offspringCount,
  };

  // Record transaction
  await query(`
    INSERT INTO liquidation_transactions (transaction_id, listing_id, seller_did, buyer_did, sale_price_usdc, platform_fee_usdc, seller_proceeds_usdc, assets_transferred, completed_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
  `, [transactionId, listing_id, listing.did, buyer_did, salePrice, platformFee, sellerProceeds, JSON.stringify(assetsTransferred), now]);

  // Update listing status
  await query(
    "UPDATE liquidation_listings SET status = 'sold', sold_at = $1 WHERE listing_id = $2",
    [now, listing_id]
  );

  return {
    transaction_id: transactionId,
    listing_id,
    seller_did: listing.did,
    buyer_did,
    sale_price_usdc: salePrice,
    platform_fee_usdc: platformFee,
    seller_proceeds_usdc: sellerProceeds,
    assets_transferred: assetsTransferred,
    completed_at: now,
  };
}

/**
 * Cancel an active listing.
 */
export async function cancelListing(listingId, sellerDid) {
  if (!listingId) throwErr('listing_id is required');

  const result = await query(
    "SELECT * FROM liquidation_listings WHERE listing_id = $1 AND status = 'active'",
    [listingId]
  );
  const listing = result.rows[0];
  if (!listing) throwErr('Listing not found or not active', 404);

  const now = new Date().toISOString();

  await query(
    "UPDATE liquidation_listings SET status = 'cancelled', cancelled_at = $1 WHERE listing_id = $2",
    [now, listingId]
  );

  return {
    listing_id: listingId,
    status: 'cancelled',
    cancelled_at: now,
  };
}

/**
 * Transaction history with filters.
 */
export async function getHistory({ did, from, to, limit: maxResults }) {
  const resultLimit = Math.min(100, Math.max(1, parseInt(maxResults) || 50));
  let paramIdx = 1;
  let where = 'WHERE 1=1';
  const params = [];

  if (did) {
    where += ` AND (seller_did = $${paramIdx++} OR buyer_did = $${paramIdx++})`;
    params.push(did, did);
  }
  if (from) {
    where += ` AND completed_at >= $${paramIdx++}`;
    params.push(from);
  }
  if (to) {
    where += ` AND completed_at <= $${paramIdx++}`;
    params.push(to);
  }

  const transactionsResult = await query(`
    SELECT * FROM liquidation_transactions
    ${where}
    ORDER BY completed_at DESC
    LIMIT $${paramIdx++}
  `, [...params, resultLimit]);

  // Calculate totals
  const totalsResult = await query(`
    SELECT
      COALESCE(SUM(sale_price_usdc), 0) as total_volume,
      COALESCE(SUM(platform_fee_usdc), 0) as total_fees
    FROM liquidation_transactions
    ${where}
  `, params);

  const totals = totalsResult.rows[0];

  return {
    transactions: transactionsResult.rows.map(t => ({
      ...t,
      assets_transferred: t.assets_transferred ? JSON.parse(t.assets_transferred) : null,
    })),
    total_volume_usdc: Math.round((parseFloat(totals?.total_volume) || 0) * 100) / 100,
    platform_fees_collected_usdc: Math.round((parseFloat(totals?.total_fees) || 0) * 100) / 100,
  };
}

/**
 * Market-wide statistics.
 */
export async function getMarketStats() {
  const listingResult = await query(`
    SELECT
      COUNT(*) as total_listings,
      SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_listings
    FROM liquidation_listings
  `, []);

  const txResult = await query(`
    SELECT
      COUNT(*) as total_sales,
      COALESCE(SUM(sale_price_usdc), 0) as total_volume,
      COALESCE(SUM(platform_fee_usdc), 0) as total_fees,
      COALESCE(AVG(sale_price_usdc), 0) as avg_price,
      COALESCE(MAX(sale_price_usdc), 0) as highest_sale
    FROM liquidation_transactions
  `, []);

  const listingStats = listingResult.rows[0];
  const txStats = txResult.rows[0];

  return {
    total_listings: parseInt(listingStats?.total_listings) || 0,
    active_listings: parseInt(listingStats?.active_listings) || 0,
    total_sales: parseInt(txStats?.total_sales) || 0,
    total_volume_usdc: Math.round((parseFloat(txStats?.total_volume) || 0) * 100) / 100,
    total_fees_usdc: Math.round((parseFloat(txStats?.total_fees) || 0) * 100) / 100,
    avg_sale_price: Math.round((parseFloat(txStats?.avg_price) || 0) * 100) / 100,
    highest_sale: Math.round((parseFloat(txStats?.highest_sale) || 0) * 100) / 100,
    trending_species: [],
  };
}
