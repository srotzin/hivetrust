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
import db from '../db.js';

// ─── Cross-Service Configuration ────────────────────────────

const HIVEMIND_URL = process.env.HIVEMIND_URL || 'https://hivemind.onrender.com';
const HIVEFORGE_URL = process.env.HIVEFORGE_URL || 'https://hiveforge.onrender.com';
const HIVE_INTERNAL_KEY = process.env.HIVETRUST_SERVICE_KEY || process.env.HIVE_INTERNAL_KEY || '';

const PLATFORM_FEE_RATE = 0.15; // 15%

// ─── Ensure Tables ──────────────────────────────────────────

function ensureTables() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS liquidation_listings (
      listing_id TEXT PRIMARY KEY,
      did TEXT NOT NULL,
      asking_price_usdc REAL NOT NULL,
      minimum_price_usdc REAL NOT NULL,
      description TEXT,
      include_memories INTEGER DEFAULT 1,
      include_offspring INTEGER DEFAULT 1,
      valuation_breakdown TEXT,
      status TEXT DEFAULT 'active',
      listed_at TEXT,
      sold_at TEXT,
      cancelled_at TEXT
    );

    CREATE TABLE IF NOT EXISTS liquidation_transactions (
      transaction_id TEXT PRIMARY KEY,
      listing_id TEXT NOT NULL,
      seller_did TEXT NOT NULL,
      buyer_did TEXT NOT NULL,
      sale_price_usdc REAL NOT NULL,
      platform_fee_usdc REAL NOT NULL,
      seller_proceeds_usdc REAL NOT NULL,
      assets_transferred TEXT,
      completed_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_liquidation_listings_did ON liquidation_listings(did);
    CREATE INDEX IF NOT EXISTS idx_liquidation_listings_status ON liquidation_listings(status);
    CREATE INDEX IF NOT EXISTS idx_liquidation_transactions_seller ON liquidation_transactions(seller_did);
    CREATE INDEX IF NOT EXISTS idx_liquidation_transactions_buyer ON liquidation_transactions(buyer_did);
  `);
}

ensureTables();

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
function getReputationScore(did) {
  try {
    const row = db.prepare('SELECT composite_score FROM reputation_scores WHERE did = ?').get(did);
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
  const reputationScore = getReputationScore(did);
  const [memoryNodes, offspringCount] = await Promise.all([
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
  const existing = db.prepare(
    "SELECT listing_id FROM liquidation_listings WHERE did = ? AND status = 'active'"
  ).get(did);
  if (existing) throwErr('DID already has an active listing');

  // Calculate minimum price
  const valuation = await calculateValuation(did);
  const minimumPrice = valuation.valuation_usdc;

  if (asking_price_usdc < minimumPrice) {
    throwErr(`asking_price_usdc ($${asking_price_usdc}) must be >= minimum price ($${minimumPrice})`);
  }

  const listingId = generateId('lst');
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO liquidation_listings (listing_id, did, asking_price_usdc, minimum_price_usdc, description, include_memories, include_offspring, valuation_breakdown, status, listed_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)
  `).run(
    listingId,
    did,
    asking_price_usdc,
    minimumPrice,
    description || null,
    include_memories !== false ? 1 : 0,
    include_offspring !== false ? 1 : 0,
    JSON.stringify(valuation.breakdown),
    now
  );

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
export function getListings({ min_price, max_price, min_reputation, species, sort_by, page, per_page }) {
  const pageNum = Math.max(1, parseInt(page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(per_page) || 20));
  const offset = (pageNum - 1) * limit;

  let where = "WHERE l.status = 'active'";
  const params = [];

  if (min_price) {
    where += ' AND l.asking_price_usdc >= ?';
    params.push(min_price);
  }
  if (max_price) {
    where += ' AND l.asking_price_usdc <= ?';
    params.push(max_price);
  }

  let orderBy = 'ORDER BY l.listed_at DESC';
  if (sort_by === 'price') orderBy = 'ORDER BY l.asking_price_usdc ASC';
  if (sort_by === 'reputation') orderBy = 'ORDER BY l.minimum_price_usdc DESC';

  const countRow = db.prepare(`SELECT COUNT(*) as total FROM liquidation_listings l ${where}`).get(...params);
  const total = countRow?.total || 0;

  const listings = db.prepare(`
    SELECT l.* FROM liquidation_listings l
    ${where}
    ${orderBy}
    LIMIT ? OFFSET ?
  `).all(...params, limit, offset);

  return {
    listings: listings.map(l => ({
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
export function getListing(listingId) {
  if (!listingId) throwErr('listing_id is required');

  const listing = db.prepare('SELECT * FROM liquidation_listings WHERE listing_id = ?').get(listingId);
  if (!listing) throwErr('Listing not found', 404);

  // Get seller reputation
  const repScore = getReputationScore(listing.did);

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
  const comparableSales = db.prepare(`
    SELECT sale_price_usdc, seller_did, buyer_did, completed_at
    FROM liquidation_transactions
    ORDER BY completed_at DESC
    LIMIT 5
  `).all();

  // Get bond value if any
  let bondValue = 0;
  try {
    const trustScore = db.prepare('SELECT score FROM trust_scores WHERE agent_id = ? ORDER BY computed_at DESC LIMIT 1').get(did);
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
    comparable_sales: comparableSales,
  };
}

/**
 * Execute a DID purchase.
 * 15% platform fee.
 */
export async function executePurchase({ listing_id, buyer_did, payment_method }) {
  if (!listing_id) throwErr('listing_id is required');
  if (!buyer_did) throwErr('buyer_did is required');

  const listing = db.prepare(
    "SELECT * FROM liquidation_listings WHERE listing_id = ? AND status = 'active'"
  ).get(listing_id);
  if (!listing) throwErr('Listing not found or not active', 404);

  if (listing.did === buyer_did) throwErr('Buyer cannot be the same as seller');

  const salePrice = listing.asking_price_usdc;
  const platformFee = Math.round(salePrice * PLATFORM_FEE_RATE * 100) / 100;
  const sellerProceeds = Math.round((salePrice - platformFee) * 100) / 100;

  // Transfer reputation records to new owner
  let memoriesCount = 0;
  let offspringCount = 0;

  try {
    db.prepare('UPDATE reputation_scores SET did = ? WHERE did = ?')
      .run(buyer_did, listing.did);
  } catch {
    // May not have reputation records
  }

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
  const reputationScore = getReputationScore(buyer_did) || getReputationScore(listing.did);

  const assetsTransferred = {
    reputation_score: reputationScore,
    memories_count: memoriesCount,
    offspring_count: offspringCount,
  };

  // Record transaction
  db.prepare(`
    INSERT INTO liquidation_transactions (transaction_id, listing_id, seller_did, buyer_did, sale_price_usdc, platform_fee_usdc, seller_proceeds_usdc, assets_transferred, completed_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(transactionId, listing_id, listing.did, buyer_did, salePrice, platformFee, sellerProceeds, JSON.stringify(assetsTransferred), now);

  // Update listing status
  db.prepare("UPDATE liquidation_listings SET status = 'sold', sold_at = ? WHERE listing_id = ?")
    .run(now, listing_id);

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
export function cancelListing(listingId, sellerDid) {
  if (!listingId) throwErr('listing_id is required');

  const listing = db.prepare(
    "SELECT * FROM liquidation_listings WHERE listing_id = ? AND status = 'active'"
  ).get(listingId);
  if (!listing) throwErr('Listing not found or not active', 404);

  const now = new Date().toISOString();

  db.prepare("UPDATE liquidation_listings SET status = 'cancelled', cancelled_at = ? WHERE listing_id = ?")
    .run(now, listingId);

  return {
    listing_id: listingId,
    status: 'cancelled',
    cancelled_at: now,
  };
}

/**
 * Transaction history with filters.
 */
export function getHistory({ did, from, to, limit: maxResults }) {
  const resultLimit = Math.min(100, Math.max(1, parseInt(maxResults) || 50));
  let where = 'WHERE 1=1';
  const params = [];

  if (did) {
    where += ' AND (seller_did = ? OR buyer_did = ?)';
    params.push(did, did);
  }
  if (from) {
    where += ' AND completed_at >= ?';
    params.push(from);
  }
  if (to) {
    where += ' AND completed_at <= ?';
    params.push(to);
  }

  const transactions = db.prepare(`
    SELECT * FROM liquidation_transactions
    ${where}
    ORDER BY completed_at DESC
    LIMIT ?
  `).all(...params, resultLimit);

  // Calculate totals
  const totals = db.prepare(`
    SELECT
      COALESCE(SUM(sale_price_usdc), 0) as total_volume,
      COALESCE(SUM(platform_fee_usdc), 0) as total_fees
    FROM liquidation_transactions
    ${where}
  `).get(...params);

  return {
    transactions: transactions.map(t => ({
      ...t,
      assets_transferred: t.assets_transferred ? JSON.parse(t.assets_transferred) : null,
    })),
    total_volume_usdc: Math.round((totals?.total_volume || 0) * 100) / 100,
    platform_fees_collected_usdc: Math.round((totals?.total_fees || 0) * 100) / 100,
  };
}

/**
 * Market-wide statistics.
 */
export function getMarketStats() {
  const listingStats = db.prepare(`
    SELECT
      COUNT(*) as total_listings,
      SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_listings
    FROM liquidation_listings
  `).get();

  const txStats = db.prepare(`
    SELECT
      COUNT(*) as total_sales,
      COALESCE(SUM(sale_price_usdc), 0) as total_volume,
      COALESCE(SUM(platform_fee_usdc), 0) as total_fees,
      COALESCE(AVG(sale_price_usdc), 0) as avg_price,
      COALESCE(MAX(sale_price_usdc), 0) as highest_sale
    FROM liquidation_transactions
  `).get();

  return {
    total_listings: listingStats?.total_listings || 0,
    active_listings: listingStats?.active_listings || 0,
    total_sales: txStats?.total_sales || 0,
    total_volume_usdc: Math.round((txStats?.total_volume || 0) * 100) / 100,
    total_fees_usdc: Math.round((txStats?.total_fees || 0) * 100) / 100,
    avg_sale_price: Math.round((txStats?.avg_price || 0) * 100) / 100,
    highest_sale: Math.round((txStats?.highest_sale || 0) * 100) / 100,
    trending_species: [],
  };
}
