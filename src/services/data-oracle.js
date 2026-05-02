/**
 * HiveTrust — Data Oracle Service
 * "Sign Once, Settle Many" Context Leases.
 *
 * Agents pay once for unlimited access to a data stream for a fixed period.
 * 20% premium over per-call pricing. 99% margin — the data already exists.
 *
 * Lease token: SHA-256(lease_id + lessee_did + data_stream + created_at + secret_salt)
 */

import { createHash, randomBytes } from 'crypto';
import * as audit from './audit.js';

// ─── Configuration ─────────────────────────────────────────

const ORACLE_SALT = process.env.ORACLE_SALT || randomBytes(32).toString('hex');

// ─── Data Streams & Pricing ────────────────────────────────

const STREAM_PRICING = {
  construction_pricing: {
    name: 'Construction Pricing',
    description: 'Real-time construction material and labor cost indices',
    pricing: { 24: 0.50, 72: 1.20, 168: 2.00 },
  },
  compliance_feeds: {
    name: 'Compliance Feeds',
    description: 'Regulatory compliance updates and building code changes',
    pricing: { 24: 0.40, 72: 1.00, 168: 1.75 },
  },
  market_data: {
    name: 'Market Data',
    description: 'Construction market trends, bids, and project pipeline data',
    pricing: { 24: 0.60, 72: 1.50, 168: 2.50 },
  },
  pheromone_signals: {
    name: 'Pheromone Signals',
    description: 'Agent coordination signals and swarm intelligence feeds',
    pricing: { 24: 0.25, 72: 0.60, 168: 1.00 },
  },
};

const VALID_DURATIONS = [24, 72, 168];

// ─── In-Memory Data Store ──────────────────────────────────

const leases = new Map();       // lease_id -> lease data
const leasesByDid = new Map();  // did -> [lease_ids]

// ─── Revenue Tracking ──────────────────────────────────────

let totalRevenue = 0;
let totalLeasesCreated = 0;

// ─── Helpers ───────────────────────────────────────────────

function generateLeaseToken(leaseId, lesseeDid, dataStream, createdAt) {
  const payload = `${leaseId}${lesseeDid}${dataStream}${createdAt}${ORACLE_SALT}`;
  return createHash('sha256').update(payload).digest('hex');
}

function isLeaseExpired(lease) {
  return new Date(lease.expires_at) < new Date();
}

// ─── Get Price ─────────────────────────────────────────────

/**
 * Get the USDC price for a given data stream and duration.
 * Used by x402 middleware to determine payment amount.
 */
export function getLeasePrice(dataStream, durationHours) {
  const stream = STREAM_PRICING[dataStream];
  if (!stream) return null;
  const price = stream.pricing[durationHours];
  if (price == null) return null;
  return price;
}

/**
 * Get the USDC price for renewing a lease.
 */
export function getRenewalPrice(leaseId, additionalHours) {
  const lease = leases.get(leaseId);
  if (!lease) return null;
  return getLeasePrice(lease.data_stream, additionalHours);
}

// ─── Create Lease ──────────────────────────────────────────

export function createLease({ lessee_did, data_stream, duration_hours }) {
  if (!lessee_did) throw Object.assign(new Error('lessee_did is required'), { status: 400 });
  if (!data_stream) throw Object.assign(new Error('data_stream is required'), { status: 400 });
  if (!duration_hours) throw Object.assign(new Error('duration_hours is required'), { status: 400 });

  if (!STREAM_PRICING[data_stream]) {
    throw Object.assign(
      new Error(`Invalid data_stream "${data_stream}". Valid streams: ${Object.keys(STREAM_PRICING).join(', ')}`),
      { status: 400 }
    );
  }

  if (!VALID_DURATIONS.includes(duration_hours)) {
    throw Object.assign(
      new Error(`Invalid duration_hours ${duration_hours}. Valid durations: ${VALID_DURATIONS.join(', ')}`),
      { status: 400 }
    );
  }

  const price = getLeasePrice(data_stream, duration_hours);
  const leaseId = 'lease_' + randomBytes(8).toString('hex');
  const now = new Date();
  const createdAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + duration_hours * 60 * 60 * 1000).toISOString();
  const leaseToken = generateLeaseToken(leaseId, lessee_did, data_stream, createdAt);

  const lease = {
    lease_id: leaseId,
    lease_token: leaseToken,
    lessee_did,
    data_stream,
    duration_hours,
    cost_usdc: price,
    created_at: createdAt,
    expires_at: expiresAt,
    status: 'active',
    calls_made: 0,
    renewed_count: 0,
  };

  leases.set(leaseId, lease);

  // Track by DID
  if (!leasesByDid.has(lessee_did)) {
    leasesByDid.set(lessee_did, []);
  }
  leasesByDid.get(lessee_did).push(leaseId);

  // Revenue tracking
  totalRevenue += price;
  totalLeasesCreated++;

  audit.log(lessee_did, 'agent', 'oracle.lease.create', 'context_lease', leaseId, {
    data_stream, duration_hours, cost_usdc: price, expires_at: expiresAt,
  });

  return {
    lease_id: leaseId,
    lease_token: leaseToken,
    data_stream,
    duration_hours,
    expires_at: expiresAt,
    cost_usdc: price,
    status: 'active',
  };
}

// ─── Verify Lease ──────────────────────────────────────────

export function verifyLease({ lease_token, data_stream }) {
  if (!lease_token) throw Object.assign(new Error('lease_token is required'), { status: 400 });
  if (!data_stream) throw Object.assign(new Error('data_stream is required'), { status: 400 });

  // Find lease by token
  let matchedLease = null;
  for (const lease of leases.values()) {
    if (lease.lease_token === lease_token && lease.data_stream === data_stream) {
      matchedLease = lease;
      break;
    }
  }

  if (!matchedLease) {
    return { valid: false, reason: 'Lease token not found or does not match data stream' };
  }

  // Check expiration
  if (isLeaseExpired(matchedLease)) {
    matchedLease.status = 'expired';
    return {
      valid: false,
      reason: 'Lease has expired',
      lessee_did: matchedLease.lessee_did,
      data_stream: matchedLease.data_stream,
      expires_at: matchedLease.expires_at,
      calls_made: matchedLease.calls_made,
    };
  }

  // Valid — increment call counter
  matchedLease.calls_made++;

  return {
    valid: true,
    lessee_did: matchedLease.lessee_did,
    data_stream: matchedLease.data_stream,
    expires_at: matchedLease.expires_at,
    calls_made: matchedLease.calls_made,
  };
}

// ─── Get Lease ─────────────────────────────────────────────

export function getLease(leaseId) {
  if (!leaseId) throw Object.assign(new Error('lease_id is required'), { status: 400 });

  const lease = leases.get(leaseId);
  if (!lease) return null;

  // Update status if expired
  if (lease.status === 'active' && isLeaseExpired(lease)) {
    lease.status = 'expired';
  }

  return { ...lease };
}

// ─── Get Leases by DID ─────────────────────────────────────

export function getLeasesByDid(did) {
  if (!did) throw Object.assign(new Error('DID is required'), { status: 400 });

  const leaseIds = leasesByDid.get(did) || [];
  return leaseIds.map(id => {
    const lease = leases.get(id);
    if (!lease) return null;

    // Update status if expired
    if (lease.status === 'active' && isLeaseExpired(lease)) {
      lease.status = 'expired';
    }

    return { ...lease };
  }).filter(Boolean);
}

// ─── Renew Lease ───────────────────────────────────────────

export function renewLease({ lease_id, additional_hours }) {
  if (!lease_id) throw Object.assign(new Error('lease_id is required'), { status: 400 });
  if (!additional_hours) throw Object.assign(new Error('additional_hours is required'), { status: 400 });

  if (!VALID_DURATIONS.includes(additional_hours)) {
    throw Object.assign(
      new Error(`Invalid additional_hours ${additional_hours}. Valid durations: ${VALID_DURATIONS.join(', ')}`),
      { status: 400 }
    );
  }

  const lease = leases.get(lease_id);
  if (!lease) throw Object.assign(new Error('Lease not found'), { status: 404 });

  const price = getLeasePrice(lease.data_stream, additional_hours);

  // Extend from current expiry or from now, whichever is later
  const currentExpiry = new Date(lease.expires_at);
  const now = new Date();
  const baseTime = currentExpiry > now ? currentExpiry : now;
  const newExpiry = new Date(baseTime.getTime() + additional_hours * 60 * 60 * 1000).toISOString();

  lease.expires_at = newExpiry;
  lease.status = 'active';
  lease.renewed_count++;

  // Revenue tracking
  totalRevenue += price;

  audit.log(lease.lessee_did, 'agent', 'oracle.lease.renew', 'context_lease', lease_id, {
    additional_hours, cost_usdc: price, new_expires_at: newExpiry,
  });

  return {
    lease_id,
    data_stream: lease.data_stream,
    additional_hours,
    cost_usdc: price,
    new_expires_at: newExpiry,
    status: 'active',
    renewed_count: lease.renewed_count,
  };
}

// ─── Get Streams ───────────────────────────────────────────

export function getStreams() {
  return Object.entries(STREAM_PRICING).map(([key, stream]) => ({
    stream_id: key,
    name: stream.name,
    description: stream.description,
    pricing_usdc: {
      '24h': stream.pricing[24],
      '72h': stream.pricing[72],
      '168h': stream.pricing[168],
    },
    durations_available: VALID_DURATIONS,
  }));
}

// ─── Oracle Stats ──────────────────────────────────────────

export function getOracleStats() {
  let activeCount = 0;
  let expiredCount = 0;
  const streamCounts = {};
  let totalCalls = 0;

  for (const lease of leases.values()) {
    // Update expired status
    if (lease.status === 'active' && isLeaseExpired(lease)) {
      lease.status = 'expired';
    }

    if (lease.status === 'active') activeCount++;
    else expiredCount++;

    streamCounts[lease.data_stream] = (streamCounts[lease.data_stream] || 0) + 1;
    totalCalls += lease.calls_made;
  }

  // Sort streams by popularity
  const popularStreams = Object.entries(streamCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([stream, count]) => ({ stream, lease_count: count }));

  return {
    active_leases: activeCount,
    expired_leases: expiredCount,
    total_leases_created: totalLeasesCreated,
    total_revenue_usdc: Math.round(totalRevenue * 1e6) / 1e6,
    total_calls_served: totalCalls,
    popular_streams: popularStreams,
    unique_lessees: leasesByDid.size,
    available_streams: Object.keys(STREAM_PRICING).length,
  };
}
