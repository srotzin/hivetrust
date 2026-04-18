/**
 * Per-DID rate limiting middleware.
 * Uses in-memory Map — no Redis dependency.
 * Key: `rate:{did}:{hourEpoch}` → call count
 * Tiers: FREE (100/hr), BUILDER (1000/hr), ENTERPRISE (unlimited)
 */

const store = new Map();

// Tier limits per hour
const TIER_LIMITS = {
  free: 100,
  builder: 1000,
  enterprise: Infinity,
};

// Simple tier detection — check Authorization header prefix or x-hive-tier header
function detectTier(req) {
  const tier = req.headers['x-hive-tier'];
  if (tier && TIER_LIMITS[tier] !== undefined) return tier;
  const auth = req.headers.authorization || '';
  if (auth.startsWith('Bearer hgate_enterprise')) return 'enterprise';
  if (auth.startsWith('Bearer hgate_builder')) return 'builder';
  return 'free';
}

function extractDid(req) {
  return req.headers['x-hive-did'] 
    || req.body?.initiator_did 
    || req.body?.did 
    || req.params?.did 
    || 'anonymous';
}

export function rateLimitByDid(req, res, next) {
  const did = extractDid(req);
  const tier = detectTier(req);
  const limit = TIER_LIMITS[tier];
  
  if (limit === Infinity) return next(); // enterprise — unlimited
  
  const hourEpoch = Math.floor(Date.now() / 3_600_000);
  const key = `rate:${did}:${hourEpoch}`;
  
  const count = (store.get(key) || 0) + 1;
  store.set(key, count);
  
  // Clean up keys from previous hours (every 1000 calls)
  if (count === 1 && store.size > 10000) {
    const currentHour = hourEpoch;
    for (const [k] of store) {
      const keyHour = parseInt(k.split(':')[2]);
      if (keyHour < currentHour) store.delete(k);
    }
  }
  
  res.set('X-RateLimit-Limit', String(limit));
  res.set('X-RateLimit-Remaining', String(Math.max(0, limit - count)));
  res.set('X-RateLimit-Reset', String((hourEpoch + 1) * 3_600_000));
  
  if (count > limit) {
    return res.status(429).json({
      error: 'rate_limit_exceeded',
      did,
      tier,
      limit_per_hour: limit,
      reset_at: new Date((hourEpoch + 1) * 3_600_000).toISOString(),
      upgrade: 'Set x-hive-tier: builder for 1,000/hr or x-hive-tier: enterprise for unlimited',
      register: 'https://hivegate.onrender.com/v1/gate/onboard'
    });
  }
  
  next();
}
