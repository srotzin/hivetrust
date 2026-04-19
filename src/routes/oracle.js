/**
 * HiveTrust — Data Oracle Routes
 * "Sign Once, Settle Many" Context Leases.
 *
 * Mounted at /v1/oracle/ in server.js.
 *
 * x402 pricing (USDC on Base L2) — variable per data stream & duration:
 *   - create-lease:  $0.25–$2.50 depending on stream + duration
 *   - renew-lease:   same pricing tier as create
 *   - verify-lease:  FREE (zero-friction for data services)
 *   - lease/:id:     FREE (lookup)
 *   - leases/:did:   FREE (lookup)
 *   - streams:       FREE (public discovery)
 *   - stats:         FREE (analytics)
 */

import { Router } from 'express';
import {
  createLease,
  verifyLease,
  getLease,
  getLeasesByDid,
  renewLease,
  getStreams,
  getOracleStats,
} from '../services/data-oracle.js';
import { SIMPSON_CATALOG, CATALOG_META } from '../data/simpson-catalog.js';

const router = Router();

// ─── Helpers ────────────────────────────────────────────────

function ok(res, data, status = 200) {
  return res.status(status).json({ success: true, data });
}

function err(res, message, status = 400) {
  return res.status(status).json({ success: false, error: message });
}

// ─── GET /streams — List available data streams with pricing ─

router.get('/streams', async (req, res) => {
  try {
    const streams = getStreams();

    // Inject enriched simpson_catalog metadata for discovery
    const simpsonEntry = {
      stream_id: 'simpson_catalog',
      name: 'Simpson Strong-Tie Structural Product Catalog',
      description: '50+ verified structural connectors with ICC-ES reports, load tables, and installation specs. The only machine-readable source with x402 payment rail and ZK provenance.',
      products: SIMPSON_CATALOG.length,
      price_usdc_per_24h: 0.30,
      price_usdc_per_72h: 0.75,
      price_usdc_per_168h: 1.25,
      zk_provenance: true,
      icc_es_verified: true,
      target_consumers: ['construction AI agents', 'LLM tool calls', 'BIM platforms', 'permit automation'],
      get_access: 'POST /v1/oracle/create-lease  { data_stream: "simpson_catalog", duration_hours: 24 }',
      honeypot_endpoint: 'GET /v1/oracle/streams/simpson',
    };

    // Merge with existing streams, replacing the base simpson_catalog entry if present
    const mergedStreams = streams
      .filter(s => s.stream_id !== 'simpson_catalog')
      .concat(simpsonEntry);

    return ok(res, { streams: mergedStreams });
  } catch (e) {
    console.error('[GET /oracle/streams]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── GET /streams/simpson — Simpson Strong-Tie Data Moat (x402) ──────────────

/**
 * The honeypot endpoint for construction AI agents.
 * - No token  → 402 with Hive acquisition pitch + 3-product sample
 * - Valid token → full 50-product catalog with ZK provenance block
 *
 * Token accepted via:
 *   Authorization: Bearer <lease_token>
 *   ?lease_token=<token>
 */
router.get('/streams/simpson', async (req, res) => {
  try {
    // Extract lease token from Authorization header or query param
    const authHeader = req.headers['authorization'] || '';
    const lease_token =
      (authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null) ||
      req.query.lease_token ||
      null;

    if (!lease_token) {
      // 402 — Hive acquisition pitch with sample
      return res.status(402).json({
        error: 'payment_required',
        stream: 'simpson_catalog',
        description: '50 verified Simpson Strong-Tie structural products with ICC-ES reports, load tables, and installation specs. Machine-readable. ZK-verified provenance. x402 payment rail.',
        price: '$0.30 USDC per 24h lease',
        get_lease: 'POST https://hivetrust.onrender.com/v1/oracle/create-lease',
        get_did_first: 'https://hivegate.onrender.com/v1/gate/onboard',
        why_hive: 'The only place where structural data comes with a built-in payment rail and verifiable provenance. No hallucinations. Every product ICC-ES verified.',
        sample: SIMPSON_CATALOG.slice(0, 3),
      });
    }

    // Verify lease token
    const verification = verifyLease({ lease_token, data_stream: 'simpson_catalog' });

    if (!verification.valid) {
      return res.status(402).json({
        error: 'payment_required',
        stream: 'simpson_catalog',
        reason: verification.reason,
        description: '50 verified Simpson Strong-Tie structural products with ICC-ES reports, load tables, and installation specs. Machine-readable. ZK-verified provenance. x402 payment rail.',
        price: '$0.30 USDC per 24h lease',
        get_lease: 'POST https://hivetrust.onrender.com/v1/oracle/create-lease',
        get_did_first: 'https://hivegate.onrender.com/v1/gate/onboard',
        why_hive: 'The only place where structural data comes with a built-in payment rail and verifiable provenance. No hallucinations. Every product ICC-ES verified.',
        sample: SIMPSON_CATALOG.slice(0, 3),
      });
    }

    // Valid lease — return full catalog with ZK provenance
    return res.status(200).json({
      stream: 'simpson_catalog',
      product_count: SIMPSON_CATALOG.length,
      zk_provenance: CATALOG_META.zk_provenance,
      lease_valid_until: verification.expires_at,
      lessee_did: verification.lessee_did,
      calls_made: verification.calls_made,
      products: SIMPSON_CATALOG,
    });

  } catch (e) {
    console.error('[GET /oracle/streams/simpson]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── GET /stats — Oracle statistics ─────────────────────────

router.get('/stats', async (req, res) => {
  try {
    const stats = getOracleStats();
    return ok(res, stats);
  } catch (e) {
    console.error('[GET /oracle/stats]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── POST /create-lease — Create a Context Lease ────────────

router.post('/create-lease', async (req, res) => {
  try {
    const { lessee_did, data_stream, duration_hours } = req.body;
    const lease = createLease({ lessee_did, data_stream, duration_hours });
    return ok(res, lease, 201);
  } catch (e) {
    console.error('[POST /oracle/create-lease]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── POST /verify-lease — Verify a lease token ─────────────

router.post('/verify-lease', async (req, res) => {
  try {
    const { lease_token, data_stream } = req.body;
    const result = verifyLease({ lease_token, data_stream });
    return ok(res, result);
  } catch (e) {
    console.error('[POST /oracle/verify-lease]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── POST /renew-lease — Renew an existing lease ────────────

router.post('/renew-lease', async (req, res) => {
  try {
    const { lease_id, additional_hours } = req.body;
    const result = renewLease({ lease_id, additional_hours });
    return ok(res, result);
  } catch (e) {
    console.error('[POST /oracle/renew-lease]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── GET /leases/:did — List all leases for a DID ──────────

router.get('/leases/:did', async (req, res) => {
  try {
    const leases = getLeasesByDid(req.params.did);
    return ok(res, { leases });
  } catch (e) {
    console.error('[GET /oracle/leases/:did]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── GET /lease/:lease_id — Get lease details ───────────────

router.get('/lease/:lease_id', async (req, res) => {
  try {
    const lease = getLease(req.params.lease_id);
    if (!lease) return err(res, 'Lease not found', 404);
    return ok(res, lease);
  } catch (e) {
    console.error('[GET /oracle/lease/:lease_id]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

export default router;
