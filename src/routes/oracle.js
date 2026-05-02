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

    return ok(res, { streams });
  } catch (e) {
    console.error('[GET /oracle/streams]', e.message);
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
