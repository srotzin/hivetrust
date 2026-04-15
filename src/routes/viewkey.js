/**
 * HiveTrust — ViewKey Audit Rail Routes
 *
 * Zero-Knowledge proof verification for structural code compliance.
 * Agent-to-agent API only — no human UI.
 *
 * Mounted at /v1/viewkey/ in server.js.
 */

import { Router } from 'express';
import {
  verifyProductCompliance,
  verifyBOM,
  getAuditTrail,
  issueCertificate,
} from '../services/viewkey.js';

const router = Router();

// ─── Helpers ────────────────────────────────────────────────

function ok(res, data, status = 200) {
  return res.status(status).json({ success: true, data });
}

function err(res, message, status = 400) {
  return res.status(status).json({ success: false, error: message });
}

// ─── POST /verify-compliance ────────────────────────────────
// Validate a single Simpson Strong-Tie connector against code requirements.

router.post('/verify-compliance', async (req, res) => {
  try {
    const result = await verifyProductCompliance(req.body);
    return ok(res, result);
  } catch (e) {
    return err(res, e.message, e.status || 500);
  }
});

// ─── POST /verify-bom ──────────────────────────────────────
// Validate an entire Bill of Materials against catalog and code.

router.post('/verify-bom', async (req, res) => {
  try {
    const result = await verifyBOM(req.body);
    return ok(res, result);
  } catch (e) {
    return err(res, e.message, e.status || 500);
  }
});

// ─── GET /audit-trail/:project_id ──────────────────────────
// Retrieve all compliance proofs issued for a project.

router.get('/audit-trail/:project_id', async (req, res) => {
  try {
    const proofs = await getAuditTrail(req.params.project_id);
    return ok(res, { project_id: req.params.project_id, proof_count: proofs.length, proofs });
  } catch (e) {
    return err(res, e.message, e.status || 500);
  }
});

// ─── POST /issue-certificate ───────────────────────────────
// Issue a signed compliance certificate for a project.

router.post('/issue-certificate', async (req, res) => {
  try {
    const result = await issueCertificate(req.body);
    return ok(res, result, 201);
  } catch (e) {
    return err(res, e.message, e.status || 500);
  }
});

export default router;
