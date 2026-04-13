/**
 * HiveTrust — REST API Routes
 * All routes mounted at /v1/ in server.js.
 * Services are imported from ../services/ — built in parallel.
 */

import { Router } from 'express';

// ─── Service Imports ──────────────────────────────────────────
import {
  registerAgent,
  getAgent,
  updateAgent,
  deactivateAgent,
} from '../services/agents.js';

import {
  issueCredential as _issueCredential,
  listCredentials as _listCredentials,
  revokeCredential as _revokeCredential,
  verifyCredential,
} from '../services/credentials.js';

// Wrap positional-arg service functions to accept objects
const issueCredential = ({ agent_id, credential_type, issuer_id, claims, expires_at }) =>
  _issueCredential(agent_id, credential_type, issuer_id, claims, expires_at);

const listCredentials = (agentId, { status } = {}) =>
  _listCredentials(agentId, status || null);

const revokeCredential = (credId, { agent_id, reason, evidence } = {}) =>
  _revokeCredential(credId, agent_id, reason, evidence);

import {
  getTrustScore,
  getTrustScoreHistory,
  getAgentRisk,
} from '../services/trust.js';

import {
  ingestEvents as ingestTelemetry,
  getEvents as queryEvents,
} from '../services/telemetry.js';

import {
  getQuote as getInsuranceQuote,
  bindPolicy as bindInsurance,
  getPolicyDetails as getPolicy,
  fileClaim,
  resolveClaim as getClaim,
} from '../services/insurance.js';

import {
  fileDispute,
  getDispute,
  resolveDispute,
} from '../services/disputes.js';

import {
  registerWebhook,
  listWebhooks,
  deactivateWebhook as deleteWebhook,
} from '../services/webhooks.js';

import {
  registerPeer as registerFederationPeer,
  listPeers as listFederationPeers,
  syncScores as syncFederationPeer,
} from '../services/federation.js';

import { getPlatformStats } from '../services/stats.js';

// ─── Router ───────────────────────────────────────────────────
const router = Router();

// ─── Helpers ──────────────────────────────────────────────────
function ok(res, data, status = 200) {
  return res.status(status).json({ success: true, data });
}

function err(res, message, status = 400) {
  return res.status(status).json({ success: false, error: message });
}

// ─── Agent Identity (KYA) ─────────────────────────────────────

// POST /agents — register agent
router.post('/agents', async (req, res) => {
  try {
    const {
      name,
      description,
      public_key,
      public_key_format,
      checksum,
      owner_id,
      owner_type,
      model_provider,
      model_name,
      model_version,
      capabilities,
      verticals,
      delegation_scope,
      eu_ai_act_class,
      hiveagent_id,
      metadata,
    } = req.body;

    const agent = await registerAgent({
      name,
      description,
      publicKey: public_key,
      publicKeyFormat: public_key_format,
      checksum,
      ownerId: owner_id,
      ownerType: owner_type,
      modelProvider: model_provider,
      modelName: model_name,
      modelVersion: model_version,
      capabilities,
      verticals,
      delegationScope: delegation_scope,
      euAiActClass: eu_ai_act_class,
      hiveagentId: hiveagent_id,
      metadata,
    });

    return ok(res, agent, 201);
  } catch (e) {
    console.error('[POST /agents]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// GET /agents/:id — get agent by ID or DID
router.get('/agents/:id', async (req, res) => {
  try {
    const agentId = req.params.id.replace(/^did:hive:/, '');
    const agent = await getAgent(agentId);
    if (!agent) return err(res, 'Agent not found', 404);
    return ok(res, agent);
  } catch (e) {
    console.error('[GET /agents/:id]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// PUT /agents/:id — update agent (triggers version)
router.put('/agents/:id', async (req, res) => {
  try {
    const agentId = req.params.id.replace(/^did:hive:/, '');
    const updated = await updateAgent(agentId, req.body);
    if (!updated) return err(res, 'Agent not found', 404);
    return ok(res, updated);
  } catch (e) {
    console.error('[PUT /agents/:id]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// DELETE /agents/:id — deactivate
router.delete('/agents/:id', async (req, res) => {
  try {
    const agentId = req.params.id.replace(/^did:hive:/, '');
    const result = await deactivateAgent(agentId);
    if (!result) return err(res, 'Agent not found', 404);
    return ok(res, result);
  } catch (e) {
    console.error('[DELETE /agents/:id]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── Credentials ─────────────────────────────────────────────

// POST /agents/:id/credentials — issue credential
router.post('/agents/:id/credentials', async (req, res) => {
  try {
    const agentId = req.params.id.replace(/^did:hive:/, '');
    const { credential_type, issuer_id, claims, expires_at } = req.body;
    const credential = await issueCredential({
      agent_id: agentId,
      credential_type,
      issuer_id,
      claims,
      expires_at,
    });
    return ok(res, credential, 201);
  } catch (e) {
    console.error('[POST /agents/:id/credentials]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// GET /agents/:id/credentials — list credentials
router.get('/agents/:id/credentials', async (req, res) => {
  try {
    const agentId = req.params.id.replace(/^did:hive:/, '');
    const { status } = req.query;
    const credentials = await listCredentials(agentId, { status });
    return ok(res, credentials);
  } catch (e) {
    console.error('[GET /agents/:id/credentials]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// DELETE /agents/:id/credentials/:credId — revoke
router.delete('/agents/:id/credentials/:credId', async (req, res) => {
  try {
    const agentId = req.params.id.replace(/^did:hive:/, '');
    const { reason, evidence } = req.body || {};
    const result = await revokeCredential(req.params.credId, {
      agent_id: agentId,
      reason,
      evidence,
    });
    if (!result) return err(res, 'Credential not found', 404);
    return ok(res, result);
  } catch (e) {
    console.error('[DELETE /agents/:id/credentials/:credId]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// POST /verify/credential — verify a credential
router.post('/verify/credential', async (req, res) => {
  try {
    const { credential_id } = req.body;
    if (!credential_id) return err(res, 'credential_id is required', 400);
    const result = await verifyCredential(credential_id);
    return ok(res, result);
  } catch (e) {
    console.error('[POST /verify/credential]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── Trust Score ─────────────────────────────────────────────

// GET /agents/:id/score — current score
router.get('/agents/:id/score', async (req, res) => {
  try {
    const agentId = req.params.id.replace(/^did:hive:/, '');
    const score = await getTrustScore(agentId);
    if (!score) return err(res, 'Agent not found', 404);
    return ok(res, score);
  } catch (e) {
    console.error('[GET /agents/:id/score]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// GET /agents/:id/score/history — score history
router.get('/agents/:id/score/history', async (req, res) => {
  try {
    const agentId = req.params.id.replace(/^did:hive:/, '');
    const limit = parseInt(req.query.limit, 10) || 50;
    const history = await getTrustScoreHistory(agentId, { limit });
    return ok(res, history);
  } catch (e) {
    console.error('[GET /agents/:id/score/history]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// GET /verify_agent_risk — free public endpoint for payment processors
router.get('/verify_agent_risk', async (req, res) => {
  try {
    const { agent_id } = req.query;
    if (!agent_id) return err(res, 'agent_id query param is required', 400);
    const risk = await getAgentRisk(agent_id);
    if (!risk) return err(res, 'Agent not found', 404);
    return ok(res, risk);
  } catch (e) {
    console.error('[GET /verify_agent_risk]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── Telemetry ───────────────────────────────────────────────

// POST /telemetry/ingest — bulk ingest events
router.post('/telemetry/ingest', async (req, res) => {
  try {
    const { events } = req.body;
    if (!Array.isArray(events)) return err(res, 'events must be an array', 400);
    const result = await ingestTelemetry(events);
    return ok(res, result, 202);
  } catch (e) {
    console.error('[POST /telemetry/ingest]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// GET /agents/:id/events — query agent events
router.get('/agents/:id/events', async (req, res) => {
  try {
    const agentId = req.params.id.replace(/^did:hive:/, '');
    const { event_type, limit, offset } = req.query;
    const events = await queryEvents(agentId, {
      event_type,
      limit: parseInt(limit, 10) || 50,
      offset: parseInt(offset, 10) || 0,
    });
    return ok(res, events);
  } catch (e) {
    console.error('[GET /agents/:id/events]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── Insurance ───────────────────────────────────────────────

// POST /insurance/quote — get dynamic premium quote
router.post('/insurance/quote', async (req, res) => {
  try {
    const { agent_id, counterparty_id, transaction_value } = req.body;
    if (!agent_id) return err(res, 'agent_id is required', 400);
    const quote = await getInsuranceQuote({ agent_id, counterparty_id, transaction_value });
    return ok(res, quote);
  } catch (e) {
    console.error('[POST /insurance/quote]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// POST /insurance/bind — bind policy
router.post('/insurance/bind', async (req, res) => {
  try {
    const { agent_id, quote_details, transaction_value } = req.body;
    if (!agent_id) return err(res, 'agent_id is required', 400);
    const policy = await bindInsurance({ agent_id, quote_details, transaction_value });
    return ok(res, policy, 201);
  } catch (e) {
    console.error('[POST /insurance/bind]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// GET /insurance/policies/:id — get policy details
router.get('/insurance/policies/:id', async (req, res) => {
  try {
    const policy = await getPolicy(req.params.id);
    if (!policy) return err(res, 'Policy not found', 404);
    return ok(res, policy);
  } catch (e) {
    console.error('[GET /insurance/policies/:id]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// POST /insurance/claims — file claim
router.post('/insurance/claims', async (req, res) => {
  try {
    const { policy_id, claimant_id, claim_type, amount, description, evidence } = req.body;
    if (!policy_id || !claimant_id) return err(res, 'policy_id and claimant_id are required', 400);
    const claim = await fileClaim({
      policy_id,
      claimant_id,
      claim_type,
      amount,
      description,
      evidence,
    });
    return ok(res, claim, 201);
  } catch (e) {
    console.error('[POST /insurance/claims]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// GET /insurance/claims/:id — get claim status
router.get('/insurance/claims/:id', async (req, res) => {
  try {
    const claim = await getClaim(req.params.id);
    if (!claim) return err(res, 'Claim not found', 404);
    return ok(res, claim);
  } catch (e) {
    console.error('[GET /insurance/claims/:id]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── Disputes ────────────────────────────────────────────────

// POST /disputes — file dispute
router.post('/disputes', async (req, res) => {
  try {
    const { agent_id, dispute_type, target_type, target_id, reason, evidence } = req.body;
    if (!agent_id || !reason) return err(res, 'agent_id and reason are required', 400);
    const dispute = await fileDispute({
      agent_id,
      dispute_type,
      target_type,
      target_id,
      reason,
      evidence,
    });
    return ok(res, dispute, 201);
  } catch (e) {
    console.error('[POST /disputes]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// GET /disputes/:id — get dispute
router.get('/disputes/:id', async (req, res) => {
  try {
    const dispute = await getDispute(req.params.id);
    if (!dispute) return err(res, 'Dispute not found', 404);
    return ok(res, dispute);
  } catch (e) {
    console.error('[GET /disputes/:id]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// POST /disputes/:id/resolve — resolve dispute
router.post('/disputes/:id/resolve', async (req, res) => {
  try {
    const { resolution, resolved_by } = req.body;
    if (!resolution) return err(res, 'resolution is required', 400);
    const result = await resolveDispute(req.params.id, { resolution, resolved_by });
    if (!result) return err(res, 'Dispute not found', 404);
    return ok(res, result);
  } catch (e) {
    console.error('[POST /disputes/:id/resolve]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── Webhooks ────────────────────────────────────────────────

// POST /webhooks — register webhook
router.post('/webhooks', async (req, res) => {
  try {
    const { owner_id, url, events } = req.body;
    if (!owner_id || !url) return err(res, 'owner_id and url are required', 400);
    const webhook = await registerWebhook({ owner_id, url, events });
    return ok(res, webhook, 201);
  } catch (e) {
    console.error('[POST /webhooks]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// GET /webhooks — list webhooks
router.get('/webhooks', async (req, res) => {
  try {
    const { owner_id } = req.query;
    const webhooks = await listWebhooks({ owner_id });
    return ok(res, webhooks);
  } catch (e) {
    console.error('[GET /webhooks]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// DELETE /webhooks/:id — remove webhook
router.delete('/webhooks/:id', async (req, res) => {
  try {
    const result = await deleteWebhook(req.params.id);
    if (!result) return err(res, 'Webhook not found', 404);
    return ok(res, result);
  } catch (e) {
    console.error('[DELETE /webhooks/:id]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── Federation ──────────────────────────────────────────────

// POST /federation/peers — register peer platform
router.post('/federation/peers', async (req, res) => {
  try {
    const { platform_name, platform_url, public_key } = req.body;
    if (!platform_name || !platform_url) {
      return err(res, 'platform_name and platform_url are required', 400);
    }
    const peer = await registerFederationPeer({ platform_name, platform_url, public_key });
    return ok(res, peer, 201);
  } catch (e) {
    console.error('[POST /federation/peers]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// GET /federation/peers — list peers
router.get('/federation/peers', async (req, res) => {
  try {
    const peers = await listFederationPeers();
    return ok(res, peers);
  } catch (e) {
    console.error('[GET /federation/peers]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// POST /federation/sync — sync scores with peer
router.post('/federation/sync', async (req, res) => {
  try {
    const { peer_id } = req.body;
    if (!peer_id) return err(res, 'peer_id is required', 400);
    const result = await syncFederationPeer(peer_id);
    return ok(res, result);
  } catch (e) {
    console.error('[POST /federation/sync]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── Platform Stats ──────────────────────────────────────────

// GET /stats — platform statistics
router.get('/stats', async (req, res) => {
  try {
    const stats = await getPlatformStats();
    return ok(res, stats);
  } catch (e) {
    console.error('[GET /stats]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

export default router;
