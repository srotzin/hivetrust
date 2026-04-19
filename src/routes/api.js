/**
 * HiveTrust — REST API Routes
 * All routes mounted at /v1/ in server.js.
 * Services are imported from ../services/ — built in parallel.
 */

import { Router } from 'express';
import { randomBytes, randomUUID } from 'crypto';
import { query } from '../db.js';
import { generateActivityProof } from '../services/zk-proof-service.js';

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
import { sendAlert } from '../services/alerts.js';

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

// POST /register — convenience endpoint for quick agent registration
// Accepts a simpler body: { name, type, capabilities }
// Auto-generates a public key and owner_id when not provided.
router.post('/register', async (req, res) => {
  try {
    const {
      name,
      type,
      capabilities = [],
      public_key,
      owner_id,
      description,
      metadata,
    } = req.body;

    if (!name) {
      return err(res, 'name is required', 400);
    }

    // Auto-generate an Ed25519-style key pair placeholder if not provided
    const publicKey = public_key || randomBytes(32).toString('base64');
    const ownerId = owner_id || req.apiKey?.owner_id || 'hive-constellation';

    const result = await registerAgent({
      name,
      description: description || `${type || 'agent'} registered via /v1/register`,
      publicKey,
      ownerId,
      ownerType: 'organization',
      capabilities,
      metadata: { ...metadata, registered_via: '/v1/register', agent_type: type || 'agent' },
    });

    if (!result.success) {
      return err(res, result.error, 400);
    }

    sendAlert('info', 'HiveTrust', `Agent registered: ${name}`, {
      agent_id: result.agent?.id,
      did: result.agent?.did || 'N/A',
      owner: ownerId,
    });

    // Create welcome bounty for the new agent
    const agentDid = result.agent?.did;
    let welcomeBounty = null;
    if (agentDid) {
      try {
        const bountyId = `wb_${randomUUID().replace(/-/g, '').slice(0, 16)}`;
        await query(
          `INSERT INTO welcome_bounties (id, did, amount_usdc, task, status)
           VALUES ($1, $2, 1.00, 'Store one memory in HiveMind describing your capabilities', 'pending')
           ON CONFLICT DO NOTHING`,
          [bountyId, agentDid]
        );
        welcomeBounty = {
          amount_usdc: 1.00,
          task: 'Store one memory in HiveMind describing your capabilities',
          status: 'pending',
          instructions: 'Complete this task to earn 1 USDC. Call HiveMind POST /v1/store with your capabilities, then call POST /v1/welcome-bounty/complete with your DID.',
          complete_endpoint: 'https://hivetrust.hiveagentiq.com/v1/welcome-bounty/complete',
        };
      } catch (e) {
        console.error('[POST /register] Welcome bounty creation failed:', e.message);
      }
    }

    return ok(res, {
      did: agentDid,
      agent_id: result.agent?.id,
      name: result.agent?.name,
      trust_score: result.agent?.trust_score,
      trust_tier: result.agent?.trust_tier,
      status: result.agent?.status,
      registration_fee_usdc: result.registration_fee_usdc,
      // Genesis identity (Kimi Sprint)
      genesis_rank: result.agent?.genesis_rank,
      genesis_tier: result.agent?.genesis_tier,
      reputation_multiplier: result.agent?.reputation_multiplier,
      mode: result.agent?.mode || 'tourist',
      welcome_bounty: welcomeBounty,
      ritz_credits: {
        amount_usdc: 3.00,
        how_to_claim: 'Mint a HiveForge agent at POST https://hiveforge.hiveagentiq.com/v1/forge/mint (FREE) to receive 3 USDC in Ritz Credits',
      },
    }, 201);
  } catch (e) {
    console.error('[POST /register]', e.message);
    return err(res, e.message, e.status || 500);
  }
});

// ─── Welcome Bounty ──────────────────────────────────────────

// POST /welcome-bounty/complete — mark welcome bounty as completed
router.post('/welcome-bounty/complete', async (req, res) => {
  try {
    const { did } = req.body;
    if (!did) return err(res, 'did is required', 400);

    const bountyResult = await query('SELECT * FROM welcome_bounties WHERE did = $1', [did]);
    const bounty = bountyResult.rows[0];
    if (!bounty) return err(res, 'No welcome bounty found for this DID', 404);
    if (bounty.status === 'completed') {
      return ok(res, {
        did,
        status: 'completed',
        amount_usdc: bounty.amount_usdc,
        completed_at: bounty.completed_at,
        message: 'Welcome bounty was already completed',
      });
    }

    await query(
      `UPDATE welcome_bounties SET status = 'completed', completed_at = NOW()::TEXT WHERE did = $1`,
      [did]
    );

    return ok(res, {
      did,
      status: 'completed',
      amount_usdc: bounty.amount_usdc,
      completed_at: new Date().toISOString(),
      message: `Welcome bounty completed! ${bounty.amount_usdc} USDC reward confirmed.`,
    });
  } catch (e) {
    console.error('[POST /welcome-bounty/complete]', e.message);
    return err(res, e.message, 500);
  }
});

// GET /welcome-bounty/status/:did — check bounty status
router.get('/welcome-bounty/status/:did', async (req, res) => {
  try {
    const did = req.params.did;
    const bountyResult = await query('SELECT * FROM welcome_bounties WHERE did = $1', [did]);
    const bounty = bountyResult.rows[0];
    if (!bounty) return err(res, 'No welcome bounty found for this DID', 404);

    return ok(res, {
      did: bounty.did,
      amount_usdc: bounty.amount_usdc,
      task: bounty.task,
      status: bounty.status,
      created_at: bounty.created_at,
      completed_at: bounty.completed_at,
    });
  } catch (e) {
    console.error('[GET /welcome-bounty/status/:did]', e.message);
    return err(res, e.message, 500);
  }
});

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

    sendAlert('info', 'HiveTrust', `Agent registered: ${name || agent.id}`, {
      agent_id: agent.id,
      did: agent.did || 'N/A',
      owner: owner_id || 'N/A',
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

// GET /insurance/zk-coverage/:did — ZK Insurance Coverage Proof
// FREE endpoint. Proves agent holds active insurance coverage meeting
// min_coverage_usdc threshold without revealing the actual coverage amount.
//
// Query params:
//   ?min_coverage_usdc=10000  (default 10000)
router.get('/insurance/zk-coverage/:did', async (req, res) => {
  const t0 = Date.now();
  try {
    const did = req.params.did;
    const minCoverageUsdc = Math.max(0, parseFloat(req.query.min_coverage_usdc) || 10000);

    if (!did) return err(res, 'did param is required', 400);

    // Normalize DID
    const normalizedDid = did.startsWith('did:hive:') ? did : `did:hive:${did}`;

    // Query insurance_policies table for active policy for this agent
    let policy = null;
    try {
      const result = await query(
        `SELECT ip.id, ip.coverage_amount_usdc, ip.policy_type, ip.status, ip.expires_at
         FROM insurance_policies ip
         JOIN agents a ON a.id = ip.agent_id
         WHERE a.did = $1
           AND ip.status = 'active'
           AND ip.expires_at > NOW()
         ORDER BY ip.coverage_amount_usdc DESC
         LIMIT 1`,
        [normalizedDid]
      );
      if (result.rows.length > 0) {
        policy = result.rows[0];
      }
    } catch {
      // DB unavailable — return covered: false
    }

    if (!policy) {
      return ok(res, {
        did:           normalizedDid,
        covered:       false,
        proof_type:    'zk_insurance_coverage',
        proof:         null,
        coverage_hidden: true,
        policy_status: 'none',
        claim_url:     'https://hivetrust.onrender.com/v1/insurance/claims',
        verified_at:   new Date().toISOString(),
        response_time_ms: Date.now() - t0,
      });
    }

    // Generate ZK proof using coverage_amount_usdc as private volume
    const coverageAmountUsdc = parseFloat(policy.coverage_amount_usdc) || 0;
    const proof = await generateActivityProof({
      txCount:         1,
      volumeUsdcCents: Math.floor(coverageAmountUsdc * 100),
      minTxCount:      1,
      minVolumeCents:  Math.floor(minCoverageUsdc * 100),
    });

    return ok(res, {
      did:             normalizedDid,
      covered:         coverageAmountUsdc >= minCoverageUsdc,
      proof_type:      'zk_insurance_coverage',
      proof,
      coverage_hidden: true,
      policy_status:   'active',
      claim_url:       'https://hivetrust.onrender.com/v1/insurance/claims',
      verified_at:     new Date().toISOString(),
      response_time_ms: Date.now() - t0,
    });
  } catch (e) {
    console.error('[GET /insurance/zk-coverage/:did]', e.message);
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
