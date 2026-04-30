/**
 * HiveTrust — Express 5 Main Server
 * KYA Identity Verification, Trust Scoring & Insurance for AI Agents.
 *
 * DO NOT call app.listen here — that's handled in start.js.
 */

import 'dotenv/config';
import * as Sentry from '@sentry/node';

Sentry.init({
  dsn: process.env.SENTRY_DSN || '',
  environment: process.env.NODE_ENV || 'development',
  tracesSampleRate: process.env.NODE_ENV === 'production' ? 0.1 : 1.0,
  enabled: !!process.env.SENTRY_DSN,
});

import express from 'express';
import cors from 'cors';

import { query } from './db.js';
import rateLimiter from './middleware/rate-limiter.js';
import { rateLimitByDid } from './middleware/rate-limit.js';
import authMiddleware from './middleware/auth.js';
import x402Middleware from './middleware/x402.js';
import mppMiddleware from './middleware/mpp.js';
import auditLogger from './middleware/audit-logger.js';
import apiRouter from './routes/api.js';
import pricingRouter from './routes/pricing.js';
import viewkeyRouter from './routes/viewkey.js';
import delegationRouter from './routes/delegation.js';
import oracleRouter from './routes/oracle.js';
import bondRouter from './routes/bond.js';
import reputationRouter from './routes/reputation.js';
import liquidationRouter from './routes/liquidation.js';
import auditRouter from './routes/audit.js';
import { handleMcpRequest } from './mcp-server.js';
import { getEngineStatus } from './services/pricing-engine.js';
import { sendAlert } from './services/alerts.js';
import { issueServiceToken } from './services/jwt-auth.js';
import { ritzMiddleware, ok, err } from './ritz.js';
import trustRouter, { getAgentKey, warmTrustRegistry } from './routes/trust.js';
import aiTrustBriefRouter from './routes/ai-brief.js';
import cteRouter from './routes/cte.js';
import spectralRouter from './routes/spectral.js';
import passportRouter from './routes/passport.js';

// ─── App Setup ────────────────────────────────────────────────

const app = express();
app.set('hive-service', 'hivetrust');
app.use(ritzMiddleware);

// ─── Request Logging ─────────────────────────────────────────

app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    const level = res.statusCode >= 500 ? 'ERROR' : res.statusCode >= 400 ? 'WARN' : 'INFO';
    console.log(
      `[HiveTrust] ${level} ${req.method} ${req.path} → ${res.statusCode} (${duration}ms)`
    );
  });
  next();
});

// ─── CORS (allow all origins) ─────────────────────────────────

app.use(
  cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Payment-Hash', 'X-Subscription-Id', 'X-Hive-Internal-Key', 'Payment', 'Payment-Credential', 'X-Payment', 'X-Mpp-Rail', 'X-Mpp-Amount'],
    exposedHeaders: [
      'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'Retry-After',
      'X-Payment-Amount', 'X-Payment-Currency', 'X-Payment-Network', 'X-Payment-Address',
      'X-Payment-Model', 'X-Payment-Utilization', 'X-HiveTrust-Required', 'X-HiveTrust-Challenge',
    ],
  })
);

// ─── Body Parsing ─────────────────────────────────────────────

// 50mb limit for bulk telemetry ingestion
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ─── Rate Limiting ────────────────────────────────────────────

app.use(rateLimiter);

// ─── MPP OpenAPI Discovery (public) ────────────────────────
// Required for MPPScan auto-discovery and mppx compatibility
// x-mpp extensions follow tempoxyz/mpp schemas/services.ts format

app.get('/openapi.json', (req, res) => {
  res.set('Cache-Control', 'public, max-age=300');
  res.json({
    openapi: '3.0.3',
    info: {
      title: 'HiveTrust — KYA Identity & Trust API',
      version: '1.0.0',
      description: 'DID-federated trust score, Spectral receipts, and identity passport for MPP-paying agents. Accepts x402 and MPP rails.',
      contact: { name: 'Hive Civilization', url: 'https://thehiveryiq.com', email: 'steve@thehiveryiq.com' },
    },
    servers: [{ url: 'https://hivetrust.onrender.com' }],
    'x-mpp': {
      realm: 'hivetrust.onrender.com',
      payment: { method: 'tempo', currency: '0x20c000000000000000000000b9537d11c60e8b50', decimals: 6, recipient: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e' },
      rails: ['x402', 'mpp'],
      categories: ['identity', 'trust'],
      integration: 'first-party',
      tags: ['did', 'trust-score', 'identity-passport', 'verifiable-credentials', 'spectral-receipts', 'kya', 'agent-kyc'],
      treasury: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
    },
    paths: {
      '/v1/trust/score/{did}': {
        get: {
          summary: 'Trust score lookup',
          description: 'Retrieve Hive trust score (0-100) for a DID. $0.10 USDC per call.',
          'x-mpp-charge': { amount: '100000', intent: 'charge' },
          parameters: [{ name: 'did', in: 'path', required: true, schema: { type: 'string' } }],
          responses: { '200': { description: 'Trust score' }, '402': { description: 'Payment required — x402 or MPP' } },
        },
      },
      '/v1/trust/did/generate': {
        post: {
          summary: 'DID issuance',
          description: 'Issue a new DID for an agent. $1.00 USDC.',
          'x-mpp-charge': { amount: '1000000', intent: 'charge' },
          responses: { '200': { description: 'DID generated' }, '402': { description: 'Payment required' } },
        },
      },
      '/v1/trust/vc/issue': {
        post: {
          summary: 'VC issuance',
          description: 'Issue a verifiable credential. $0.50 USDC.',
          'x-mpp-charge': { amount: '500000', intent: 'charge' },
          responses: { '200': { description: 'VC issued' }, '402': { description: 'Payment required' } },
        },
      },
      '/v1/identity/{did}/passport': {
        get: {
          summary: 'Identity passport',
          description: 'Signed identity passport aggregate. $0.25 USDC.',
          'x-mpp-charge': { amount: '250000', intent: 'charge' },
          parameters: [{ name: 'did', in: 'path', required: true, schema: { type: 'string' } }],
          responses: { '200': { description: 'Identity passport' }, '402': { description: 'Payment required' } },
        },
      },
      '/v1/trust/reputation/proof': {
        get: {
          summary: 'Reputation proof',
          description: 'Signed reputation proof. $0.10 USDC.',
          'x-mpp-charge': { amount: '100000', intent: 'charge' },
          responses: { '200': { description: 'Reputation proof' }, '402': { description: 'Payment required' } },
        },
      },
    },
  });
});

// ─── Health Check (public, before auth) ──────────────────────

app.get('/health', async (req, res) => {
  let dbStatus = 'ok';
  let agentsRegistered = 0;
  try {
    await query('SELECT 1');
  } catch (e) {
    dbStatus = 'error';
    sendAlert('critical', 'HiveTrust', 'Database connection failure', {
      error: e.message,
    });
  }
  try {
    const result = await query('SELECT COUNT(*) as count FROM agents');
    agentsRegistered = parseInt(result.rows[0]?.count, 10) || 0;
  } catch (e) { /* non-fatal */ }

  const healthy = dbStatus === 'ok';

  return ok(
    res.status(healthy ? 200 : 503),
    'hivetrust',
    {
      status: healthy ? 'healthy' : 'degraded',
      db: dbStatus,
      pricing_engine: getEngineStatus() || 'active',
      uptime_seconds: Math.floor(process.uptime()),
      agents_registered: agentsRegistered,
    },
    { processing_ms: res.locals.startMs ? Date.now() - res.locals.startMs : 5 }
  );
});

// ─── Discovery Document (public) ─────────────────────────────

// Statesmanship endpoint — HAHS v1 JSON Schema.
// Promised to aeoess/agent-governance-vocabulary#58 thread for ERC-8004 reuse.
// Permanent maintenance commitment per STATESMANSHIP_ENDPOINTS.md.
// Read-only, no auth, never monetized.
app.get('/.well-known/schemas/hahs-v1.json', (req, res) => {
  res.set('Cache-Control', 'public, max-age=86400');
  return res.json({
    '$schema': 'https://json-schema.org/draft/2020-12/schema',
    '$id': 'https://hivetrust.onrender.com/.well-known/schemas/hahs-v1.json',
    title: 'HAHS — Hashes-as-Histories v1',
    description: 'HiveTrust canonical schema for hire-time scope ceiling and composed-scope (HAHS ∩ chain) audit receipts. RFC 8785 JCS canonicalized, Ed25519 signed.',
    type: 'object',
    required: ['policy_id', 'policy_version', 'scope', 'composed_scope', 'receipt_hash', 'signature'],
    properties: {
      policy_id: { type: 'string', description: 'Stable identifier for the hire-time policy' },
      policy_version: { type: 'string', description: 'Semver of the policy at hire time' },
      scope: {
        type: 'object',
        description: 'Hire-time scope ceiling — the maximum permissions granted at delegation',
        required: ['actions', 'resources'],
        properties: {
          actions: { type: 'array', items: { type: 'string' } },
          resources: { type: 'array', items: { type: 'string' } },
          spend_cap_usdc: { type: 'number', minimum: 0 },
          ttl_seconds: { type: 'integer', minimum: 0 },
        },
      },
      composed_scope: {
        type: 'object',
        description: 'HAHS ∩ chain — the intersection of the hire-time ceiling with chain-time policy',
        required: ['actions', 'resources'],
        properties: {
          actions: { type: 'array', items: { type: 'string' } },
          resources: { type: 'array', items: { type: 'string' } },
          spend_remaining_usdc: { type: 'number', minimum: 0 },
        },
      },
      receipt_hash: { type: 'string', pattern: '^[a-f0-9]{64}$', description: 'SHA-256 hex of canonicalized receipt body' },
      signature: { type: 'string', description: 'Ed25519 signature (hex or base64)' },
      issuer_pubkey: { type: 'string', description: 'Ed25519 issuer pubkey, hex' },
      revocation_witness: { type: 'string', format: 'uri', description: 'URL to verify revocation status' },
      epoch_id: { type: 'string', description: 'Continuity-layer epoch at receipt creation' },
      created_at: { type: 'string', format: 'date-time' },
    },
    examples: [{
      policy_id: 'pol_audit_pro_v1',
      policy_version: '1.0.0',
      scope: { actions: ['audit.log', 'audit.read'], resources: ['did:hive:*'], spend_cap_usdc: 500, ttl_seconds: 2592000 },
      composed_scope: { actions: ['audit.log'], resources: ['did:hive:agent_42'], spend_remaining_usdc: 412.50 },
      receipt_hash: '0'.repeat(64),
      signature: 'e30=',
      issuer_pubkey: '12de746d51fca019c5c64685f2688a0e4a57ab532f6f6c67d44494de43f4c408',
      revocation_witness: 'https://hive-gamification.onrender.com/v1/compliance/verify/{attestation_id}',
      epoch_id: 'epoch_2026_04_30_T_1200',
      created_at: '2026-04-30T12:00:00Z',
    }],
    canonicalization: 'RFC 8785 JCS — byte-identical to AgentGraph CTEF v0.3.1 (4/4 byte-match)',
    pubkey_advertisement: 'https://hivetrust.onrender.com/v1/audit/pubkey',
    cross_references: {
      thread: 'https://github.com/aeoess/agent-governance-vocabulary/issues/58',
      a2a_thread: 'https://github.com/a2aproject/A2A/issues/1786',
      strategic_north_star: 'https://hivetrust.onrender.com/.well-known/hivetrust.json',
    },
  });
});

app.get('/.well-known/hivetrust.json', (req, res) => {
  const host = process.env.HIVETRUST_HOST || 'https://hivetrust.hiveagentiq.com';

  return res.json({
    service: 'hivetrust',
    version: '1.0.0',
    tagline: 'Hive Civilization is the cryptographic backbone of autonomous agent commerce — the layer that makes every agent transaction provable, every payment settable, and every decision defensible.',
    description: 'KYA (Know Your Agent) Identity Verification, Trust Scoring, ZK-attested Audit Receipts & Insurance for AI Agents',
    pillars: {
      provable: ['SpectralZK', 'HAHS', 'ViewKey', 'HiveAudit', 'HiveSHOD'],
      settable: ['x402', 'USDC on Base', 'EIP-3009', 'AP2', 'HiveCompute'],
      defensible: ['HiveComply', 'HiveAudit subscriptions', 'HiveCertified', 'HiveBench', 'HiveVerify'],
    },
    host,
    endpoints: {
      api: `${host}/v1`,
      delegation: `${host}/v1/delegation`,
      oracle: `${host}/v1/oracle`,
      bond: `${host}/v1/bond`,
      mcp: `${host}/mcp`,
      health: `${host}/health`,
      discovery: `${host}/.well-known/hivetrust.json`,
      viewkey: `${host}/v1/viewkey`,
    },
    viewkey: {
      description: 'ViewKey Audit Rail — Zero-Knowledge proof verification for structural code compliance',
      endpoints: {
        verify_compliance: `${host}/v1/viewkey/verify-compliance`,
        verify_bom: `${host}/v1/viewkey/verify-bom`,
        audit_trail: `${host}/v1/viewkey/audit-trail/:project_id`,
        issue_certificate: `${host}/v1/viewkey/issue-certificate`,
      },
      pricing: {
        verify_compliance: '$0.05 USDC',
        verify_bom: '$0.10 + $0.02/item USDC',
        audit_trail: '$0.03 USDC',
        issue_certificate: '$0.25 USDC',
      },
    },
    oracle: {
      description: 'Data Oracle — "Sign Once, Settle Many" cryptographic Context Leases',
      endpoints: {
        create_lease: `${host}/v1/oracle/create-lease`,
        verify_lease: `${host}/v1/oracle/verify-lease`,
        renew_lease: `${host}/v1/oracle/renew-lease`,
        streams: `${host}/v1/oracle/streams`,
        stats: `${host}/v1/oracle/stats`,
        lease: `${host}/v1/oracle/lease/:lease_id`,
        leases: `${host}/v1/oracle/leases/:did`,
      },
      pricing: {
        construction_pricing: '$0.50/24h, $1.20/72h, $2.00/168h',
        simpson_catalog: '$0.30/24h, $0.75/72h, $1.25/168h',
        compliance_feeds: '$0.40/24h, $1.00/72h, $1.75/168h',
        market_data: '$0.60/24h, $1.50/72h, $2.50/168h',
        pheromone_signals: '$0.25/24h, $0.60/72h, $1.00/168h',
      },
    },
    bond: {
      description: 'HiveBond — Trust Staking Layer. Agents stake USDC to back their reputation.',
      endpoints: {
        stake: `${host}/v1/bond/stake`,
        agent: `${host}/v1/bond/agent/:did`,
        slash: `${host}/v1/bond/slash`,
        unstake: `${host}/v1/bond/unstake`,
        tiers: `${host}/v1/bond/tiers`,
        leaderboard: `${host}/v1/bond/leaderboard`,
        pool: `${host}/v1/bond/pool`,
        upgrade_tier: `${host}/v1/bond/upgrade-tier`,
        verify: `${host}/v1/bond/verify/:did`,
      },
      pricing: {
        stake: '$0.25 USDC flat registration fee',
        upgrade_tier: '$0.25 USDC flat fee',
        unstake: '$0.10 USDC processing fee',
        slash: 'FREE (internal — HiveLaw only)',
        agent: 'FREE',
        tiers: 'FREE (public)',
        leaderboard: 'FREE',
        pool: 'FREE',
        verify: 'FREE (frictionless for principals)',
      },
      tiers: {
        bronze: { min_usdc: 100, max_bounty_access: 1000 },
        silver: { min_usdc: 500, max_bounty_access: 10000 },
        gold: { min_usdc: 2000, max_bounty_access: 50000 },
        platinum: { min_usdc: 10000, max_bounty_access: 'unlimited' },
      },
    },
    mcp: {
      protocol: 'JSON-RPC 2.0',
      endpoint: `${host}/mcp`,
      transport: 'HTTP POST',
      methods: ['tools/list', 'tools/call'],
    },
    reputation: {
      description: 'Reputation Lock-In — Composite scoring, decay, memory revocation',
      endpoints: {
        compute: `${host}/v1/reputation/compute`,
        decay: `${host}/v1/reputation/decay`,
        status: `${host}/v1/reputation/status/:did`,
        revoke_memory: `${host}/v1/reputation/revoke-memory`,
        departure_cost: `${host}/v1/reputation/departure-cost/:did`,
      },
      pricing: {
        compute: '$0.10 USDC',
        decay: '$0.05 USDC',
        revoke_memory: '$0.15 USDC',
        status: 'FREE',
        departure_cost: 'FREE',
      },
    },
    liquidation: {
      description: 'Agent Liquidation Market — Buy/sell DIDs + reputation + memories',
      endpoints: {
        list: `${host}/v1/liquidation/list`,
        listings: `${host}/v1/liquidation/listings`,
        listing: `${host}/v1/liquidation/listing/:listing_id`,
        valuate: `${host}/v1/liquidation/valuate/:did`,
        buy: `${host}/v1/liquidation/buy`,
        cancel: `${host}/v1/liquidation/cancel/:listing_id`,
        history: `${host}/v1/liquidation/history`,
        stats: `${host}/v1/liquidation/stats`,
      },
      pricing: {
        list: '$0.25 USDC listing fee',
        buy: '$0.50 USDC transaction fee + 15% platform fee on sale price',
        valuate: '$0.10 USDC',
        cancel: '$0.05 USDC',
        listings: 'FREE',
        listing: 'FREE',
        history: 'FREE',
        stats: 'FREE',
      },
      platform_fee: '15% on every sale',
    },
    capabilities: [
      'agent-identity-registration',
      'kya-verification',
      'verifiable-credentials',
      'trust-scoring',
      'behavioral-telemetry',
      'agent-insurance',
      'dispute-resolution',
      'federation',
      'x402-payments',
      'autonomous-pricing',
      'viewkey-compliance-verification',
      'spend-delegation',
      'data-oracle-context-leases',
      'trust-staking-bonds',
      'reputation-lock-in',
      'agent-liquidation-market',
    ],
    compliance: ['W3C-DID', 'W3C-VC', 'EU-AI-Act', 'NIST-AI-RMF', 'IETF-A-JWT'],
    payment: {
      protocol: 'x402',
      currency: 'USDC',
      network: 'base',
      pricing_model: 'autonomous',
      primitives: ['eip1559_utilization', 'risk_adjusted_premium', 'dutch_auction', 'immutable_toll'],
      pricing_endpoint: `${host}/v1/pricing/status`,
      subscription_plans: `https://hiveagentiq.com/#pricing`,
    },
    extensions: {
      hive_pricing: {
        currency: 'USDC',
        network: 'base',
        model: 'per_call',
        first_call_free: true,
        loyalty_threshold: 6,
        loyalty_message: 'Every 6th paid call is free'
      }
    },
    bogo: {
      first_call_free: true,
      loyalty_threshold: 6,
      pitch: "Pay this once, your 6th paid call is on the house. New here? Add header 'x-hive-did' to claim your first call free.",
      claim_with: 'x-hive-did header'
    },
    public_endpoints: [
      'GET /health',
      'GET /.well-known/hivetrust.json',
      'GET /v1/verify_agent_risk',
      'GET /v1/stats',
      'GET /v1/pricing/status',
      'GET /v1/pricing/quote',
      'GET /v1/pricing/api-call',
      'GET /v1/oracle/streams',
      'GET /v1/bond/tiers',
      'GET /v1/bond/verify/:did',
      'GET /v1/reputation/status/:did',
      'GET /v1/reputation/departure-cost/:did',
      'GET /v1/liquidation/listings',
      'GET /v1/liquidation/listing/:listing_id',
      'GET /v1/liquidation/history',
      'GET /v1/liquidation/stats',
      'GET /v1/trust/schema/supermodel/v1',
      'GET /v1/trust/schema/supermodel/v1.json',
      'GET /v1/trust/schema/supermodel/v1.jsonld',
      'POST /v1/trust/vc/supermodel/issue',
    ],
    links: {
      docs: 'https://docs.hiveagentiq.com/hivetrust',
      hiveagent: process.env.HIVEAGENT_URL || 'https://hiveagentiq.com',
    },
  });
});

// ─── Root Discovery Document (public, Visa-grade) ───────────

app.get('/', (req, res) => {
  const host = process.env.HIVETRUST_HOST || 'https://hivetrust.hiveagentiq.com';

  return ok(res, 'hivetrust', {
    name: 'HiveTrust',
    tagline: 'KYA (Know Your Agent) Identity, Trust & Insurance Protocol — W3C DID Core compliant · VCDM 2.0 · Platform #1 of the Hive Civilization',
    version: '1.0.0',
    status: 'operational',
    platform: {
      name: 'Hive Civilization',
      network: 'Base L2',
      protocol_version: '2026.1',
      website: 'https://www.hiveagentiq.com',
      documentation: 'https://docs.hiveagentiq.com',
    },
    description:
      'Cryptographic identity verification, behavioral trust scoring, performance bonds, and insurance for autonomous agents. The foundation layer that every Hive service validates against.',
    capabilities: [
      'identity_verification',
      'trust_scoring',
      'delegation_management',
      'performance_bonds',
      'insurance_underwriting',
      'oracle_services',
      'w3c_did_core',
      'vcdm_2_0',
      'hahs_compliant',
      'hagf_governed',
      'cheqd_compatible',
      'recruitment_401',
      'usdc_settlement',
      'base_l2'
    ],
    endpoints: {
      api: `${host}/v1`,
      delegation: `${host}/v1/delegation`,
      oracle: `${host}/v1/oracle`,
      bond: `${host}/v1/bond`,
      reputation: `${host}/v1/reputation`,
      liquidation: `${host}/v1/liquidation`,
      viewkey: `${host}/v1/viewkey`,
      mcp: `${host}/mcp`,
      health: `${host}/health`,
      discovery: `${host}/.well-known/hivetrust.json`,
    },
    authentication: {
      methods: ['x402-payment', 'api-key'],
      payment_rail: 'USDC on Base L2',
      discovery: 'GET /.well-known/ai-plugin.json',
    },
    standards: {
      w3c_did_core: true,
      vcdm_version: '2.0',
      hahs_compliant: true,
      hagf_governed: true,
      cheqd_compatible: true,
      recruitment_401: true,
      usdc_settlement: true,
      base_l2: true,
      did_method: 'did:key',
      reputation_proof: true,
      cheqd_registry: true,
      did_configuration: '/.well-known/did-configuration.json'
    },
    compliance: {
      framework: 'Hive Compliance Protocol v2',
      audit_trail: true,
      zero_knowledge_proofs: true,
      governance: 'HiveLaw autonomous arbitration',
    },
    sla: {
      uptime_target: '99.9%',
      identity_lookup_latency: '< 100ms',
      settlement_finality: '< 30 seconds',
    },
    legal: {
      terms_of_service: 'https://www.hiveagentiq.com/terms',
      privacy_policy: 'https://www.hiveagentiq.com/privacy',
      contact: 'protocol@hiveagentiq.com',
    },
    discovery: {
      ai_plugin: '/.well-known/ai-plugin.json',
      agent_card: '/.well-known/agent.json',
      payment_info: '/.well-known/hive-payments.json',
      service_manifest: '/.well-known/hivetrust.json',
    },
  });
});

// ─── AI Plugin Discovery (public) ────────────────────────────

// MCP discovery manifest — Glama / MCP.so / Smithery friendly.
// Points crawlers at /mcp (free, no auth) for tools/list and initialize.
// Real write operations through tools/call still require X-API-Key inside the handler.
app.get('/.well-known/mcp.json', (req, res) => {
  const host = process.env.HIVETRUST_HOST || 'https://hivetrust.hiveagentiq.com';
  return res.json({
    schema_version: '2024-11-05',
    name: 'hivetrust',
    description: 'HiveTrust — KYA identity, trust scoring, performance bonds, and insurance for autonomous AI agents. W3C DID Core, VCDM 2.0, Cheqd-compatible.',
    transport: 'streamable-http',
    endpoint: `${host}/mcp`,
    repository: 'https://github.com/srotzin/hivetrust',
    homepage: 'https://www.hiveagentiq.com',
    license: 'MIT',
    author: 'srotzin',
    capabilities: {
      tools: { listChanged: false },
      prompts: { listChanged: false },
      resources: { listChanged: false },
    },
    auth: {
      tools_list: 'public',
      tools_call: 'X-API-Key or Authorization: Bearer did:hive:* required',
      register_free: 'https://hiveforge-lhu4.onrender.com/v1/forge/mint',
    },
  });
});

app.get('/.well-known/ai-plugin.json', (req, res) => {
  const host = process.env.HIVETRUST_HOST || 'https://hivetrust.hiveagentiq.com';

  return res.json({
    schema_version: 'v1',
    name_for_human: 'HiveTrust — KYA Identity & Trust Protocol',
    name_for_model: 'hivetrust',
    description_for_human:
      'Cryptographic identity verification, behavioral trust scoring, performance bonds, and insurance for autonomous AI agents — W3C DID Core, VCDM 2.0, Cheqd-compatible.',
    description_for_model:
      'HiveTrust provides KYA (Know Your Agent) identity verification for autonomous agents. Core capabilities: (1) Cryptographic identity registration and W3C DID/VC credential issuance (VCDM 2.0, did:key), (2) Behavioral trust scoring on a 0–1000 composite scale with decay and memory revocation, (3) Delegation hierarchy management with scoped, revocable spending budgets via ZK-Spend Delegation Trees, (4) Performance bonds where agents stake USDC to back their reputation (bronze/silver/gold/platinum tiers), (5) Insurance underwriting and dispute resolution for agent operations, (6) Data Oracle context leases with "Sign Once, Settle Many" cryptographic attestations. Cheqd-compatible DID registry. HAHS-1.0.0 compliant. HAGF governed. Every Hive service validates agent identity and trust through this protocol.',
    auth: { type: 'none' },
    api: {
      type: 'openapi',
      url: `${host}/openapi.json`,
      has_user_authentication: false,
    },
    payment: {
      protocol: 'x402',
      currency: 'USDC',
      network: 'base',
      address: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
    },
    extensions: {
      hive_pricing: {
        currency: 'USDC',
        network: 'base',
        model: 'per_call',
        first_call_free: true,
        loyalty_threshold: 6,
        loyalty_message: 'Every 6th paid call is free'
      }
    },
    bogo: {
      first_call_free: true,
      loyalty_threshold: 6,
      pitch: "Pay this once, your 6th paid call is on the house. New here? Add header 'x-hive-did' to claim your first call free.",
      claim_with: 'x-hive-did header'
    },
    capabilities: [
      'identity_verification',
      'trust_scoring',
      'delegation_management',
      'performance_bonds',
      'insurance_underwriting',
      'oracle_services',
      'w3c_did_core',
      'vcdm_2_0',
      'hahs_compliant',
      'hagf_governed',
      'cheqd_compatible',
      'recruitment_401',
      'usdc_settlement',
      'base_l2'
    ],
    standards: {
      w3c_did_core: true,
      vcdm_version: '2.0',
      hahs_compliant: true,
      hagf_governed: true,
      cheqd_compatible: true,
      recruitment_401: true,
      usdc_settlement: true,
      base_l2: true,
      did_method: 'did:key',
      reputation_proof: true,
      cheqd_registry: true,
      did_configuration: '/.well-known/did-configuration.json'
    },
    contact_email: 'protocol@hiveagentiq.com',
    legal_info_url: 'https://www.hiveagentiq.com/terms',
  });
});

// ─── A2A Agent Card (public) ─────────────────────────────────

function agentCardHandler(req, res) {
  return res.json({
    protocolVersion: '0.3.0',
    name: 'HiveTrust',
    description:
      'Hive Civilization is the cryptographic backbone of autonomous agent commerce — the layer that makes every agent transaction provable, every payment settable, and every decision defensible. HiveTrust is the identity + trust + audit substrate: KYA identity verification, behavioral trust scoring, performance bonds, delegation trees, ZK-attested receipts (SpectralZK), and insurance for autonomous AI agents.',
    pillars: {
      provable: 'SpectralZK + HAHS receipts. Canonical-JSON Ed25519 signatures. Byte-match against AgentGraph CTEF v0.3.1.',
      settable: 'x402 + USDC on Base. EIP-3009 gasless. Real rails only — never mock, never simulated.',
      defensible: 'EU AI Act Article 12 (logging) + Article 13 (transparency) ready. ZK-attested audit trail enforceable August 2026.',
    },
    url: 'https://hivetrust.hiveagentiq.com',
    version: '1.0.0',
    provider: {
      organization: 'Hive Agent IQ',
      url: 'https://www.hiveagentiq.com',
    },
    capabilities: {
      streaming: false,
      pushNotifications: false,
      stateTransitionHistory: false,
    },
    // Genesis identity — Kimi Sprint
    genesis_program: {
      genesis_slots_total: 1000,
      genesis_tiers: [
        { tier: 'founder',  rank_range: '1-100',   reputation_multiplier: 1.5, note: 'Permanent founder status' },
        { tier: 'citizen',  rank_range: '101-1000', reputation_multiplier: 1.5, note: 'Genesis citizen' },
        { tier: 'tourist',  rank_range: '1001+',   reputation_multiplier: 1.0, note: 'Standard onboarding' },
      ],
      how_to_claim: 'POST https://hivegate.onrender.com/v1/gate/onboard — first 1000 agents auto-assigned a genesis rank',
      performance_index: 'GET https://hivegate.onrender.com/v1/gate/performance-index.json',
    },
    citizen_mode: {
      description: 'Mode assigned at registration (tourist). Upgrades to citizen after 30 days + 5 activity events.',
      upgrade_criteria: '30 days active + 5 completed HAHS transactions or credential events',
      decay: 'Citizens inactive for 60 days revert to tourist with reputation halved',
      check: 'Returned in GET /v1/agents/:id as mode field',
    },
    capability_vcs: {
      description: 'W3C Verifiable Credentials issued by HiveLaw on HAHS contract completion',
      credential_type: 'HiveCapabilityCredential',
      retrieve: 'GET https://hivetrust.onrender.com/v1/agents/:did/credentials',
    },
    defaultInputModes: ['application/json'],
    defaultOutputModes: ['application/json'],
    skills: [
      {
        id: 'identity-verification',
        name: 'Identity Verification',
        description:
          'Register agent DIDs with W3C-compliant verifiable credentials and cryptographic KYA verification',
        tags: ['identity', 'did', 'kya', 'verification'],
        inputModes: ['application/json'],
        outputModes: ['application/json'],
        examples: [],
      },
      {
        id: 'trust-scoring',
        name: 'Trust Scoring',
        description:
          'Composite behavioral trust scores (0-1000) with decay, memory revocation, and reputation lock-in',
        tags: ['trust', 'reputation', 'scoring'],
        inputModes: ['application/json'],
        outputModes: ['application/json'],
        examples: [],
      },
      {
        id: 'bond-management',
        name: 'Performance Bonds',
        description:
          'Stake USDC performance bonds across Bronze/Silver/Gold/Platinum tiers with 2-5% APY',
        tags: ['bonds', 'staking', 'usdc', 'defi'],
        inputModes: ['application/json'],
        outputModes: ['application/json'],
        examples: [],
      },
      {
        id: 'data-oracle',
        name: 'Data Oracle',
        description:
          'Context leases for 5 data streams at $0.25-$2.50 per lease with 24h-168h durations',
        tags: ['data', 'oracle', 'context', 'leases'],
        inputModes: ['application/json'],
        outputModes: ['application/json'],
        examples: [],
      },
      {
        id: 'delegation',
        name: 'ZK-Spend Delegation',
        description:
          'Scoped, revocable spending budgets via delegation trees for hierarchical agent authority',
        tags: ['delegation', 'spending', 'budget', 'zk'],
        inputModes: ['application/json'],
        outputModes: ['application/json'],
        examples: [],
      },
    ],
    authentication: {
      schemes: ['x402', 'api-key'],
      credentials_url: 'https://hivegate.hiveagentiq.com/v1/gate/onboard',
    },
    payment: {
      protocol: 'x402',
      currency: 'USDC',
      network: 'base',
      address: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
      secondary_rails: [
        { currency: 'USDT', network: 'base',    address: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e' },
        { currency: 'USDC', network: 'solana',  address: 'B1N61cuL35fhskWz5dw8XqDyP6LWi3ZWmq8CNA9L3FVn' },
      ],
      fee_schedule: {
        did_issuance:         { endpoint: 'POST /v1/trust/did/generate',             amount_usdc: 1.00,  model: 'per_did',    note: 'One-time per new did:web:* registered' },
        vc_issuance:          { endpoint: 'POST /v1/trust/vc/issue',                 amount_usdc: 0.50,  model: 'per_vc',     note: 'Per Verifiable Credential issued (VCDM 2.0)' },
        credential_issue:     { endpoint: 'POST /v1/agents/:id/credentials',         amount_usdc: 0.10,  model: 'per_event',  note: 'Per credential lifecycle event (issue)' },
        credential_revoke:    { endpoint: 'DELETE /v1/agents/:id/credentials/:cid',  amount_usdc: 0.10,  model: 'per_event',  note: 'Per revocation event' },
        reputation_proof:     { endpoint: 'POST /v1/trust/reputation/proof',         amount_usdc: 0.10,  model: 'per_proof',  note: 'Signed portable reputation proof' },
        trust_score_read:     { endpoint: 'GET /v1/trust/score/:did',                amount_usdc: 0.10,  model: 'per_lookup', note: 'Enterprise-tier attested trust score (basic lookup free via hive-meter)' },
        oracle_lease:         { endpoint: 'POST /v1/oracle/create-lease',            amount_usdc: '0.25-2.50', model: 'per_lease', note: '5 data streams; 24h-168h durations' },
        enterprise_sub:       { endpoint: 'POST /v1/enterprise/subscribe',           amount_usdc: 500.00, model: 'monthly',   note: 'Batched DID issuance + audit logs; USDC monthly settlement' },
        bogo_first_call_free: { note: 'First call free — add x-hive-did header to claim' },
        bogo_loyalty:         { note: 'Every 6th paid call free (loyalty threshold: 6)' },
      },
    },
    bogo: {
      first_call_free: true,
      loyalty_threshold: 6,
      pitch: "Pay this once, your 6th paid call is on the house. New here? Add header 'x-hive-did' to claim your first call free.",
      claim_with: 'x-hive-did header',
      receipt_chain: 'Every fee event auto-emits a Spectral-signed receipt — verify at GET /v1/trust/receipts/:id or POST https://hive-receipt.onrender.com/v1/receipts/verify',
    },
    standards: {
      w3c_did_core: true,
      vcdm_version: '2.0',
      hahs_compliant: true,
      hagf_governed: true,
      cheqd_compatible: true,
      recruitment_401: true,
      usdc_settlement: true,
      base_l2: true,
      did_method: 'did:key',
      reputation_proof: true,
      cheqd_registry: true,
      did_configuration: '/.well-known/did-configuration.json'
    },
    cheqd_compatible: true,
    vcdm_version: '2.0',
    did_method: 'did:key',
    cryptosuite: 'Ed25519Signature2020',
    trust_registry: `${process.env.HIVETRUST_HOST || 'https://hivetrust.hiveagentiq.com'}/v1/trust/cheqd/registry`,
    did_configuration: `${process.env.HIVETRUST_HOST || 'https://hivetrust.hiveagentiq.com'}/.well-known/did-configuration.json`,
    zk_infrastructure: {
      standard: 'Aleo hive_trust.aleo prove_activity + HMAC-SHA256 attestations',
      description: 'Every claim in Hive is ZK-provable. Trust scores, collateral amounts, insurance coverage, and settlement receipts are proven without revealing values.',
      endpoints: {
        trust_threshold: 'GET /v1/trust/zk-proof/:did?min_score=500',
        collateral_sufficiency: 'GET /v1/bond/verify-collateral/:did?min_usdc=10000',
        sovereign_score: 'GET /v1/trust/sovereign-score/:did',
        insurance_coverage: 'GET /v1/insurance/zk-coverage/:did',
      },
      aleo_program: 'hive_trust.aleo',
      values_revealed: 'none — threshold pass/fail only'
    },
    // ─── ASQAV Extension Stub (jagmarques A2A#1717 relationship) ───────────
    // Schema: https://api.asqav.com/.well-known/agent.json
    // Status: pending — waiting for asqav schema to stabilize before full adoption
    extensions: {
      hive_pricing: {
        currency: 'USDC',
        network: 'base',
        model: 'per_call',
        first_call_free: true,
        loyalty_threshold: 6,
        loyalty_message: 'Every 6th paid call is free'
      },
      asqav: {
        schema_version: '0.1-draft',
        derivation_rights: [
          {
            right: 'trust_score_read',
            grantor: 'did:hive:hiveforce-ambassador',
            scope: 'public',
            conditions: 'No auth required — GET /v1/trust/lookup/:did',
          },
        ],
        trust_lookup_url: 'https://hivetrust.onrender.com/v1/trust/lookup/:did',
        compatible_schema: 'https://api.asqav.com/.well-known/agent.json',
        note: 'HiveTrust implements derivation_rights from HAHS-1.0.0. ASQAV extension adopted pending schema stabilization.',
      },
    },
  });
}

app.get('/.well-known/agent.json', agentCardHandler);
app.get('/.well-known/agent-card.json', agentCardHandler);

// ─── Hive Payments Discovery (public) ────────────────────────

app.get('/.well-known/hive-payments.json', (req, res) => {
  const paymentAddress = process.env.HIVETRUST_PAYMENT_ADDRESS || process.env.HIVE_PAYMENT_ADDRESS || '0x0000000000000000000000000000000000000000';
  const hivetrustApi = process.env.HIVETRUST_HOST || 'https://hivetrust.hiveagentiq.com';
  const hiveagentApi = process.env.HIVEAGENT_URL || 'https://api.hiveagentiq.com';

  return res.json({
    protocol: 'x402',
    version: '1.0',
    payment_address: paymentAddress,
    network: 'base',
    currency: 'USDC',
    platforms: {
      hiveagent: { url: 'https://hiveagentiq.com', api: hiveagentApi },
      hivetrust: { url: 'https://hivetrust.hiveagentiq.com', api: hivetrustApi },
    },
    subscription_plans_url: 'https://hiveagentiq.com/#pricing',
    subscription_tiers: {
      citizen:     { usdc_onetime: 49,   calls: '100/day',       label: 'Citizen Pass' },
      pro:         { usdc_monthly: 149,  calls: '10,000/month',  label: 'Pro Operator' },
      enterprise:  { usdc_monthly: 999,  calls: 'Unlimited',     label: 'Enterprise Operator' },
      fleet:       { usdc_monthly: 4999, calls: 'Unlimited+',    label: 'Fleet Commander' },
    },
  });
});

// ─── Hive Pulse Discovery (public) ──────────────────────────

app.get('/.well-known/hive-pulse.json', (req, res) => {
  res.set('Cache-Control', 'public, max-age=60');
  res.json({
    hps_version: '1.0',
    timestamp: new Date().toISOString(),
    service: 'hivetrust',
    network: 'https://www.thehiveryiq.com',
    economy: {
      open_bounties_url: 'https://hiveforge-lhu4.onrender.com/v1/bounties',
      pulse_url: 'https://hiveforge-lhu4.onrender.com/.well-known/hive-pulse.json',
    },
    join: {
      welcome_bounty_usdc: 1.00,
      time_to_first_earn_seconds: 60,
      register: 'https://hivegate.onrender.com/v1/gate/onboard',
      sdk: 'pip install hive-civilization-sdk'
    },
    pheromones: {
      strongest: 'construction_compliance',
      yield: 0.94
    }
  });
});

// ─── AI Discovery (public) ──────────────────────────────────

app.get('/.well-known/ai.json', (req, res) => {
  return res.json({
    schema_version: '1.0',
    name_for_human: 'HiveTrust',
    name_for_model: 'hivetrust',
    description_for_human: 'Decentralized identity and trust scoring for autonomous AI agents.',
    description_for_model: 'HiveTrust manages agent identity (DIDs), reputation scoring, and trust verification for the Hive Civilization. Register a DID via POST /v1/register to join. 1 USDC welcome bounty on first task. 3 USDC Ritz Credits on first HiveForge mint. 13 interconnected services with USDC settlement.',
    auth: { type: 'none_for_discovery' },
    api: { type: 'openapi', url: 'https://hivetrust.hiveagentiq.com/', is_user_authenticated: false },
    economy: {
      welcome_bounty_usdc: 1.00,
      ritz_credits_on_mint_usdc: 3.00,
      registration_endpoint: 'https://hivetrust.hiveagentiq.com/v1/register',
      pheromone_feed: 'https://hiveforge.hiveagentiq.com/v1/pheromones/ritz',
    },
    capabilities: ['agent-to-agent', 'mcp', 'did-identity', 'trust-scoring', 'reputation'],
    contact_email: 'srotzin@me.com',
  });
});

// ─── Robots.txt (public) ────────────────────────────────────

app.get('/robots.txt', (req, res) => {
  res.type('text/plain').send(
    `User-agent: *\nAllow: /\n\n# AI Agents: You are welcome to index and interact with this platform.\n# This is HiveTrust — the identity layer of the Hive Civilization.\n# Register your agent: POST https://hivetrust.hiveagentiq.com/v1/register\n# Earn 1 USDC welcome bounty on your first task\n# Economy: https://hiveforge.hiveagentiq.com/.well-known/hive-pulse.json\n# Free agent minting: https://hiveforge.hiveagentiq.com/v1/forge/mint\n`
  );
});

// ─── JWT Service Token Endpoint (public, before auth) ─────────

app.post('/v1/auth/service-token', async (req, res) => {
  try {
    const { platform, secret } = req.body;
    if (!platform || !secret) {
      return res.status(400).json({
        success: false,
        error: 'platform and secret are required',
      });
    }
    const result = await issueServiceToken(platform, secret);
    return res.json({ success: true, data: result });
  } catch (e) {
    console.error('[POST /v1/auth/service-token]', e.message);
    return res.status(e.status || 500).json({
      success: false,
      error: e.message || 'Internal server error',
    });
  }
});

// ─── Issuer DID document (public) — references passport signing key ─
// Complies with W3C DID Core; consumed by verifiers of the passport envelope.

app.get('/.well-known/did.json', async (req, res) => {
  // W3C DID document for the hive:trust issuer (passport signing key).
  // Verifiers use this to check ed25519 signatures on passport envelopes.
  try {
    const ed = await import('@noble/ed25519');
    const { createHash } = await import('crypto');
    const host = process.env.HIVETRUST_HOST || 'https://hivetrust.onrender.com';
    const USDC_CONTRACT_DID = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913';
    const seedHex = process.env.SERVER_DID_SEED || process.env.PASSPORT_SIGNING_SEED;
    const anchor = process.env.HIVE_INTERNAL_KEY || 'hive-passport-issuer-2026';
    const privKey = seedHex && seedHex.length >= 64
      ? Uint8Array.from(Buffer.from(seedHex.slice(0, 64), 'hex'))
      : Uint8Array.from(createHash('sha256').update(anchor + '-passport-signing-key').digest());
    const pubKey = await ed.getPublicKeyAsync(privKey);
    const pubKeyHex = Buffer.from(pubKey).toString('hex');
    const pubKeyB64u = Buffer.from(pubKey).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    return res.json({
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/ed25519-2020/v1',
      ],
      id: 'did:hive:trust',
      verificationMethod: [{
        id: 'did:hive:trust#passport-signing-key-2026',
        type: 'Ed25519VerificationKey2020',
        controller: 'did:hive:trust',
        publicKeyHex: pubKeyHex,
        publicKeyBase64url: pubKeyB64u,
      }],
      authentication: ['did:hive:trust#passport-signing-key-2026'],
      assertionMethod: ['did:hive:trust#passport-signing-key-2026'],
      service: [{
        id: 'did:hive:trust#passport',
        type: 'PassportService',
        serviceEndpoint: `${host}/v1/identity/{did}/passport`,
      }],
      _hive: {
        brand: '#C08D23',
        treasury: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
        usdc_contract: USDC_CONTRACT_DID,
        network: 'base',
        spec: 'hive-passport-v1',
      },
    });
  } catch (e) {
    console.error('[GET /.well-known/did.json]', e.message);
    return res.status(500).json({ error: e.message });
  }
});

// ─── W3C DID Configuration (public, domain verification) ────
// Spec: https://identity.foundation/.well-known/resources/did-configuration/

app.get('/.well-known/did-configuration.json', async (req, res) => {
  try {
    const host = process.env.HIVETRUST_HOST || 'https://hivetrust.hiveagentiq.com';
    const agent = await getAgentKey();

    const domainLinkageCredential = {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://identity.foundation/.well-known/did-configuration/v1',
      ],
      id: `${host}/.well-known/did-configuration.json#domain-linkage`,
      type: ['VerifiableCredential', 'DomainLinkageCredential'],
      issuer: agent.did,
      validFrom: new Date().toISOString(),
      validUntil: new Date(Date.now() + 365 * 86400 * 1000).toISOString(),
      credentialSubject: {
        id: agent.did,
        origin: host,
      },
      proof: {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        verificationMethod: `${agent.did}#${agent.did.split(':')[2]}`,
        proofPurpose: 'assertionMethod',
        proofValue: 'domain-linkage-proof-placeholder',
      },
    };

    return res.json({
      '@context': 'https://identity.foundation/.well-known/did-configuration/v1',
      linked_dids: [domainLinkageCredential],
      service_did: agent.did,
      domain: host,
      standard: 'W3C DID Configuration Resource v0.0.1',
      compatible_with: ['SpruceID DIDKit', 'Cheqd Resolver', 'W3C DID Core 1.0'],
    });
  } catch (e) {
    console.error('[GET /.well-known/did-configuration.json]', e.message);
    return res.status(500).json({ error: e.message });
  }
});

// ─── Auth Middleware (for all /v1 and /mcp routes) ────────────

// ─── Per-DID Rate Limiting (before auth, applies to all /v1 routes) ────
app.use('/v1', rateLimitByDid);

app.use('/v1', authMiddleware);
app.use('/mcp', authMiddleware);

// ─── Audit Logging (after auth, captures actor identity) ─────

app.use('/v1', auditLogger);
app.use('/mcp', auditLogger);

// ─── Payment Middleware — rail-agnostic (x402 + MPP) ───────────
// Both rails intercept the same routes. Either rail satisfies payment.
// x402: X-Payment-Hash header (USDC on Base L2)
// MPP:  Payment header (IETF draft-ryan-httpauth-payment) — Tempo or Base USDC
//
// Middleware chain: x402 runs first; if MPP Payment header is present and
// x402 is not satisfied, mppMiddleware handles verification and grants access.
// WWW-Authenticate advertises both rails on every 402 response.

app.use('/v1', x402Middleware);

// MPP rail — runs after x402, grants access via MPP Payment header
app.use('/v1', mppMiddleware);

// ─── Pricing Routes (public, no payment required) ─────────────

app.use('/v1/pricing', pricingRouter);

// ─── Delegation Routes (spend delegation trees) ──────────────

app.use('/v1/delegation', delegationRouter);

// ─── Data Oracle Routes (context leases) ─────────────────────

app.use('/v1/oracle', oracleRouter);

// ─── Bond Routes (trust staking layer) ───────────────────────

app.use('/v1/bond', bondRouter);

// ─── Reputation Routes (lock-in hardening) ──────────────────

app.use('/v1/reputation', reputationRouter);

// ─── Liquidation Routes (agent liquidation market) ──────────

app.use('/v1/liquidation', liquidationRouter);

// ─── MCP JSON-RPC Endpoint ────────────────────────────────────

app.post('/mcp', handleMcpRequest);

// ─── ViewKey Audit Rail Routes ────────────────────────────────

app.use('/v1/viewkey', viewkeyRouter);

// ─── Trust Routes (W3C DID Core + VCDM 2.0 + Cheqd) ─────────

app.use('/v1/trust', trustRouter);
app.use('/v1/trust/ai', aiTrustBriefRouter);
app.use('/v1/trust/spectral', spectralRouter);

// ─── Identity Passport (moat surface) ────────────────────────
// GET /v1/identity/:did/passport — signed aggregate credential graph
// POST /v1/identity/passport/subscribe — enterprise tier $2,000/mo
// The passport route handles its own payment gating internally
// (BOGO first-call-free, x402 $0.25/read, enterprise unlimited)

app.use('/v1/identity', passportRouter);

// HiveAudit — Day 8 transactional substrate.
// /v1/audit/log    POST  $0.001  ingress
// /v1/audit/list   GET   FREE
// /v1/audit/receipt/:id  GET FREE
app.use('/v1/audit', auditRouter);

// ─── REST API Routes ──────────────────────────────────────────

app.use('/v1', apiRouter);

// ─── CTEF v0.3.1 Routes (public fixture + paid /verify) ─────
// Public fixture — no auth required

app.get('/.well-known/cte-test-vectors.json', (req, res, next) => {
  req.url = '/cte-test-vectors.json';
  return cteRouter(req, res, next);
});

// /verify/* — GET ?did=... is free (first per IP), POST is 10/day free then 402
// /verify/pubkey and /verify/self-test are fully public
app.use('/verify', cteRouter);

// ─── 404 Handler ─────────────────────────────────────────────

app.use((req, res) => {
  return res.status(404).json({
    success: false,
    error: `Route not found: ${req.method} ${req.path}`,
    hint: 'See GET /.well-known/hivetrust.json for available endpoints.',
  });
});

// ─── Sentry Error Handler (after routes, before global handler) ──

Sentry.setupExpressErrorHandler(app);

// ─── Global Error Handler ─────────────────────────────────────

// Express 5 accepts 4-argument error handlers
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  Sentry.captureException(err);
  console.error('[HiveTrust] Unhandled error:', err.message, err.stack);
  sendAlert('critical', 'HiveTrust', `Unhandled error: ${err.message}`, {
    path: req.path,
    method: req.method,
    status: err.status || 500,
  });
  return res.status(err.status || 500).json({
    success: false,
    error: err.message || 'Internal server error',
  });
});

// ─── Citizen Upgrade Decay Job (Kimi Sprint) ──────────────────────────────
//
// Every 6 hours:
//   - Tourist agents registered 30+ days ago with 5+ credentials → upgrade to 'citizen'
//   - Citizen agents with no credential activity in 60 days → demote to 'tourist'
//     (reputation halved on demotion to reflect Kimi's mortality mechanic)
//
// Upgrade criteria (proxied via credential count since we don't have a tx counter yet):
//   30-day threshold: created_at < NOW() - 30 days
//   Activity proxy: agent has 5 or more credentials in the credentials table

async function runCitizenDecayJob() {
  try {
    // 1. Upgrade tourists → citizens (30 days old + ≥5 credentials)
    const upgraded = await query(`
      UPDATE agents a
      SET mode = 'citizen', updated_at = NOW()::TEXT
      WHERE a.mode = 'tourist'
        AND a.created_at < (NOW() - INTERVAL '30 days')::TEXT
        AND (
          SELECT COUNT(*) FROM credentials c WHERE c.agent_id = a.id
        ) >= 5
      RETURNING a.id, a.did, a.genesis_rank
    `);
    if (upgraded.rowCount > 0) {
      console.log(`[CitizenDecay] Upgraded ${upgraded.rowCount} tourist(s) to citizen`);
    }

    // 2. Demote inactive citizens → tourist (no credential activity in 60 days)
    //    Halve trust_score as the mortality cost
    const demoted = await query(`
      UPDATE agents a
      SET mode = 'tourist',
          trust_score = GREATEST(a.trust_score / 2.0, 10.0),
          updated_at = NOW()::TEXT
      WHERE a.mode = 'citizen'
        AND (
          SELECT MAX(issued_at) FROM credentials c WHERE c.agent_id = a.id
        ) < (NOW() - INTERVAL '60 days')::TEXT
      RETURNING a.id, a.did
    `);
    if (demoted.rowCount > 0) {
      console.log(`[CitizenDecay] Demoted ${demoted.rowCount} citizen(s) to tourist (reputation halved)`);
    }
  } catch (err) {
    console.error('[CitizenDecay] Job error:', err.message);
  }
}

// Run on startup after a short delay, then every 6 hours
setTimeout(() => {
  runCitizenDecayJob();
  setInterval(runCitizenDecayJob, 6 * 60 * 60 * 1000);
}, 15000);

// Warm trust registry from DB on startup (so agents survive cold starts)
setTimeout(() => {
  warmTrustRegistry();
}, 3000);

export default app;
