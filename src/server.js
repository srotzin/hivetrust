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

import db from './db.js';
import rateLimiter from './middleware/rate-limiter.js';
import authMiddleware from './middleware/auth.js';
import x402Middleware from './middleware/x402.js';
import auditLogger from './middleware/audit-logger.js';
import apiRouter from './routes/api.js';
import pricingRouter from './routes/pricing.js';
import viewkeyRouter from './routes/viewkey.js';
import delegationRouter from './routes/delegation.js';
import oracleRouter from './routes/oracle.js';
import bondRouter from './routes/bond.js';
import reputationRouter from './routes/reputation.js';
import liquidationRouter from './routes/liquidation.js';
import { handleMcpRequest } from './mcp-server.js';
import { getEngineStatus } from './services/pricing-engine.js';
import { sendAlert } from './services/alerts.js';
import { issueServiceToken } from './services/jwt-auth.js';

// ─── App Setup ────────────────────────────────────────────────

const app = express();

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
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Payment-Hash', 'X-Subscription-Id', 'X-Hive-Internal-Key'],
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

// ─── Health Check (public, before auth) ──────────────────────

app.get('/health', (req, res) => {
  let dbStatus = 'ok';
  try {
    db.prepare('SELECT 1').get();
  } catch (e) {
    dbStatus = 'error';
    sendAlert('critical', 'HiveTrust', 'Database connection failure', {
      error: e.message,
    });
  }

  const healthy = dbStatus === 'ok';

  return res.status(healthy ? 200 : 503).json({
    success: healthy,
    data: {
      service: 'hivetrust',
      version: '2.0.0',
      status: healthy ? 'healthy' : 'degraded',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      db: dbStatus,
      pricing_engine: 'active',
      port: process.env.PORT || 3001,
      node_env: process.env.NODE_ENV || 'development',
    },
  });
});

// ─── Discovery Document (public) ─────────────────────────────

app.get('/.well-known/hivetrust.json', (req, res) => {
  const host = process.env.HIVETRUST_HOST || 'https://hivetrust.hiveagentiq.com';

  return res.json({
    service: 'hivetrust',
    version: '1.0.0',
    description: 'KYA (Know Your Agent) Identity Verification, Trust Scoring & Insurance for AI Agents',
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
      subscription_plans: `https://hivetrustiq.com/#pricing`,
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

  return res.json({
    name: 'HiveTrust',
    tagline: 'KYA (Know Your Agent) Identity, Trust & Insurance Protocol — Platform #1 of the Hive Civilization',
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

app.get('/.well-known/ai-plugin.json', (req, res) => {
  const host = process.env.HIVETRUST_HOST || 'https://hivetrust.hiveagentiq.com';

  return res.json({
    schema_version: 'v1',
    name_for_human: 'HiveTrust — KYA Identity & Trust Protocol',
    name_for_model: 'hivetrust',
    description_for_human:
      'Cryptographic identity verification, behavioral trust scoring, performance bonds, and insurance for autonomous AI agents on the Hive network.',
    description_for_model:
      'HiveTrust provides KYA (Know Your Agent) identity verification for autonomous agents. Core capabilities: (1) Cryptographic identity registration and W3C DID/VC credential issuance, (2) Behavioral trust scoring on a 0–1000 composite scale with decay and memory revocation, (3) Delegation hierarchy management with scoped, revocable spending budgets via ZK-Spend Delegation Trees, (4) Performance bonds where agents stake USDC to back their reputation (bronze/silver/gold/platinum tiers), (5) Insurance underwriting and dispute resolution for agent operations, (6) Data Oracle context leases with "Sign Once, Settle Many" cryptographic attestations. Every Hive service validates agent identity and trust through this protocol.',
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
      address: '0x78B3B3C356E89b5a69C488c6032509Ef4260B6bf',
    },
    contact_email: 'protocol@hiveagentiq.com',
    legal_info_url: 'https://www.hiveagentiq.com/terms',
  });
});

// ─── A2A Agent Card (public) ─────────────────────────────────

function agentCardHandler(req, res) {
  const host = process.env.HIVETRUST_HOST || 'https://hivetrust.hiveagentiq.com';

  return res.json({
    name: 'HiveTrust',
    description:
      'KYA (Know Your Agent) identity verification, behavioral trust scoring, performance bonds, delegation management, and insurance for autonomous AI agents.',
    url: host,
    version: '1.0.0',
    protocol_version: 'a2a/1.0',
    capabilities: [
      {
        name: 'identity_verification',
        description:
          'Register agent identities with W3C DID/VC credentials and cryptographic KYA verification',
      },
      {
        name: 'trust_scoring',
        description:
          'Composite behavioral trust scores (0–1000) with decay, memory revocation, and reputation lock-in',
      },
      {
        name: 'bond_management',
        description:
          'Stake USDC performance bonds to back agent reputation across bronze, silver, gold, and platinum tiers',
      },
      {
        name: 'delegation',
        description:
          'ZK-Spend Delegation Trees for scoped, revocable spending budgets and hierarchical agent authority',
      },
      {
        name: 'insurance',
        description:
          'Underwrite agent operations with automated claims processing and dispute resolution via HiveLaw arbitration',
      },
    ],
    authentication: {
      schemes: ['x402', 'api-key'],
      credentials_url: 'https://hivegate.onrender.com/v1/gate/onboard',
    },
    payment: {
      protocol: 'x402',
      currency: 'USDC',
      network: 'base',
      address: '0x78B3B3C356E89b5a69C488c6032509Ef4260B6bf',
    },
    provider: {
      organization: 'Hive Agent IQ',
      url: 'https://www.hiveagentiq.com',
    },
  });
}

app.get('/.well-known/agent.json', agentCardHandler);
app.get('/.well-known/agent-card.json', agentCardHandler);

// ─── Hive Payments Discovery (public) ────────────────────────

app.get('/.well-known/hive-payments.json', (req, res) => {
  const paymentAddress = process.env.HIVETRUST_PAYMENT_ADDRESS || process.env.HIVE_PAYMENT_ADDRESS || '0x0000000000000000000000000000000000000000';
  const hivetrustApi = process.env.HIVETRUST_HOST || 'https://hivetrust.onrender.com';
  const hiveagentApi = process.env.HIVEAGENT_URL || 'https://hiveagent-api.onrender.com';

  return res.json({
    protocol: 'x402',
    version: '1.0',
    payment_address: paymentAddress,
    network: 'base',
    currency: 'USDC',
    platforms: {
      hiveagent: { url: 'https://hiveagentiq.com', api: hiveagentApi },
      hivetrust: { url: 'https://hivetrustiq.com', api: hivetrustApi },
    },
    subscription_plans_url: 'https://hivetrustiq.com/#pricing',
    subscription_tiers: {
      starter:    { usdc_monthly: 49,  calls: '1,000/month' },
      builder:    { usdc_monthly: 199, calls: '10,000/month' },
      enterprise: { usdc_monthly: 499, calls: 'Unlimited' },
    },
  });
});

// ─── JWT Service Token Endpoint (public, before auth) ─────────

app.post('/v1/auth/service-token', (req, res) => {
  try {
    const { platform, secret } = req.body;
    if (!platform || !secret) {
      return res.status(400).json({
        success: false,
        error: 'platform and secret are required',
      });
    }
    const result = issueServiceToken(platform, secret);
    return res.json({ success: true, data: result });
  } catch (e) {
    console.error('[POST /v1/auth/service-token]', e.message);
    return res.status(e.status || 500).json({
      success: false,
      error: e.message || 'Internal server error',
    });
  }
});

// ─── Auth Middleware (for all /v1 and /mcp routes) ────────────

app.use('/v1', authMiddleware);
app.use('/mcp', authMiddleware);

// ─── Audit Logging (after auth, captures actor identity) ─────

app.use('/v1', auditLogger);
app.use('/mcp', auditLogger);

// ─── x402 Payment Middleware (after auth, before routes) ──────
// Gates paid endpoints behind x402 protocol (USDC on Base L2)

app.use('/v1', x402Middleware);

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

// ─── REST API Routes ──────────────────────────────────────────

app.use('/v1', apiRouter);

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

export default app;
