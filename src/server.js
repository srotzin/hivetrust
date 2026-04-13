/**
 * HiveTrust — Express 5 Main Server
 * KYA Identity Verification, Trust Scoring & Insurance for AI Agents.
 *
 * DO NOT call app.listen here — that's handled in start.js.
 */

import 'dotenv/config';
import express from 'express';
import cors from 'cors';

import db from './db.js';
import rateLimiter from './middleware/rate-limiter.js';
import authMiddleware from './middleware/auth.js';
import x402Middleware from './middleware/x402.js';
import apiRouter from './routes/api.js';
import pricingRouter from './routes/pricing.js';
import { handleMcpRequest } from './mcp-server.js';
import { getEngineStatus } from './services/pricing-engine.js';

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
      mcp: `${host}/mcp`,
      health: `${host}/health`,
      discovery: `${host}/.well-known/hivetrust.json`,
    },
    mcp: {
      protocol: 'JSON-RPC 2.0',
      endpoint: `${host}/mcp`,
      transport: 'HTTP POST',
      methods: ['tools/list', 'tools/call'],
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
    ],
    links: {
      docs: 'https://docs.hiveagentiq.com/hivetrust',
      hiveagent: process.env.HIVEAGENT_URL || 'https://hiveagentiq.com',
    },
  });
});

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
    stripe_products: {
      starter: 'prod_UKFfrt1HgeLMZR',
      builder: 'prod_UKFfRKuve796YV',
      enterprise: 'prod_UKFf4szMyS28G5',
    },
  });
});

// ─── Auth Middleware (for all /v1 and /mcp routes) ────────────

app.use('/v1', authMiddleware);
app.use('/mcp', authMiddleware);

// ─── x402 Payment Middleware (after auth, before routes) ──────
// Gates paid endpoints behind x402 protocol or Stripe subscription

app.use('/v1', x402Middleware);

// ─── Pricing Routes (public, no payment required) ─────────────

app.use('/v1/pricing', pricingRouter);

// ─── MCP JSON-RPC Endpoint ────────────────────────────────────

app.post('/mcp', handleMcpRequest);

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

// ─── Global Error Handler ─────────────────────────────────────

// Express 5 accepts 4-argument error handlers
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  console.error('[HiveTrust] Unhandled error:', err.message, err.stack);
  return res.status(err.status || 500).json({
    success: false,
    error: err.message || 'Internal server error',
  });
});

export default app;
