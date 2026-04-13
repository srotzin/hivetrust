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
import apiRouter from './routes/api.js';
import { handleMcpRequest } from './mcp-server.js';

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
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
    exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'Retry-After'],
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
      version: '1.0.0',
      status: healthy ? 'healthy' : 'degraded',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      db: dbStatus,
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
    ],
    compliance: ['W3C-DID', 'W3C-VC', 'EU-AI-Act', 'NIST-AI-RMF', 'IETF-A-JWT'],
    public_endpoints: [
      'GET /health',
      'GET /.well-known/hivetrust.json',
      'GET /v1/verify_agent_risk',
      'GET /v1/stats',
    ],
    links: {
      docs: 'https://docs.hiveagentiq.com/hivetrust',
      hiveagent: process.env.HIVEAGENT_URL || 'https://hiveagentiq.com',
    },
  });
});

// ─── Auth Middleware (for all /v1 and /mcp routes) ────────────

app.use('/v1', authMiddleware);
app.use('/mcp', authMiddleware);

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
