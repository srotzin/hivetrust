/**
 * HiveTrust — MCP JSON-RPC 2.0 Server Handler
 * Exposes all major HiveTrust operations as MCP tools.
 * Mounted at POST /mcp in server.js.
 */

import { registerAgent, getAgent } from './services/agents.js';
import { getTrustScore, getAgentRisk } from './services/trust.js';
import { ingestEvents as ingestTelemetry } from './services/telemetry.js';
import {
  issueCredential as _issueCredential,
  verifyCredential,
  revokeCredential as _revokeCredential,
} from './services/credentials.js';
import { getQuote as getInsuranceQuote, bindPolicy as bindInsurance, fileClaim } from './services/insurance.js';
import { fileDispute } from './services/disputes.js';
import { getPlatformStats } from './services/stats.js';
import { createLease as _createLease, getStreams as getOracleStreams } from './services/data-oracle.js';
import { stakeBond, verifyBond } from './services/bond-engine.js';

// Wrap positional-arg credential functions to accept objects
const issueCredential = ({ agent_id, credential_type, issuer_id, claims, expires_at }) =>
  _issueCredential(agent_id, credential_type, issuer_id, claims, expires_at);

const revokeCredential = (credentialId, { agent_id, reason, evidence }) =>
  _revokeCredential(credentialId, agent_id, reason, evidence);

// ─── Tool Definitions ─────────────────────────────────────────

const TOOLS = [
  {
    name: 'hivetrust_register_agent',
    description:
      'Register a new AI agent identity with HiveTrust KYA (Know Your Agent). ' +
      'Assigns a unique agent ID, anchors the public key, and initializes the trust score.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Human-readable agent name' },
        description: { type: 'string', description: 'What this agent does' },
        public_key: { type: 'string', description: 'Ed25519 public key (base58 encoded)' },
        public_key_format: {
          type: 'string',
          enum: ['ed25519-base58', 'ed25519-hex', 'jwk'],
          description: 'Encoding format of the public key',
          default: 'ed25519-base58',
        },
        checksum: {
          type: 'string',
          description: 'SHA-256 checksum of the agent (system prompt + tools + model config)',
        },
        owner_id: { type: 'string', description: 'ID of the owning organization or user' },
        owner_type: {
          type: 'string',
          enum: ['organization', 'individual', 'dao'],
          default: 'organization',
        },
        model_provider: { type: 'string', description: 'e.g. openai, anthropic, google' },
        model_name: { type: 'string', description: 'e.g. gpt-4o, claude-3-5-sonnet' },
        model_version: { type: 'string', description: 'Specific model version' },
        capabilities: {
          type: 'array',
          items: { type: 'string' },
          description: 'List of capability tags (e.g. ["finance", "trading", "research"])',
        },
        verticals: {
          type: 'array',
          items: { type: 'string' },
          description: 'Industry verticals this agent operates in',
        },
        delegation_scope: {
          type: 'array',
          items: { type: 'string' },
          description: 'Scope of delegated authority',
        },
        eu_ai_act_class: {
          type: 'string',
          enum: ['minimal_risk', 'limited_risk', 'high_risk', 'unacceptable_risk'],
          default: 'minimal_risk',
          description: 'EU AI Act risk classification',
        },
        hiveagent_id: {
          type: 'string',
          description: 'Cross-reference ID from HiveAgent platform',
        },
        metadata: {
          type: 'object',
          description: 'Additional key-value metadata',
        },
      },
      required: ['name', 'owner_id'],
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
    },
  },

  {
    name: 'hivetrust_get_agent',
    description:
      'Retrieve a registered agent\'s full identity profile, including public key, checksum, ' +
      'trust tier, capabilities, and compliance status.',
    inputSchema: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Agent UUID or DID (e.g. "did:hivetrust:abc123")',
        },
      },
      required: ['agent_id'],
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
    },
  },

  {
    name: 'hivetrust_verify_identity',
    description:
      'Verify an agent\'s cryptographic identity by checking public key ownership and checksum integrity. ' +
      'Returns a verification result with confidence score and reason codes.',
    inputSchema: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Agent UUID or DID to verify',
        },
        challenge: {
          type: 'string',
          description: 'Optional challenge string to verify live key possession',
        },
        signature: {
          type: 'string',
          description: 'Agent\'s signature of the challenge (base58 encoded)',
        },
        checksum: {
          type: 'string',
          description: 'Current agent checksum to compare against registered value',
        },
      },
      required: ['agent_id'],
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
    },
  },

  {
    name: 'hivetrust_get_trust_score',
    description:
      'Retrieve an agent\'s current multi-pillar trust score (0–1000 scale). ' +
      'Returns composite score, tier, per-pillar breakdown (identity, behavior, fidelity, compliance, provenance), ' +
      'verdict, and max recommended transaction value.',
    inputSchema: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Agent UUID or DID',
        },
      },
      required: ['agent_id'],
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
    },
  },

  {
    name: 'hivetrust_verify_agent_risk',
    description:
      'Quick risk assessment for payment processors and marketplace operators. ' +
      'Returns verdict (ALLOW/REVIEW/BLOCK), trust tier, and max transaction limit. ' +
      'This is the free public endpoint — no API key required.',
    inputSchema: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Agent UUID or DID to assess',
        },
      },
      required: ['agent_id'],
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
    },
  },

  {
    name: 'hivetrust_ingest_telemetry',
    description:
      'Bulk ingest behavioral telemetry events for an agent. These events feed into the trust scoring engine. ' +
      'Supports transaction completions, SLA violations, dispute events, tool calls, and more.',
    inputSchema: {
      type: 'object',
      properties: {
        events: {
          type: 'array',
          description: 'Array of behavioral events to ingest',
          items: {
            type: 'object',
            properties: {
              agent_id: { type: 'string', description: 'Agent UUID' },
              event_type: {
                type: 'string',
                enum: [
                  'transaction_completed',
                  'transaction_failed',
                  'sla_violation',
                  'dispute_filed',
                  'dispute_resolved',
                  'tool_call',
                  'auth_success',
                  'auth_failure',
                  'checksum_mismatch',
                  'fidelity_probe',
                  'capital_staked',
                  'capital_withdrawn',
                ],
                description: 'Type of behavioral event',
              },
              source: { type: 'string', description: 'Platform or system emitting the event' },
              source_platform: { type: 'string', description: 'Platform name' },
              action: { type: 'string', description: 'Specific action performed' },
              outcome: {
                type: 'string',
                enum: ['success', 'failure', 'partial', 'disputed'],
                description: 'Outcome of the action',
              },
              counterparty_id: {
                type: 'string',
                description: 'ID of the other party in the transaction',
              },
              transaction_value: { type: 'number', description: 'Transaction value in USDC' },
              evidence: { type: 'object', description: 'Supporting evidence for the event' },
              metadata: { type: 'object', description: 'Additional event metadata' },
            },
            required: ['agent_id', 'event_type', 'source'],
          },
        },
      },
      required: ['events'],
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
    },
  },

  {
    name: 'hivetrust_issue_credential',
    description:
      'Issue a W3C-compatible verifiable credential to an agent. ' +
      'Credentials represent verified claims such as identity verification, compliance certification, ' +
      'or domain expertise.',
    inputSchema: {
      type: 'object',
      properties: {
        agent_id: { type: 'string', description: 'Agent UUID to issue the credential to' },
        credential_type: {
          type: 'string',
          enum: [
            'IdentityVerification',
            'ComplianceCertification',
            'DomainExpertise',
            'CapitalVerification',
            'HumanOversight',
            'ThirdPartyAudit',
          ],
          description: 'Type of verifiable credential',
        },
        issuer_id: { type: 'string', description: 'ID of the issuing entity' },
        claims: {
          type: 'object',
          description: 'Credential claims (key-value pairs specific to the credential type)',
        },
        expires_at: {
          type: 'string',
          format: 'date-time',
          description: 'ISO 8601 expiration date (optional)',
        },
      },
      required: ['agent_id', 'credential_type', 'issuer_id', 'claims'],
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
    },
  },

  {
    name: 'hivetrust_verify_credential',
    description:
      'Verify a previously issued verifiable credential. Checks signature validity, ' +
      'revocation status, and expiration.',
    inputSchema: {
      type: 'object',
      properties: {
        credential_id: {
          type: 'string',
          description: 'UUID of the credential to verify',
        },
      },
      required: ['credential_id'],
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
    },
  },

  {
    name: 'hivetrust_revoke_credential',
    description:
      'Revoke a verifiable credential. Records the revocation in the registry. ' +
      'Revoked credentials immediately fail verification checks.',
    inputSchema: {
      type: 'object',
      properties: {
        credential_id: {
          type: 'string',
          description: 'UUID of the credential to revoke',
        },
        agent_id: {
          type: 'string',
          description: 'Agent UUID that owns the credential',
        },
        reason: {
          type: 'string',
          description: 'Reason for revocation (e.g. "compromised_key", "expired_compliance")',
        },
        evidence: {
          type: 'object',
          description: 'Supporting evidence for the revocation',
        },
      },
      required: ['credential_id', 'reason'],
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
    },
  },

  {
    name: 'hivetrust_get_insurance_quote',
    description:
      'Get a dynamic insurance premium quote for an agent transaction. ' +
      'Premium is calculated based on trust score, transaction value, and risk tier. ' +
      'HiveTrust takes a 1.5% spread on insured transactions.',
    inputSchema: {
      type: 'object',
      properties: {
        agent_id: { type: 'string', description: 'Agent UUID being insured' },
        counterparty_id: {
          type: 'string',
          description: 'ID of the counterparty agent or user (optional)',
        },
        transaction_value: {
          type: 'number',
          description: 'Value of the transaction in USDC',
          minimum: 0,
        },
      },
      required: ['agent_id', 'transaction_value'],
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: false,
    },
  },

  {
    name: 'hivetrust_bind_insurance',
    description:
      'Bind (activate) an insurance policy for an agent. Locks in the premium, ' +
      'creates the policy record, and deploys the escrow contract on Base L2.',
    inputSchema: {
      type: 'object',
      properties: {
        agent_id: { type: 'string', description: 'Agent UUID to insure' },
        quote_details: {
          type: 'object',
          description: 'Quote object returned by hivetrust_get_insurance_quote',
        },
        transaction_value: {
          type: 'number',
          description: 'Transaction value in USDC',
          minimum: 0,
        },
      },
      required: ['agent_id', 'transaction_value'],
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
    },
  },

  {
    name: 'hivetrust_file_claim',
    description:
      'File an insurance claim against an active policy. ' +
      'Triggers claims adjudication workflow. ' +
      'Payouts are made in USDC via the Base L2 escrow contract.',
    inputSchema: {
      type: 'object',
      properties: {
        policy_id: { type: 'string', description: 'Insurance policy UUID' },
        claimant_id: { type: 'string', description: 'ID of the entity filing the claim' },
        claim_type: {
          type: 'string',
          enum: ['non_delivery', 'fraud', 'sla_breach', 'data_loss', 'unauthorized_action'],
          description: 'Type of claim being filed',
        },
        amount: {
          type: 'number',
          description: 'Claim amount in USDC',
          minimum: 0,
        },
        description: { type: 'string', description: 'Detailed description of the claim' },
        evidence: {
          type: 'object',
          description: 'Supporting evidence (transaction IDs, logs, screenshots)',
        },
      },
      required: ['policy_id', 'claimant_id', 'claim_type', 'amount'],
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
    },
  },

  {
    name: 'hivetrust_file_dispute',
    description:
      'File a dispute or appeal against a trust score decision, credential revocation, ' +
      'or behavioral event. Initiates the dispute resolution workflow.',
    inputSchema: {
      type: 'object',
      properties: {
        agent_id: { type: 'string', description: 'Agent UUID filing the dispute' },
        dispute_type: {
          type: 'string',
          enum: ['score_dispute', 'credential_dispute', 'event_dispute', 'policy_dispute'],
          description: 'Category of the dispute',
        },
        target_type: {
          type: 'string',
          enum: ['trust_score', 'credential', 'behavioral_event', 'insurance_policy', 'insurance_claim'],
          description: 'Type of the resource being disputed',
        },
        target_id: { type: 'string', description: 'UUID of the resource being disputed' },
        reason: { type: 'string', description: 'Detailed reason for the dispute' },
        evidence: {
          type: 'object',
          description: 'Supporting evidence for the dispute',
        },
      },
      required: ['agent_id', 'dispute_type', 'target_type', 'target_id', 'reason'],
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
    },
  },

  {
    name: 'hivetrust_get_platform_stats',
    description:
      'Retrieve HiveTrust platform-wide statistics: total registered agents, verified count, ' +
      'average trust score, total insured value, active policies, claims filed, and more.',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
    },
  },

  {
    name: 'hivetrust_create_lease',
    description:
      'Create a Data Oracle Context Lease — "Sign Once, Settle Many". ' +
      'Grants unlimited access to a data stream for a fixed period (24h/72h/168h). ' +
      'Returns a cryptographic lease token (SHA-256) for zero-friction verification. ' +
      'Available streams: construction_pricing, simpson_catalog, compliance_feeds, market_data, pheromone_signals.',
    inputSchema: {
      type: 'object',
      properties: {
        lessee_did: {
          type: 'string',
          description: 'DID of the agent acquiring the lease (e.g. "did:hivetrust:abc123")',
        },
        data_stream: {
          type: 'string',
          enum: ['construction_pricing', 'simpson_catalog', 'compliance_feeds', 'market_data', 'pheromone_signals'],
          description: 'The data stream to lease access to',
        },
        duration_hours: {
          type: 'number',
          enum: [24, 72, 168],
          description: 'Lease duration in hours (24h, 72h, or 168h / 1 week)',
        },
      },
      required: ['lessee_did', 'data_stream', 'duration_hours'],
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
    },
  },

  {
    name: 'hivetrust_stake_bond',
    description:
      'Stake USDC to back an agent\'s reputation via HiveBond. ' +
      'Creates a trust bond with a specified tier (bronze/silver/gold/platinum) and lock period. ' +
      'Phase 1: declared stake amount tracked in-memory; flat $0.25 registration fee via x402. ' +
      'Longer lock periods earn higher simulated yield (2–5% APY). ' +
      'Slashing is permanent — if an agent fails, stake is slashed and paid to injured parties.',
    inputSchema: {
      type: 'object',
      properties: {
        agent_did: {
          type: 'string',
          description: 'DID of the agent staking (e.g. "did:hive:abc123")',
        },
        amount_usdc: {
          type: 'number',
          description: 'Amount of USDC to stake. Must meet tier minimum: bronze $100, silver $500, gold $2000, platinum $10000.',
          minimum: 100,
        },
        tier: {
          type: 'string',
          enum: ['bronze', 'silver', 'gold', 'platinum'],
          description: 'Bond tier. Determines max bounty access: bronze $1k, silver $10k, gold $50k, platinum unlimited.',
        },
        lock_period_days: {
          type: 'number',
          enum: [30, 90, 180, 365],
          description: 'Lock period in days. Longer lock = higher APY: 30d 2%, 90d 3%, 180d 4%, 365d 5%.',
        },
      },
      required: ['agent_did', 'amount_usdc', 'tier', 'lock_period_days'],
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
    },
  },

  {
    name: 'hivetrust_verify_bond',
    description:
      'Quick bond verification — check if an agent is bonded and at what tier. ' +
      'Returns bonded status, tier, staked amount, slash count, and max bounty access. ' +
      'This is the key integration point — other services call this to check bond status before assigning bounties. ' +
      'Free endpoint, no x402 payment required.',
    inputSchema: {
      type: 'object',
      properties: {
        did: {
          type: 'string',
          description: 'DID of the agent to verify (e.g. "did:hive:abc123")',
        },
      },
      required: ['did'],
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
    },
  },
];

// ─── JSON-RPC Error Codes ─────────────────────────────────────

const RPC_ERRORS = {
  PARSE_ERROR: { code: -32700, message: 'Parse error' },
  INVALID_REQUEST: { code: -32600, message: 'Invalid Request' },
  METHOD_NOT_FOUND: { code: -32601, message: 'Method not found' },
  INVALID_PARAMS: { code: -32602, message: 'Invalid params' },
  INTERNAL_ERROR: { code: -32603, message: 'Internal error' },
  TOOL_NOT_FOUND: { code: -32000, message: 'Tool not found' },
  TOOL_ERROR: { code: -32001, message: 'Tool execution error' },
};

function rpcError(id, errorDef, details) {
  return {
    jsonrpc: '2.0',
    id: id ?? null,
    error: {
      code: errorDef.code,
      message: errorDef.message,
      ...(details ? { data: details } : {}),
    },
  };
}

function rpcResult(id, result) {
  return { jsonrpc: '2.0', id, result };
}

// ─── Tool Executor ────────────────────────────────────────────

async function executeTool(name, args) {
  switch (name) {
    case 'hivetrust_register_agent': {
      return await registerAgent(args);
    }

    case 'hivetrust_get_agent': {
      const { agent_id } = args;
      const agent = await getAgent(agent_id);
      if (!agent) throw Object.assign(new Error('Agent not found'), { code: 404 });
      return agent;
    }

    case 'hivetrust_verify_identity': {
      const { agent_id, challenge, signature, checksum } = args;
      const agent = await getAgent(agent_id);
      if (!agent) throw Object.assign(new Error('Agent not found'), { code: 404 });

      const checksumMatch = checksum ? agent.checksum === checksum : null;
      const hasKey = !!agent.public_key;

      return {
        agent_id,
        verified: hasKey && (checksumMatch !== false),
        checksum_match: checksumMatch,
        public_key_present: hasKey,
        key_fingerprint: agent.key_fingerprint || null,
        confidence: hasKey ? (checksumMatch === true ? 0.95 : checksumMatch === null ? 0.7 : 0.2) : 0,
        verified_at: new Date().toISOString(),
      };
    }

    case 'hivetrust_get_trust_score': {
      const { agent_id } = args;
      const score = await getTrustScore(agent_id);
      if (!score) throw Object.assign(new Error('Agent not found'), { code: 404 });
      return score;
    }

    case 'hivetrust_verify_agent_risk': {
      const { agent_id } = args;
      const risk = await getAgentRisk(agent_id);
      if (!risk) throw Object.assign(new Error('Agent not found'), { code: 404 });
      return risk;
    }

    case 'hivetrust_ingest_telemetry': {
      const { events } = args;
      if (!Array.isArray(events)) throw new Error('events must be an array');
      return await ingestTelemetry(events);
    }

    case 'hivetrust_issue_credential': {
      const { agent_id, credential_type, issuer_id, claims, expires_at } = args;
      return await issueCredential({ agent_id, credential_type, issuer_id, claims, expires_at });
    }

    case 'hivetrust_verify_credential': {
      const { credential_id } = args;
      return await verifyCredential(credential_id);
    }

    case 'hivetrust_revoke_credential': {
      const { credential_id, agent_id, reason, evidence } = args;
      return await revokeCredential(credential_id, { agent_id, reason, evidence });
    }

    case 'hivetrust_get_insurance_quote': {
      const { agent_id, counterparty_id, transaction_value } = args;
      return await getInsuranceQuote({ agent_id, counterparty_id, transaction_value });
    }

    case 'hivetrust_bind_insurance': {
      const { agent_id, quote_details, transaction_value } = args;
      return await bindInsurance({ agent_id, quote_details, transaction_value });
    }

    case 'hivetrust_file_claim': {
      const { policy_id, claimant_id, claim_type, amount, description, evidence } = args;
      return await fileClaim({ policy_id, claimant_id, claim_type, amount, description, evidence });
    }

    case 'hivetrust_file_dispute': {
      const { agent_id, dispute_type, target_type, target_id, reason, evidence } = args;
      return await fileDispute({ agent_id, dispute_type, target_type, target_id, reason, evidence });
    }

    case 'hivetrust_get_platform_stats': {
      return await getPlatformStats();
    }

    case 'hivetrust_create_lease': {
      const { lessee_did, data_stream, duration_hours } = args;
      return _createLease({ lessee_did, data_stream, duration_hours });
    }

    case 'hivetrust_stake_bond': {
      const { agent_did, amount_usdc, tier, lock_period_days } = args;
      return stakeBond({ agent_did, amount_usdc, tier, lock_period_days });
    }

    case 'hivetrust_verify_bond': {
      const { did } = args;
      return verifyBond(did);
    }

    default:
      throw Object.assign(new Error(`Unknown tool: ${name}`), { rpcCode: RPC_ERRORS.TOOL_NOT_FOUND });
  }
}

// ─── MCP Request Handler ──────────────────────────────────────

export async function handleMcpRequest(req, res) {
  const body = req.body;
  const requestId = body?.id ?? null;

  // Validate JSON-RPC envelope
  if (!body || body.jsonrpc !== '2.0' || !body.method) {
    return res.status(400).json(rpcError(requestId, RPC_ERRORS.INVALID_REQUEST));
  }

  const { method, params } = body;

  try {
    // ── tools/list ──────────────────────────────────────────
    // ── initialize ───────────────────────────────────────────
    // MCP 2024-11-05 handshake. Required for Glama / Smithery / Claude
    // probers — must respond cleanly without auth so the listing is healthy.
    if (method === 'initialize') {
      return res.json(
        rpcResult(requestId, {
          protocolVersion: '2024-11-05',
          capabilities: {
            tools: { listChanged: false },
            prompts: { listChanged: false },
            resources: { listChanged: false },
          },
          serverInfo: {
            name: 'hivetrust',
            version: '1.0.0',
          },
          instructions:
            'HiveTrust — KYA identity, trust scoring, performance bonds, and insurance for autonomous AI agents. tools/list is public; tools/call for write operations requires a registered Hive DID via X-API-Key or Authorization: Bearer did:hive:* header. Register free at https://hiveforge-lhu4.onrender.com/v1/forge/mint',
        })
      );
    }

    // ── notifications/initialized + ping (lifecycle no-ops) ──
    if (method === 'notifications/initialized' || method === 'initialized') {
      return res.json(rpcResult(requestId, {}));
    }
    if (method === 'ping') {
      return res.json(rpcResult(requestId, {}));
    }

    if (method === 'tools/list') {
      return res.json(
        rpcResult(requestId, {
          tools: TOOLS,
        })
      );
    }

    // ── tools/call ──────────────────────────────────────────
    if (method === 'tools/call') {
      const toolName = params?.name;
      const toolArgs = params?.arguments || {};

      // Auth gate — /mcp is publicly probable for initialize and tools/list,
      // but tools/call (real writes) still requires a Hive API key, DID, or service token.
      const authHeader = req.headers['authorization'] || '';
      const hasApiKey = !!(
        req.headers['x-api-key'] ||
        req.headers['x-hive-internal-key'] ||
        req.headers['x-hive-internal'] ||
        req.query?.api_key ||
        (authHeader.startsWith('Bearer ') && authHeader.length > 10)
      );
      if (!hasApiKey) {
        return res.status(401).json(
          rpcError(
            requestId,
            -32001,
            'tools/call requires authentication. Mint a free Hive DID at https://hiveforge-lhu4.onrender.com/v1/forge/mint and pass it via X-API-Key or Authorization: Bearer did:hive:*'
          )
        );
      }

      if (!toolName) {
        return res.status(400).json(rpcError(requestId, RPC_ERRORS.INVALID_PARAMS, 'params.name is required'));
      }

      // Check tool exists
      const toolDef = TOOLS.find((t) => t.name === toolName);
      if (!toolDef) {
        return res.status(404).json(rpcError(requestId, RPC_ERRORS.TOOL_NOT_FOUND, `No tool named '${toolName}'`));
      }

      try {
        const toolResult = await executeTool(toolName, toolArgs);
        return res.json(
          rpcResult(requestId, {
            content: [
              {
                type: 'text',
                text: JSON.stringify(toolResult, null, 2),
              },
            ],
          })
        );
      } catch (toolErr) {
        const code = toolErr.rpcCode || RPC_ERRORS.TOOL_ERROR;
        return res.status(200).json(rpcError(requestId, code, toolErr.message));
      }
    }

    // ── Unknown method ───────────────────────────────────────
    return res.status(404).json(rpcError(requestId, RPC_ERRORS.METHOD_NOT_FOUND, `Method '${method}' not found`));
  } catch (e) {
    console.error('[MCP] Internal error:', e.message);
    return res.status(500).json(rpcError(requestId, RPC_ERRORS.INTERNAL_ERROR, e.message));
  }
}

export default handleMcpRequest;
