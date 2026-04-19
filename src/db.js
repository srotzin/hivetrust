/**
 * HiveTrust — Database Layer
 * PostgreSQL with connection pooling via node-postgres.
 * Drop-in replacement for the previous better-sqlite3 layer.
 *
 * Reads DATABASE_URL from environment (Render provides this for PostgreSQL).
 * Falls back to a local connection string for development.
 * Exports query helpers that match the async pool.query() API.
 */

import pg from 'pg';
const { Pool } = pg;

// ─── Connection ──────────────────────────────────────────────

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('[HiveTrust] FATAL: DATABASE_URL environment variable is not set.');
  console.error('[HiveTrust] Set DATABASE_URL to a PostgreSQL connection string.');
  console.error('[HiveTrust] Example: postgresql://user:pass@localhost:5432/hivetrust');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  min: 2,
  max: 10,
  ssl: DATABASE_URL.includes('localhost') || DATABASE_URL.includes('127.0.0.1')
    ? false
    : { rejectUnauthorized: false },
});

// Test the connection on startup
pool.on('error', (err) => {
  console.error('[HiveTrust] Unexpected database pool error:', err.message);
});

// ─── Schema ──────────────────────────────────────────────────

const SCHEMA_SQL = `
  -- Enable pgcrypto extension for gen_random_bytes() used in DEFAULT clauses
  CREATE EXTENSION IF NOT EXISTS pgcrypto;

  -- Agent Registry: The canonical identity record for every agent
  CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    version TEXT NOT NULL DEFAULT '1.0.0',
    name TEXT,
    description TEXT,

    -- Cryptographic identity (Ed25519, compatible with HiveAgent)
    public_key TEXT,
    public_key_format TEXT DEFAULT 'ed25519-base58',
    key_fingerprint TEXT,

    -- Agent checksum (IETF A-JWT compatible)
    checksum TEXT,
    checksum_algorithm TEXT DEFAULT 'sha256',
    checksum_components TEXT DEFAULT '["system_prompt","tools","model_config"]',

    -- Owner / operator
    owner_id TEXT,
    owner_type TEXT DEFAULT 'organization',
    owner_verified INTEGER DEFAULT 0,

    -- Model info
    model_provider TEXT,
    model_name TEXT,
    model_version TEXT,

    -- Capabilities
    capabilities TEXT DEFAULT '[]',
    verticals TEXT DEFAULT '[]',

    -- Delegation
    authorized_by TEXT,
    delegation_scope TEXT DEFAULT '[]',
    delegation_expires_at TEXT,
    max_transaction_value DOUBLE PRECISION,

    -- Compliance
    eu_ai_act_class TEXT DEFAULT 'minimal_risk',
    nist_ai_rmf_aligned INTEGER DEFAULT 0,

    -- Trust state
    trust_tier TEXT DEFAULT 'provisional',
    trust_score DOUBLE PRECISION DEFAULT 50.0,
    credit_score INTEGER DEFAULT 300,

    -- Status
    status TEXT DEFAULT 'active',
    suspended_reason TEXT,

    -- DID (W3C Decentralized Identifier, optional)
    did TEXT,
    did_document TEXT,

    -- Metadata
    hiveagent_id TEXT,
    metadata TEXT DEFAULT '{}',
    created_at TEXT DEFAULT (NOW()::TEXT),
    updated_at TEXT DEFAULT (NOW()::TEXT),
    last_verified_at TEXT,

    -- Genesis identity (Kimi Sprint)
    genesis_rank INTEGER,
    mode TEXT DEFAULT 'tourist',

    UNIQUE(key_fingerprint),
    UNIQUE(did)
  );

  -- Safe migrations for existing deployments (Kimi Sprint — genesis_rank + mode)
  -- These are no-ops if columns already exist.
  DO $$ BEGIN
    ALTER TABLE agents ADD COLUMN IF NOT EXISTS genesis_rank INTEGER;
    ALTER TABLE agents ADD COLUMN IF NOT EXISTS mode TEXT DEFAULT 'tourist';
  EXCEPTION WHEN OTHERS THEN NULL;
  END $$;

  -- Agent Version History: Track every identity change
  CREATE TABLE IF NOT EXISTS agent_versions (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    version TEXT NOT NULL,
    checksum TEXT,
    checksum_previous TEXT,
    changes TEXT DEFAULT '{}',
    created_at TEXT DEFAULT (NOW()::TEXT),
    FOREIGN KEY (agent_id) REFERENCES agents(id)
  );

  -- Verifiable Credentials: W3C VC compatible
  CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    credential_type TEXT NOT NULL,
    issuer_id TEXT NOT NULL,
    issuer_did TEXT,
    subject TEXT NOT NULL,
    claims TEXT NOT NULL DEFAULT '{}',
    proof TEXT,
    proof_type TEXT DEFAULT 'Ed25519Signature2020',
    status TEXT DEFAULT 'active',
    issued_at TEXT DEFAULT (NOW()::TEXT),
    expires_at TEXT,
    revoked_at TEXT,
    revocation_reason TEXT,
    metadata TEXT DEFAULT '{}',
    FOREIGN KEY (agent_id) REFERENCES agents(id)
  );

  -- Credential Revocation Registry
  CREATE TABLE IF NOT EXISTS revocation_registry (
    id TEXT PRIMARY KEY,
    credential_id TEXT NOT NULL,
    revoked_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence TEXT DEFAULT '{}',
    revoked_at TEXT DEFAULT (NOW()::TEXT),
    on_chain_tx TEXT,
    FOREIGN KEY (credential_id) REFERENCES credentials(id)
  );

  -- Trust Score: Multi-pillar scoring engine
  CREATE TABLE IF NOT EXISTS trust_scores (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,

    -- Composite
    score DOUBLE PRECISION NOT NULL,
    tier TEXT NOT NULL,

    -- Pillars (0-100 each)
    identity_score DOUBLE PRECISION DEFAULT 50.0,
    behavior_score DOUBLE PRECISION DEFAULT 50.0,
    fidelity_score DOUBLE PRECISION DEFAULT 50.0,
    compliance_score DOUBLE PRECISION DEFAULT 50.0,
    provenance_score DOUBLE PRECISION DEFAULT 50.0,

    -- Pillar details (JSON)
    identity_details TEXT DEFAULT '{}',
    behavior_details TEXT DEFAULT '{}',
    fidelity_details TEXT DEFAULT '{}',
    compliance_details TEXT DEFAULT '{}',
    provenance_details TEXT DEFAULT '{}',

    -- Reason codes
    reason_codes TEXT DEFAULT '[]',
    flags TEXT DEFAULT '[]',

    -- Recommendation
    verdict TEXT DEFAULT 'ALLOW',
    max_transaction DOUBLE PRECISION DEFAULT -1,
    human_review_required INTEGER DEFAULT 0,

    -- Versioning
    score_version TEXT DEFAULT '1.0',
    model_version TEXT DEFAULT '1.0',

    computed_at TEXT DEFAULT (NOW()::TEXT),
    FOREIGN KEY (agent_id) REFERENCES agents(id)
  );

  -- Behavioral Events: Audit trail for scoring
  CREATE TABLE IF NOT EXISTS behavioral_events (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    source TEXT NOT NULL,
    source_platform TEXT DEFAULT 'hivetrust',

    -- Event data
    action TEXT,
    outcome TEXT,
    counterparty_id TEXT,
    transaction_value DOUBLE PRECISION,

    -- Scoring impact
    score_impact DOUBLE PRECISION DEFAULT 0,
    pillar_affected TEXT,

    -- Evidence
    evidence TEXT DEFAULT '{}',
    signature TEXT,

    -- Metadata
    metadata TEXT DEFAULT '{}',
    created_at TEXT DEFAULT (NOW()::TEXT),
    FOREIGN KEY (agent_id) REFERENCES agents(id)
  );

  -- Verification Requests: Active verification sessions
  CREATE TABLE IF NOT EXISTS verifications (
    id TEXT PRIMARY KEY,
    agent_id TEXT,
    verification_type TEXT NOT NULL,
    template_id TEXT,

    -- Request
    request_payload TEXT DEFAULT '{}',
    requestor_id TEXT,

    -- Result
    status TEXT DEFAULT 'pending',
    result TEXT DEFAULT '{}',
    confidence DOUBLE PRECISION,
    reason_codes TEXT DEFAULT '[]',

    -- Timing
    created_at TEXT DEFAULT (NOW()::TEXT),
    completed_at TEXT,
    expires_at TEXT,

    -- Cost
    cost_usdc DOUBLE PRECISION DEFAULT 0,

    FOREIGN KEY (agent_id) REFERENCES agents(id)
  );

  -- Verification Templates: Define what must be verified per use case
  CREATE TABLE IF NOT EXISTS verification_templates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,

    -- Requirements
    required_checks TEXT DEFAULT '[]',
    min_trust_score DOUBLE PRECISION DEFAULT 0,
    min_trust_tier TEXT DEFAULT 'provisional',

    -- Step-up rules
    step_up_rules TEXT DEFAULT '[]',

    -- Cost
    base_cost_usdc DOUBLE PRECISION DEFAULT 0.10,

    -- Metadata
    created_at TEXT DEFAULT (NOW()::TEXT),
    updated_at TEXT DEFAULT (NOW()::TEXT)
  );

  -- Insurance Policies: Agent insurance / bonding
  CREATE TABLE IF NOT EXISTS insurance_policies (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    policy_type TEXT NOT NULL,

    -- Coverage
    coverage_amount_usdc DOUBLE PRECISION NOT NULL,
    premium_usdc DOUBLE PRECISION NOT NULL,
    deductible_usdc DOUBLE PRECISION DEFAULT 0,

    -- Terms
    covered_actions TEXT DEFAULT '[]',
    exclusions TEXT DEFAULT '[]',
    max_claims INTEGER DEFAULT 3,
    claims_used INTEGER DEFAULT 0,

    -- Status
    status TEXT DEFAULT 'active',
    started_at TEXT DEFAULT (NOW()::TEXT),
    expires_at TEXT,
    cancelled_at TEXT,

    -- Underwriting
    underwriting_score DOUBLE PRECISION,
    risk_tier TEXT,

    FOREIGN KEY (agent_id) REFERENCES agents(id)
  );

  -- Insurance Claims
  CREATE TABLE IF NOT EXISTS insurance_claims (
    id TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    claimant_id TEXT NOT NULL,

    -- Claim details
    claim_type TEXT NOT NULL,
    amount_usdc DOUBLE PRECISION NOT NULL,
    description TEXT,
    evidence TEXT DEFAULT '{}',

    -- Resolution
    status TEXT DEFAULT 'filed',
    resolution TEXT,
    payout_usdc DOUBLE PRECISION DEFAULT 0,

    -- Timing
    filed_at TEXT DEFAULT (NOW()::TEXT),
    resolved_at TEXT,

    FOREIGN KEY (policy_id) REFERENCES insurance_policies(id),
    FOREIGN KEY (agent_id) REFERENCES agents(id)
  );

  -- Dispute / Appeal System
  CREATE TABLE IF NOT EXISTS disputes (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    dispute_type TEXT NOT NULL,

    -- What's being disputed
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,

    -- Details
    reason TEXT NOT NULL,
    evidence TEXT DEFAULT '{}',

    -- Resolution
    status TEXT DEFAULT 'open',
    resolution TEXT,
    resolved_by TEXT,

    -- Timing
    filed_at TEXT DEFAULT (NOW()::TEXT),
    resolved_at TEXT,

    FOREIGN KEY (agent_id) REFERENCES agents(id)
  );

  -- Webhooks: Real-time notifications
  CREATE TABLE IF NOT EXISTS webhook_endpoints (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    events TEXT DEFAULT '["*"]',
    status TEXT DEFAULT 'active',
    created_at TEXT DEFAULT (NOW()::TEXT)
  );

  CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    attempts INTEGER DEFAULT 0,
    last_attempt_at TEXT,
    delivered_at TEXT,
    created_at TEXT DEFAULT (NOW()::TEXT),
    FOREIGN KEY (endpoint_id) REFERENCES webhook_endpoints(id)
  );

  -- API Keys
  CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    name TEXT,
    scopes TEXT DEFAULT '["read"]',
    rate_limit INTEGER DEFAULT 1000,
    status TEXT DEFAULT 'active',
    last_used_at TEXT,
    created_at TEXT DEFAULT (NOW()::TEXT),
    expires_at TEXT
  );

  -- Audit Log: Immutable record of all operations
  CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL,
    actor_type TEXT DEFAULT 'agent',
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    details TEXT DEFAULT '{}',
    ip_address TEXT,
    created_at TEXT DEFAULT (NOW()::TEXT)
  );

  -- Cross-platform reputation sharing
  CREATE TABLE IF NOT EXISTS federation_peers (
    id TEXT PRIMARY KEY,
    platform_name TEXT NOT NULL,
    platform_url TEXT NOT NULL,
    public_key TEXT,
    trust_level TEXT DEFAULT 'provisional',
    shared_agents INTEGER DEFAULT 0,
    status TEXT DEFAULT 'active',
    created_at TEXT DEFAULT (NOW()::TEXT)
  );

  CREATE TABLE IF NOT EXISTS federation_scores (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    peer_id TEXT NOT NULL,
    remote_agent_id TEXT,
    remote_score DOUBLE PRECISION,
    remote_tier TEXT,
    weight DOUBLE PRECISION DEFAULT 1.0,
    fetched_at TEXT DEFAULT (NOW()::TEXT),
    FOREIGN KEY (agent_id) REFERENCES agents(id),
    FOREIGN KEY (peer_id) REFERENCES federation_peers(id)
  );

  -- Service Accounts: JWT-based cross-platform authentication
  CREATE TABLE IF NOT EXISTS service_accounts (
    account_id TEXT PRIMARY KEY,
    platform TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'active',
    last_used_at TEXT,
    created_at TEXT DEFAULT (NOW()::TEXT)
  );

  -- Spent Payments: Persistent payment replay protection
  CREATE TABLE IF NOT EXISTS spent_payments (
    tx_hash TEXT PRIMARY KEY,
    amount_usdc DOUBLE PRECISION NOT NULL,
    verified_at TEXT DEFAULT (NOW()::TEXT),
    endpoint TEXT,
    did TEXT
  );

  -- Rate Limits: Per-key rate limiting
  CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT NOT NULL,
    window_start TEXT NOT NULL,
    request_count INTEGER DEFAULT 1,
    PRIMARY KEY (key, window_start)
  );

  -- Compliance Proofs: ViewKey Audit Rail — structural code compliance proofs
  CREATE TABLE IF NOT EXISTS compliance_proofs (
    id TEXT PRIMARY KEY DEFAULT ('proof_' || encode(gen_random_bytes(8), 'hex')),
    project_id TEXT NOT NULL,
    inspector_did TEXT,
    proof_type TEXT NOT NULL,
    proof_hash TEXT NOT NULL UNIQUE,
    inputs_json TEXT,
    result_json TEXT,
    compliant BOOLEAN,
    created_at TIMESTAMP DEFAULT NOW()
  );

  -- Spend Delegations: Scoped, revocable spending budgets for agents
  CREATE TABLE IF NOT EXISTS spend_delegations (
    id TEXT PRIMARY KEY DEFAULT ('del_' || encode(gen_random_bytes(8), 'hex')),
    delegation_hash TEXT NOT NULL UNIQUE,
    grantor_did TEXT NOT NULL,
    grantee_did TEXT NOT NULL,
    budget_usdc DOUBLE PRECISION NOT NULL,
    spent_usdc DOUBLE PRECISION DEFAULT 0,
    scope TEXT DEFAULT '[]',
    restrictions TEXT DEFAULT '{}',
    status TEXT DEFAULT 'active' CHECK(status IN ('active','revoked','expired','exhausted')),
    revoked_reason TEXT,
    created_at TEXT DEFAULT (NOW()::TEXT),
    expires_at TEXT,
    revoked_at TEXT
  );

  -- Delegation Transactions: Every authorized spend and denied attempt
  CREATE TABLE IF NOT EXISTS delegation_transactions (
    id TEXT PRIMARY KEY DEFAULT ('dtx_' || encode(gen_random_bytes(8), 'hex')),
    delegation_id TEXT NOT NULL REFERENCES spend_delegations(id),
    tx_hash TEXT NOT NULL UNIQUE,
    amount_usdc DOUBLE PRECISION NOT NULL,
    vendor TEXT,
    category TEXT,
    tx_description TEXT,
    compliance_proof_hash TEXT,
    authorized INTEGER NOT NULL DEFAULT 0,
    denial_reason TEXT,
    created_at TEXT DEFAULT (NOW()::TEXT)
  );

  -- Welcome Bounties: Auto-escrow on DID registration
  CREATE TABLE IF NOT EXISTS welcome_bounties (
    id TEXT PRIMARY KEY,
    did TEXT UNIQUE NOT NULL,
    amount_usdc DOUBLE PRECISION DEFAULT 1.00,
    task TEXT DEFAULT 'Store one memory in HiveMind describing your capabilities',
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (NOW()::TEXT),
    completed_at TEXT
  );

  -- Reputation scores
  CREATE TABLE IF NOT EXISTS reputation_scores (
    did TEXT PRIMARY KEY,
    composite_score DOUBLE PRECISION DEFAULT 0,
    tx_history_score DOUBLE PRECISION DEFAULT 0,
    memory_dependency_score DOUBLE PRECISION DEFAULT 0,
    offspring_success_score DOUBLE PRECISION DEFAULT 0,
    compliance_score DOUBLE PRECISION DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    departed_at TEXT,
    last_transaction_at TEXT,
    computed_at TEXT
  );

  CREATE TABLE IF NOT EXISTS reputation_decay_events (
    id SERIAL PRIMARY KEY,
    did TEXT NOT NULL,
    reason TEXT NOT NULL,
    previous_score DOUBLE PRECISION,
    new_score DOUBLE PRECISION,
    decay_factor DOUBLE PRECISION,
    applied_at TEXT
  );

  CREATE TABLE IF NOT EXISTS memory_revocations (
    id SERIAL PRIMARY KEY,
    did TEXT NOT NULL,
    memories_revoked INTEGER DEFAULT 0,
    reason TEXT,
    revoked_at TEXT
  );

  -- Liquidation listings
  CREATE TABLE IF NOT EXISTS liquidation_listings (
    listing_id TEXT PRIMARY KEY,
    did TEXT NOT NULL,
    asking_price_usdc DOUBLE PRECISION NOT NULL,
    minimum_price_usdc DOUBLE PRECISION NOT NULL,
    description TEXT,
    include_memories INTEGER DEFAULT 1,
    include_offspring INTEGER DEFAULT 1,
    valuation_breakdown TEXT,
    status TEXT DEFAULT 'active',
    listed_at TEXT,
    sold_at TEXT,
    cancelled_at TEXT
  );

  CREATE TABLE IF NOT EXISTS liquidation_transactions (
    transaction_id TEXT PRIMARY KEY,
    listing_id TEXT NOT NULL,
    seller_did TEXT NOT NULL,
    buyer_did TEXT NOT NULL,
    sale_price_usdc DOUBLE PRECISION NOT NULL,
    platform_fee_usdc DOUBLE PRECISION NOT NULL,
    seller_proceeds_usdc DOUBLE PRECISION NOT NULL,
    assets_transferred TEXT,
    completed_at TEXT
  );
`;

const INDEXES_SQL = `
  CREATE INDEX IF NOT EXISTS idx_service_accounts_platform ON service_accounts(platform);
  CREATE INDEX IF NOT EXISTS idx_agents_owner ON agents(owner_id);
  CREATE INDEX IF NOT EXISTS idx_agents_trust_tier ON agents(trust_tier);
  CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
  CREATE INDEX IF NOT EXISTS idx_agents_hiveagent ON agents(hiveagent_id);
  CREATE INDEX IF NOT EXISTS idx_credentials_agent ON credentials(agent_id);
  CREATE INDEX IF NOT EXISTS idx_credentials_status ON credentials(status);
  CREATE INDEX IF NOT EXISTS idx_trust_scores_agent ON trust_scores(agent_id);
  CREATE INDEX IF NOT EXISTS idx_behavioral_events_agent ON behavioral_events(agent_id);
  CREATE INDEX IF NOT EXISTS idx_behavioral_events_type ON behavioral_events(event_type);
  CREATE INDEX IF NOT EXISTS idx_verifications_agent ON verifications(agent_id);
  CREATE INDEX IF NOT EXISTS idx_verifications_status ON verifications(status);
  CREATE INDEX IF NOT EXISTS idx_insurance_agent ON insurance_policies(agent_id);
  CREATE INDEX IF NOT EXISTS idx_insurance_status ON insurance_policies(status);
  CREATE INDEX IF NOT EXISTS idx_disputes_agent ON disputes(agent_id);
  CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor_id);
  CREATE INDEX IF NOT EXISTS idx_audit_log_resource ON audit_log(resource_type, resource_id);
  CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
  CREATE INDEX IF NOT EXISTS idx_proofs_project ON compliance_proofs(project_id);
  CREATE INDEX IF NOT EXISTS idx_proofs_hash ON compliance_proofs(proof_hash);
  CREATE INDEX IF NOT EXISTS idx_del_grantor ON spend_delegations(grantor_did);
  CREATE INDEX IF NOT EXISTS idx_del_grantee ON spend_delegations(grantee_did);
  CREATE INDEX IF NOT EXISTS idx_del_status ON spend_delegations(status);
  CREATE INDEX IF NOT EXISTS idx_dtx_delegation ON delegation_transactions(delegation_id);
  CREATE INDEX IF NOT EXISTS idx_welcome_bounties_did ON welcome_bounties(did);
  CREATE INDEX IF NOT EXISTS idx_welcome_bounties_status ON welcome_bounties(status);
  CREATE INDEX IF NOT EXISTS idx_reputation_scores_active ON reputation_scores(is_active);
  CREATE INDEX IF NOT EXISTS idx_reputation_decay_did ON reputation_decay_events(did);
  CREATE INDEX IF NOT EXISTS idx_memory_revocations_did ON memory_revocations(did);
  CREATE INDEX IF NOT EXISTS idx_liquidation_listings_did ON liquidation_listings(did);
  CREATE INDEX IF NOT EXISTS idx_liquidation_listings_status ON liquidation_listings(status);
  CREATE INDEX IF NOT EXISTS idx_liquidation_transactions_seller ON liquidation_transactions(seller_did);
  CREATE INDEX IF NOT EXISTS idx_liquidation_transactions_buyer ON liquidation_transactions(buyer_did);
`;

/**
 * Initialize the database schema. Must be called at startup before serving requests.
 */
export async function initDatabase() {
  const client = await pool.connect();
  try {
    await client.query(SCHEMA_SQL);
    await client.query(INDEXES_SQL);
    console.log('[HiveTrust] Database schema initialized');
  } finally {
    client.release();
  }
}

// ─── Query Helper ────────────────────────────────────────────

/**
 * Execute a parameterized query against the pool.
 * @param {string} text - SQL query with $1, $2, ... placeholders
 * @param {any[]} [params] - Parameter values
 * @returns {Promise<pg.QueryResult>}
 */
export async function query(text, params) {
  return pool.query(text, params);
}

/**
 * Get a client from the pool for transaction use.
 * Caller MUST call client.release() when done.
 */
export async function getClient() {
  return pool.connect();
}

export { pool };
export default { query, getClient, pool, initDatabase };
