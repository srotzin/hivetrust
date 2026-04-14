/**
 * HiveTrust — Database Layer
 * SQLite with WAL mode, foreign keys enforced.
 * Compatible with HiveAgent's database patterns.
 */

import Database from 'better-sqlite3';
import { existsSync } from 'fs';

const DB_PATH = process.env.HIVETRUST_DB_PATH || './data/hivetrust.db';

const db = new Database(DB_PATH);

// Performance & integrity settings (match HiveAgent)
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

// ─── Core Schema ─────────────────────────────────────────────

db.exec(`
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
    max_transaction_value REAL,
    
    -- Compliance
    eu_ai_act_class TEXT DEFAULT 'minimal_risk',
    nist_ai_rmf_aligned INTEGER DEFAULT 0,
    
    -- Trust state
    trust_tier TEXT DEFAULT 'provisional',
    trust_score REAL DEFAULT 50.0,
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
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    last_verified_at TEXT,
    
    -- Indexes for HiveAgent cross-reference
    UNIQUE(key_fingerprint),
    UNIQUE(did)
  );

  -- Agent Version History: Track every identity change
  CREATE TABLE IF NOT EXISTS agent_versions (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    version TEXT NOT NULL,
    checksum TEXT,
    checksum_previous TEXT,
    changes TEXT DEFAULT '{}',
    created_at TEXT DEFAULT (datetime('now')),
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
    issued_at TEXT DEFAULT (datetime('now')),
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
    revoked_at TEXT DEFAULT (datetime('now')),
    on_chain_tx TEXT,
    FOREIGN KEY (credential_id) REFERENCES credentials(id)
  );

  -- Trust Score: Multi-pillar scoring engine
  CREATE TABLE IF NOT EXISTS trust_scores (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    
    -- Composite
    score REAL NOT NULL,
    tier TEXT NOT NULL,
    
    -- Pillars (0-100 each)
    identity_score REAL DEFAULT 50.0,
    behavior_score REAL DEFAULT 50.0,
    fidelity_score REAL DEFAULT 50.0,
    compliance_score REAL DEFAULT 50.0,
    provenance_score REAL DEFAULT 50.0,
    
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
    max_transaction REAL DEFAULT -1,
    human_review_required INTEGER DEFAULT 0,
    
    -- Versioning
    score_version TEXT DEFAULT '1.0',
    model_version TEXT DEFAULT '1.0',
    
    computed_at TEXT DEFAULT (datetime('now')),
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
    transaction_value REAL,
    
    -- Scoring impact
    score_impact REAL DEFAULT 0,
    pillar_affected TEXT,
    
    -- Evidence
    evidence TEXT DEFAULT '{}',
    signature TEXT,
    
    -- Metadata
    metadata TEXT DEFAULT '{}',
    created_at TEXT DEFAULT (datetime('now')),
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
    confidence REAL,
    reason_codes TEXT DEFAULT '[]',
    
    -- Timing
    created_at TEXT DEFAULT (datetime('now')),
    completed_at TEXT,
    expires_at TEXT,
    
    -- Cost
    cost_usdc REAL DEFAULT 0,
    
    FOREIGN KEY (agent_id) REFERENCES agents(id)
  );

  -- Verification Templates: Define what must be verified per use case
  CREATE TABLE IF NOT EXISTS verification_templates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    
    -- Requirements
    required_checks TEXT DEFAULT '[]',
    min_trust_score REAL DEFAULT 0,
    min_trust_tier TEXT DEFAULT 'provisional',
    
    -- Step-up rules
    step_up_rules TEXT DEFAULT '[]',
    
    -- Cost
    base_cost_usdc REAL DEFAULT 0.10,
    
    -- Metadata
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  );

  -- Insurance Policies: Agent insurance / bonding
  CREATE TABLE IF NOT EXISTS insurance_policies (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    policy_type TEXT NOT NULL,
    
    -- Coverage
    coverage_amount_usdc REAL NOT NULL,
    premium_usdc REAL NOT NULL,
    deductible_usdc REAL DEFAULT 0,
    
    -- Terms
    covered_actions TEXT DEFAULT '[]',
    exclusions TEXT DEFAULT '[]',
    max_claims INTEGER DEFAULT 3,
    claims_used INTEGER DEFAULT 0,
    
    -- Status
    status TEXT DEFAULT 'active',
    started_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT,
    cancelled_at TEXT,
    
    -- Underwriting
    underwriting_score REAL,
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
    amount_usdc REAL NOT NULL,
    description TEXT,
    evidence TEXT DEFAULT '{}',
    
    -- Resolution
    status TEXT DEFAULT 'filed',
    resolution TEXT,
    payout_usdc REAL DEFAULT 0,
    
    -- Timing
    filed_at TEXT DEFAULT (datetime('now')),
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
    filed_at TEXT DEFAULT (datetime('now')),
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
    created_at TEXT DEFAULT (datetime('now'))
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
    created_at TEXT DEFAULT (datetime('now')),
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
    created_at TEXT DEFAULT (datetime('now')),
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
    created_at TEXT DEFAULT (datetime('now'))
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
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS federation_scores (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    peer_id TEXT NOT NULL,
    remote_agent_id TEXT,
    remote_score REAL,
    remote_tier TEXT,
    weight REAL DEFAULT 1.0,
    fetched_at TEXT DEFAULT (datetime('now')),
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
    created_at TEXT DEFAULT (datetime('now'))
  );

  -- Spent Payments: Persistent payment replay protection
  CREATE TABLE IF NOT EXISTS spent_payments (
    tx_hash TEXT PRIMARY KEY,
    amount_usdc REAL NOT NULL,
    verified_at TEXT DEFAULT (datetime('now')),
    endpoint TEXT,
    did TEXT
  );

  -- Rate Limits: SQLite-backed per-key rate limiting
  CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT NOT NULL,
    window_start TEXT NOT NULL,
    request_count INTEGER DEFAULT 1,
    PRIMARY KEY (key, window_start)
  );

  -- Compliance Proofs: ViewKey Audit Rail — structural code compliance proofs
  CREATE TABLE IF NOT EXISTS compliance_proofs (
    id TEXT PRIMARY KEY DEFAULT ('proof_' || lower(hex(randomblob(8)))),
    project_id TEXT NOT NULL,
    inspector_did TEXT,
    proof_type TEXT NOT NULL,
    proof_hash TEXT NOT NULL UNIQUE,
    inputs_json TEXT,
    result_json TEXT,
    compliant BOOLEAN,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Indexes
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
`);

console.log('[HiveTrust] Database schema initialized');

export default db;
