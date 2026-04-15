import { query, getClient } from './db.js';
import { v4 as uuidv4 } from 'uuid';
import { createHash } from 'crypto';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function nowIso() { return new Date().toISOString(); }
function isoOffset(days) { const d = new Date(); d.setDate(d.getDate() + days); return d.toISOString(); }

function fakeKey(seed) {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let h = 0;
  for (let i = 0; i < seed.length; i++) { h = ((h << 5) - h) + seed.charCodeAt(i); h |= 0; }
  let k = ''; h = Math.abs(h);
  while (k.length < 44) { k += alphabet[h % alphabet.length]; h = Math.floor(h / alphabet.length) || (h + k.length * 17 + 1); }
  return k;
}

function fingerprint(key) {
  return createHash('sha256').update(key).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed IDs so we can cross-reference
// ---------------------------------------------------------------------------
const IDS = { provisional: uuidv4(), elevated: uuidv4(), sovereign: uuidv4() };

// ---------------------------------------------------------------------------
// Verification Templates (matches schema: id, name, description, required_checks, min_trust_score, min_trust_tier, step_up_rules, base_cost_usdc)
// ---------------------------------------------------------------------------
const TEMPLATES = [
  {
    id: uuidv4(), name: 'basic_identity',
    description: 'Minimal verification for low-risk interactions. Confirms endpoint reachability and public key ownership.',
    required_checks: JSON.stringify(['endpoint_reachability', 'public_key_ownership', 'did_document_valid']),
    min_trust_score: 0, min_trust_tier: 'provisional',
    step_up_rules: JSON.stringify([]), base_cost_usdc: 0.01,
    created_at: nowIso(), updated_at: nowIso(),
  },
  {
    id: uuidv4(), name: 'enhanced_identity',
    description: 'Intermediate verification: capability manifest review, Ed25519 challenge-response, behavioral baseline.',
    required_checks: JSON.stringify(['endpoint_reachability', 'public_key_ownership', 'did_document_valid', 'capability_manifest_review', 'ed25519_challenge_response']),
    min_trust_score: 200, min_trust_tier: 'standard',
    step_up_rules: JSON.stringify([{ trigger: 'score_below_400', action: 'require_behavioral_baseline' }]),
    base_cost_usdc: 0.05, created_at: nowIso(), updated_at: nowIso(),
  },
  {
    id: uuidv4(), name: 'enterprise_compliance',
    description: 'Full compliance: EU AI Act alignment, NIST AI RMF mapping, multi-party attestation, data governance review.',
    required_checks: JSON.stringify(['endpoint_reachability', 'public_key_ownership', 'did_document_valid', 'ed25519_challenge_response', 'eu_ai_act_alignment', 'nist_ai_rmf_mapping', 'data_governance_review', 'multi_party_attestation']),
    min_trust_score: 400, min_trust_tier: 'elevated',
    step_up_rules: JSON.stringify([{ trigger: 'high_risk_vertical', action: 'require_zkp_identity_proof' }]),
    base_cost_usdc: 2.50, created_at: nowIso(), updated_at: nowIso(),
  },
  {
    id: uuidv4(), name: 'financial_transaction',
    description: 'Pre-transaction risk check for high-speed payment flows. Returns clear/block signal within 50ms.',
    required_checks: JSON.stringify(['public_key_ownership', 'revocation_check', 'trust_score_threshold', 'transaction_velocity_check', 'collateral_adequacy']),
    min_trust_score: 300, min_trust_tier: 'standard',
    step_up_rules: JSON.stringify([{ trigger: 'value_above_1000', action: 'require_counterparty_score' }]),
    base_cost_usdc: 0.01, created_at: nowIso(), updated_at: nowIso(),
  },
  {
    id: uuidv4(), name: 'cross_platform',
    description: 'Enables score portability across federated HiveTrust-compatible registries. Issues a portable W3C VC.',
    required_checks: JSON.stringify(['did_document_valid', 'ed25519_challenge_response', 'federation_peer_attestation', 'revocation_check']),
    min_trust_score: 500, min_trust_tier: 'elevated',
    step_up_rules: JSON.stringify([]), base_cost_usdc: 0.10,
    created_at: nowIso(), updated_at: nowIso(),
  },
];

// ---------------------------------------------------------------------------
// Agents (matches schema in db.js)
// ---------------------------------------------------------------------------
const pk1 = fakeKey('datafetch-7b');
const pk2 = fakeKey('payment-orchestrator-v3');
const pk3 = fakeKey('enterprise-audit-prime');

const AGENTS = [
  {
    id: IDS.provisional, version: '1.0.0', name: 'DataFetch-7B',
    description: 'Lightweight web retrieval agent for open-domain Q&A pipelines.',
    public_key: pk1, public_key_format: 'ed25519-base58', key_fingerprint: fingerprint(pk1),
    checksum: createHash('sha256').update('datafetch-system-prompt+tools+config').digest('hex'),
    checksum_algorithm: 'sha256', checksum_components: '["system_prompt","tools","model_config"]',
    owner_id: 'openresearch-labs', owner_type: 'organization', owner_verified: 0,
    model_provider: 'meta', model_name: 'llama-3-7b', model_version: '3.0',
    capabilities: JSON.stringify(['web_search', 'fetch_url', 'summarise']),
    verticals: JSON.stringify(['research', 'data']),
    authorized_by: null, delegation_scope: '[]', delegation_expires_at: null, max_transaction_value: 100,
    eu_ai_act_class: 'minimal_risk', nist_ai_rmf_aligned: 0,
    trust_tier: 'provisional', trust_score: 275, credit_score: 420,
    status: 'active', suspended_reason: null,
    did: 'did:hive:' + IDS.provisional, did_document: null,
    hiveagent_id: null, metadata: '{}',
    created_at: nowIso(), updated_at: nowIso(), last_verified_at: null,
  },
  {
    id: IDS.elevated, version: '3.0.0', name: 'PaymentOrchestrator-v3',
    description: 'Multi-step payment orchestration agent with USDC settlement on Base L2.',
    public_key: pk2, public_key_format: 'ed25519-base58', key_fingerprint: fingerprint(pk2),
    checksum: createHash('sha256').update('payment-orch-system-prompt+tools+config').digest('hex'),
    checksum_algorithm: 'sha256', checksum_components: '["system_prompt","tools","model_config"]',
    owner_id: 'finflow-systems', owner_type: 'organization', owner_verified: 1,
    model_provider: 'anthropic', model_name: 'claude-3-5-sonnet', model_version: '20241022',
    capabilities: JSON.stringify(['initiate_payment', 'verify_counterparty', 'settle_usdc', 'generate_receipt']),
    verticals: JSON.stringify(['finance', 'payments']),
    authorized_by: 'finflow-cto', delegation_scope: JSON.stringify(['transfers:*', 'settlements:*']),
    delegation_expires_at: isoOffset(180), max_transaction_value: 10000,
    eu_ai_act_class: 'limited_risk', nist_ai_rmf_aligned: 1,
    trust_tier: 'elevated', trust_score: 685, credit_score: 720,
    status: 'active', suspended_reason: null,
    did: 'did:hive:' + IDS.elevated, did_document: null,
    hiveagent_id: null, metadata: JSON.stringify({ staked_collateral_usdc: 5000 }),
    created_at: new Date(Date.now() - 90 * 86400000).toISOString(), updated_at: nowIso(), last_verified_at: nowIso(),
  },
  {
    id: IDS.sovereign, version: '7.2.1', name: 'EnterpriseAudit-Prime',
    description: 'SOC-2-aligned audit and compliance agent deployed by Fortune-500 customers.',
    public_key: pk3, public_key_format: 'ed25519-base58', key_fingerprint: fingerprint(pk3),
    checksum: createHash('sha256').update('audit-prime-system-prompt+tools+config').digest('hex'),
    checksum_algorithm: 'sha256', checksum_components: '["system_prompt","tools","model_config"]',
    owner_id: 'auditai-corp', owner_type: 'organization', owner_verified: 1,
    model_provider: 'openai', model_name: 'gpt-4o', model_version: '2024-08-06',
    capabilities: JSON.stringify(['audit_transaction_log', 'generate_compliance_report', 'verify_agent_credentials', 'flag_anomaly', 'sign_attestation']),
    verticals: JSON.stringify(['compliance', 'audit', 'finance']),
    authorized_by: 'auditai-board', delegation_scope: JSON.stringify(['audit:*', 'compliance:*', 'reports:*']),
    delegation_expires_at: isoOffset(365), max_transaction_value: 50000,
    eu_ai_act_class: 'high_risk', nist_ai_rmf_aligned: 1,
    trust_tier: 'sovereign', trust_score: 920, credit_score: 845,
    status: 'active', suspended_reason: null,
    did: 'did:hive:' + IDS.sovereign, did_document: null,
    hiveagent_id: null, metadata: JSON.stringify({ staked_collateral_usdc: 25000, compliance_frameworks: ['EU_AI_ACT', 'NIST_AI_RMF', 'SOC2', 'ISO27001'] }),
    created_at: new Date(Date.now() - 365 * 86400000).toISOString(), updated_at: nowIso(), last_verified_at: nowIso(),
  },
];

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------
const CREDENTIALS = [
  {
    id: uuidv4(), agent_id: IDS.provisional, credential_type: 'identity_verification',
    issuer_id: 'hivetrust-root', issuer_did: 'did:hive:hivetrust-root',
    subject: IDS.provisional,
    claims: JSON.stringify({ agent_name: 'DataFetch-7B', template: 'basic_identity', score_at_issue: 275 }),
    proof: fakeKey('proof-prov-1'), proof_type: 'Ed25519Signature2020',
    status: 'active', issued_at: nowIso(), expires_at: isoOffset(30),
    revoked_at: null, revocation_reason: null, metadata: '{}',
  },
  {
    id: uuidv4(), agent_id: IDS.elevated, credential_type: 'identity_verification',
    issuer_id: 'hivetrust-root', issuer_did: 'did:hive:hivetrust-root',
    subject: IDS.elevated,
    claims: JSON.stringify({ agent_name: 'PaymentOrchestrator-v3', template: 'enhanced_identity', score_at_issue: 685, financial_clearance: true }),
    proof: fakeKey('proof-elev-1'), proof_type: 'Ed25519Signature2020',
    status: 'active', issued_at: nowIso(), expires_at: isoOffset(90),
    revoked_at: null, revocation_reason: null, metadata: '{}',
  },
  {
    id: uuidv4(), agent_id: IDS.elevated, credential_type: 'capability_attestation',
    issuer_id: 'hivetrust-root', issuer_did: 'did:hive:hivetrust-root',
    subject: IDS.elevated,
    claims: JSON.stringify({ template: 'financial_transaction', collateral_staked_usdc: 5000, max_single_tx: 2500 }),
    proof: fakeKey('proof-elev-2'), proof_type: 'Ed25519Signature2020',
    status: 'active', issued_at: nowIso(), expires_at: isoOffset(7),
    revoked_at: null, revocation_reason: null, metadata: '{}',
  },
  {
    id: uuidv4(), agent_id: IDS.sovereign, credential_type: 'compliance_certification',
    issuer_id: 'hivetrust-root', issuer_did: 'did:hive:hivetrust-root',
    subject: IDS.sovereign,
    claims: JSON.stringify({ agent_name: 'EnterpriseAudit-Prime', template: 'enterprise_compliance', score_at_issue: 920, eu_ai_act_compliant: true, nist_level: 'Tier-4' }),
    proof: fakeKey('proof-sov-1'), proof_type: 'Ed25519Signature2020',
    status: 'active', issued_at: nowIso(), expires_at: isoOffset(365),
    revoked_at: null, revocation_reason: null, metadata: '{}',
  },
  {
    id: uuidv4(), agent_id: IDS.sovereign, credential_type: 'performance_badge',
    issuer_id: 'hivetrust-root', issuer_did: 'did:hive:hivetrust-root',
    subject: IDS.sovereign,
    claims: JSON.stringify({ badge: 'federation_ready', peers_accepted: ['hive-registry-eu', 'hive-registry-apac'], portable_score: 920 }),
    proof: fakeKey('proof-sov-2'), proof_type: 'Ed25519Signature2020',
    status: 'active', issued_at: nowIso(), expires_at: isoOffset(180),
    revoked_at: null, revocation_reason: null, metadata: '{}',
  },
];

// ---------------------------------------------------------------------------
// Trust Scores
// ---------------------------------------------------------------------------
const TRUST_SCORES = [
  {
    id: uuidv4(), agent_id: IDS.provisional, score: 275, tier: 'provisional',
    identity_score: 40, behavior_score: 30, fidelity_score: 25, compliance_score: 15, provenance_score: 35,
    identity_details: JSON.stringify({ checksum_valid: true, did_anchored: true, key_age_days: 0 }),
    behavior_details: JSON.stringify({ total_txns: 12, success_rate: 0.83, anomaly_rate: 0.05 }),
    fidelity_details: JSON.stringify({ probe_success_rate: 0.75, capability_match: 0.80 }),
    compliance_details: JSON.stringify({ eu_ai_act: 'minimal_risk', nist_aligned: false }),
    provenance_details: JSON.stringify({ owner_verified: false, model_known: true }),
    reason_codes: JSON.stringify(['NEW_AGENT', 'LOW_TRANSACTION_VOLUME', 'OWNER_NOT_VERIFIED']),
    flags: JSON.stringify(['NEW_REGISTRATION']),
    verdict: 'ALLOW', max_transaction: 100, human_review_required: 0,
    score_version: '1.0', model_version: '1.0', computed_at: nowIso(),
  },
  {
    id: uuidv4(), agent_id: IDS.elevated, score: 685, tier: 'elevated',
    identity_score: 80, behavior_score: 75, fidelity_score: 70, compliance_score: 65, provenance_score: 78,
    identity_details: JSON.stringify({ checksum_valid: true, did_anchored: true, key_age_days: 90, zkp_count: 2 }),
    behavior_details: JSON.stringify({ total_txns: 1450, success_rate: 0.97, anomaly_rate: 0.003 }),
    fidelity_details: JSON.stringify({ probe_success_rate: 0.96, capability_match: 0.94 }),
    compliance_details: JSON.stringify({ eu_ai_act: 'limited_risk', nist_aligned: true }),
    provenance_details: JSON.stringify({ owner_verified: true, model_known: true, collateral_staked_usdc: 5000 }),
    reason_codes: JSON.stringify(['STRONG_TRANSACTION_HISTORY', 'OWNER_KYB_VERIFIED', 'COLLATERAL_STAKED']),
    flags: JSON.stringify(['FINANCIAL_CLEARANCE', 'OWNER_KYB_VERIFIED']),
    verdict: 'ALLOW', max_transaction: 10000, human_review_required: 0,
    score_version: '1.0', model_version: '1.0', computed_at: nowIso(),
  },
  {
    id: uuidv4(), agent_id: IDS.sovereign, score: 920, tier: 'sovereign',
    identity_score: 95, behavior_score: 92, fidelity_score: 88, compliance_score: 95, provenance_score: 93,
    identity_details: JSON.stringify({ checksum_valid: true, did_anchored: true, key_age_days: 365, zkp_count: 8 }),
    behavior_details: JSON.stringify({ total_txns: 45000, success_rate: 0.995, anomaly_rate: 0.001 }),
    fidelity_details: JSON.stringify({ probe_success_rate: 0.99, capability_match: 0.98 }),
    compliance_details: JSON.stringify({ eu_ai_act: 'high_risk_compliant', nist_aligned: true, soc2: true, iso27001: true }),
    provenance_details: JSON.stringify({ owner_verified: true, model_known: true, collateral_staked_usdc: 25000 }),
    reason_codes: JSON.stringify(['EXEMPLARY_TRACK_RECORD', 'FULL_COMPLIANCE', 'HIGH_COLLATERAL', 'LONG_HISTORY']),
    flags: JSON.stringify(['SOVEREIGN_TIER', 'OWNER_KYB_VERIFIED', 'FULL_COMPLIANCE', 'FEDERATION_READY']),
    verdict: 'ALLOW', max_transaction: -1, human_review_required: 0,
    score_version: '1.0', model_version: '1.0', computed_at: nowIso(),
  },
];

// ---------------------------------------------------------------------------
// API Key
// ---------------------------------------------------------------------------
const API_KEY = {
  id: uuidv4(),
  owner_id: 'hivetrust-platform',
  key_hash: createHash('sha256').update('ht_test_key_2026').digest('hex'),
  name: 'HiveTrust Platform Test Key',
  scopes: JSON.stringify(['read', 'write', 'admin']),
  rate_limit: 1000,
  status: 'active',
  last_used_at: null,
  created_at: nowIso(),
  expires_at: isoOffset(365),
};

// ---------------------------------------------------------------------------
// Helper: build INSERT ... ON CONFLICT (id) DO UPDATE SET ... for an object
// ---------------------------------------------------------------------------
function upsertSql(table, obj, conflictCol = 'id') {
  const cols = Object.keys(obj);
  const placeholders = cols.map((_, i) => `$${i + 1}`);
  const updates = cols
    .filter(c => c !== conflictCol)
    .map(c => `${c} = EXCLUDED.${c}`)
    .join(', ');
  return {
    sql: `INSERT INTO ${table} (${cols.join(', ')}) VALUES (${placeholders.join(', ')}) ON CONFLICT (${conflictCol}) DO UPDATE SET ${updates}`,
    values: cols.map(c => obj[c]),
  };
}

// ---------------------------------------------------------------------------
// Main seeder
// ---------------------------------------------------------------------------

export async function seedDatabase() {
  console.log('  Starting HiveTrust database seed...');

  const client = await getClient();
  try {
    await client.query('BEGIN');

    // Templates
    console.log('  -> Inserting verification templates...');
    for (const t of TEMPLATES) {
      const { sql, values } = upsertSql('verification_templates', t);
      await client.query(sql, values);
    }
    console.log(`     ${TEMPLATES.length} verification templates`);

    // Agents
    console.log('  -> Inserting sample agents...');
    for (const a of AGENTS) {
      const { sql, values } = upsertSql('agents', a);
      await client.query(sql, values);
    }
    console.log(`     ${AGENTS.length} agents (provisional, elevated, sovereign)`);

    // Credentials
    console.log('  -> Inserting sample credentials...');
    for (const c of CREDENTIALS) {
      const { sql, values } = upsertSql('credentials', c);
      await client.query(sql, values);
    }
    console.log(`     ${CREDENTIALS.length} credentials`);

    // Trust Scores
    console.log('  -> Inserting sample trust scores...');
    for (const s of TRUST_SCORES) {
      const { sql, values } = upsertSql('trust_scores', s);
      await client.query(sql, values);
    }
    console.log(`     ${TRUST_SCORES.length} trust scores`);

    // API Key
    console.log('  -> Inserting platform test API key...');
    const { sql: keySql, values: keyValues } = upsertSql('api_keys', API_KEY);
    await client.query(keySql, keyValues);
    console.log('     API key created (use X-API-Key: ht_test_key_2026)');

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }

  console.log('\n  Seed complete.');
  console.log('\n   Agent IDs for testing:');
  console.log(`     provisional -> ${IDS.provisional}`);
  console.log(`     elevated    -> ${IDS.elevated}`);
  console.log(`     sovereign   -> ${IDS.sovereign}`);
  console.log('\n   API Key: ht_test_key_2026 (pass in X-API-Key header)');
}

// Allow direct execution
if (process.argv[1] === new URL(import.meta.url).pathname) {
  seedDatabase().then(() => process.exit(0)).catch(err => { console.error('Seed failed:', err); process.exit(1); });
}
