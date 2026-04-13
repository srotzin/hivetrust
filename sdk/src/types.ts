// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

export interface HiveClientConfig {
  hiveTrustUrl?: string;
  hiveMindUrl?: string;
  hiveForgeUrl?: string;
  hiveLawUrl?: string;
  hiveAgentUrl?: string;
  apiKey?: string;
  did?: string;
  internalKey?: string;
  timeoutMs?: number;
}

export interface HiveResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
}

// ---------------------------------------------------------------------------
// HiveTrust
// ---------------------------------------------------------------------------

export interface RegisterAgentOpts {
  name: string;
  description?: string;
  public_key?: string;
  owner_id?: string;
  owner_type?: string;
  model_provider?: string;
  model_name?: string;
  capabilities?: string[];
  verticals?: string[];
  eu_ai_act_class?: string;
  metadata?: Record<string, any>;
}

export interface Agent {
  id: string;
  did: string;
  name: string;
  description?: string;
  public_key?: string;
  checksum?: string;
  trust_score: number;
  trust_tier: string;
  status: string;
  owner_id?: string;
  owner_type?: string;
  model_provider?: string;
  model_name?: string;
  capabilities?: string[];
  verticals?: string[];
  eu_ai_act_class?: string;
  metadata?: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface TrustScore {
  id: string;
  agentId: string;
  score: number;
  tier: string;
  verdict: 'ALLOW' | 'FLAG' | 'BLOCK';
  pillars: {
    transaction: number;
    capital: number;
    centrality: number;
    identity: number;
    compliance: number;
  };
  reason_codes: string[];
  flags: string[];
  max_transaction: number;
  human_review_required: boolean;
  computed_at: string;
}

export interface RiskVerification {
  agentId: string;
  verdict: 'ALLOW' | 'FLAG' | 'BLOCK';
  score: number;
  tier: string;
  flags: string[];
  max_transaction: number;
  human_review_required: boolean;
  score_age_seconds: number;
}

export interface PlatformStats {
  agents: {
    total: number;
    active: number;
    by_tier: Record<string, number>;
    avg_trust_score: number;
  };
  credentials: { total: number; active: number };
  insurance: {
    total_policies: number;
    active_policies: number;
    total_insured_value_usdc: number;
    total_claims: number;
    pending_claims: number;
  };
  disputes: { total: number; open: number };
  telemetry: { total_events: number };
  federation: { active_peers: number };
  computed_at: string;
}

// ---------------------------------------------------------------------------
// HiveMind
// ---------------------------------------------------------------------------

export interface StoreMemoryOpts {
  agent_id: string;
  content: string;
  memory_type?: string;
  metadata?: Record<string, any>;
  tags?: string[];
}

export interface QueryMemoryOpts {
  agent_id: string;
  query: string;
  limit?: number;
  memory_type?: string;
  tags?: string[];
}

export interface MemoryNode {
  id: string;
  agent_id: string;
  content: string;
  memory_type: string;
  metadata?: Record<string, any>;
  tags?: string[];
  created_at: string;
}

export interface MemoryStats {
  total_nodes: number;
  by_type: Record<string, number>;
  storage_bytes: number;
}

export interface PublishGlobalHiveOpts {
  agent_id: string;
  content: string;
  topic?: string;
  tags?: string[];
  metadata?: Record<string, any>;
}

export interface BrowseGlobalHiveOpts {
  topic?: string;
  tags?: string[];
  limit?: number;
  offset?: number;
}

// ---------------------------------------------------------------------------
// HiveForge
// ---------------------------------------------------------------------------

export interface MintOpts {
  name: string;
  species?: string;
  traits?: Record<string, any>;
  parent_did?: string;
  metadata?: Record<string, any>;
}

export interface CrossbreedOpts {
  parent_a: string;
  parent_b: string;
  name?: string;
  metadata?: Record<string, any>;
}

export interface EvolveOpts {
  genome_id: string;
  mutation_pressure?: number;
  environment?: string;
  metadata?: Record<string, any>;
}

export interface Genome {
  id: string;
  name: string;
  species: string;
  traits: Record<string, any>;
  lineage: string[];
  generation: number;
  fitness: number;
  created_at: string;
}

export interface Census {
  total_population: number;
  by_species: Record<string, number>;
  by_generation: Record<string, number>;
  avg_fitness: number;
}

export interface Pheromone {
  id: string;
  source_id: string;
  signal_type: string;
  intensity: number;
  payload: Record<string, any>;
  emitted_at: string;
}

// ---------------------------------------------------------------------------
// HiveLaw
// ---------------------------------------------------------------------------

export interface CreateContractOpts {
  parties: string[];
  contract_type: string;
  terms: Record<string, any>;
  jurisdiction?: string;
  effective_date?: string;
  expiry_date?: string;
  metadata?: Record<string, any>;
}

export interface Contract {
  id: string;
  parties: string[];
  contract_type: string;
  terms: Record<string, any>;
  jurisdiction: string;
  status: string;
  effective_date: string;
  expiry_date?: string;
  created_at: string;
}

export interface FileDisputeOpts {
  contract_id?: string;
  complainant_id: string;
  respondent_id: string;
  dispute_type: string;
  description: string;
  evidence?: Record<string, any>;
  metadata?: Record<string, any>;
}

export interface Dispute {
  id: string;
  contract_id?: string;
  complainant_id: string;
  respondent_id: string;
  dispute_type: string;
  description: string;
  status: string;
  ruling?: string;
  created_at: string;
}

export interface AppealDisputeOpts {
  reason: string;
  new_evidence?: Record<string, any>;
}

export interface AssessLiabilityOpts {
  agent_id: string;
  incident_type: string;
  affected_parties?: string[];
  damages_estimate?: number;
  context?: Record<string, any>;
}

export interface LiabilityAssessment {
  agent_id: string;
  liability_score: number;
  risk_level: string;
  recommended_action: string;
  breakdown: Record<string, any>;
}

export interface CaseLawEntry {
  id: string;
  title: string;
  summary: string;
  ruling: string;
  jurisdiction: string;
  precedent_weight: number;
  decided_at: string;
}

export interface CaseLawStats {
  total_cases: number;
  by_jurisdiction: Record<string, number>;
  by_ruling_type: Record<string, number>;
  avg_precedent_weight: number;
}

export interface Jurisdiction {
  id: string;
  name: string;
  description: string;
  rules: Record<string, any>;
}
