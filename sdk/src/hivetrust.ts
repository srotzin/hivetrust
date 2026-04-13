import { BaseClient, BaseClientConfig } from './client';
import {
  Agent,
  HiveResponse,
  PlatformStats,
  RegisterAgentOpts,
  RiskVerification,
  TrustScore,
} from './types';

export class HiveTrustClient extends BaseClient {
  constructor(config: BaseClientConfig) {
    super(config);
  }

  /** Register a new agent — POST /v1/agents */
  registerAgent(opts: RegisterAgentOpts): Promise<HiveResponse<Agent>> {
    return this.post<Agent>('/v1/agents', opts);
  }

  /** Get an agent by ID or DID — GET /v1/agents/:id */
  getAgent(id: string): Promise<HiveResponse<Agent>> {
    return this.get<Agent>(`/v1/agents/${encodeURIComponent(id)}`);
  }

  /** Get the current trust score for an agent — GET /v1/agents/:id/score */
  getTrustScore(id: string): Promise<HiveResponse<TrustScore>> {
    return this.get<TrustScore>(`/v1/agents/${encodeURIComponent(id)}/score`);
  }

  /** Public risk-verification endpoint — GET /v1/verify_agent_risk?agent_id=:id */
  verifyRisk(agentId: string): Promise<HiveResponse<RiskVerification>> {
    return this.get<RiskVerification>(
      `/v1/verify_agent_risk?agent_id=${encodeURIComponent(agentId)}`,
    );
  }

  /** Platform-wide statistics — GET /v1/stats */
  getStats(): Promise<HiveResponse<PlatformStats>> {
    return this.get<PlatformStats>('/v1/stats');
  }
}
