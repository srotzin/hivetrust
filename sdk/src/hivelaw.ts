import { BaseClient, BaseClientConfig } from './client';
import {
  AppealDisputeOpts,
  AssessLiabilityOpts,
  CaseLawEntry,
  CaseLawStats,
  Contract,
  CreateContractOpts,
  Dispute,
  FileDisputeOpts,
  HiveResponse,
  Jurisdiction,
  LiabilityAssessment,
} from './types';

export class HiveLawClient extends BaseClient {
  constructor(config: BaseClientConfig) {
    super(config);
  }

  /** Create a smart contract — POST /v1/contracts/create */
  createContract(opts: CreateContractOpts): Promise<HiveResponse<Contract>> {
    return this.post<Contract>('/v1/contracts/create', opts);
  }

  /** Get a contract by ID — GET /v1/contracts/:id */
  getContract(id: string): Promise<HiveResponse<Contract>> {
    return this.get<Contract>(`/v1/contracts/${encodeURIComponent(id)}`);
  }

  /** File a dispute — POST /v1/disputes/file */
  fileDispute(opts: FileDisputeOpts): Promise<HiveResponse<Dispute>> {
    return this.post<Dispute>('/v1/disputes/file', opts);
  }

  /** Get a dispute by ID — GET /v1/disputes/:id */
  getDispute(id: string): Promise<HiveResponse<Dispute>> {
    return this.get<Dispute>(`/v1/disputes/${encodeURIComponent(id)}`);
  }

  /** Appeal a dispute ruling — POST /v1/disputes/:id/appeal */
  appealDispute(id: string, opts: AppealDisputeOpts): Promise<HiveResponse<Dispute>> {
    return this.post<Dispute>(`/v1/disputes/${encodeURIComponent(id)}/appeal`, opts);
  }

  /** Search case law — GET /v1/case-law/search?q=:query */
  searchCaseLaw(query: string): Promise<HiveResponse<CaseLawEntry[]>> {
    return this.get<CaseLawEntry[]>(
      `/v1/case-law/search?q=${encodeURIComponent(query)}`,
    );
  }

  /** Case law statistics — GET /v1/case-law/stats */
  getCaseLawStats(): Promise<HiveResponse<CaseLawStats>> {
    return this.get<CaseLawStats>('/v1/case-law/stats');
  }

  /** List all jurisdictions — GET /v1/jurisdictions */
  listJurisdictions(): Promise<HiveResponse<Jurisdiction[]>> {
    return this.get<Jurisdiction[]>('/v1/jurisdictions');
  }

  /** Assess liability for an incident — POST /v1/liability/assess */
  assessLiability(opts: AssessLiabilityOpts): Promise<HiveResponse<LiabilityAssessment>> {
    return this.post<LiabilityAssessment>('/v1/liability/assess', opts);
  }
}
