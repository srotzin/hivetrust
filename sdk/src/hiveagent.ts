import { BaseClient, BaseClientConfig } from './client';
import { HiveResponse } from './types';

/**
 * HiveAgent client — stub for future autonomous-agent runtime APIs.
 *
 * HiveAgent will provide endpoints for agent task execution, tool
 * orchestration, and inter-agent communication. Methods will be added
 * as the platform API stabilises.
 */
export class HiveAgentClient extends BaseClient {
  constructor(config: BaseClientConfig) {
    super(config);
  }

  /** Health-check / ping — GET /v1/health */
  health(): Promise<HiveResponse<{ status: string }>> {
    return this.get<{ status: string }>('/v1/health');
  }
}
