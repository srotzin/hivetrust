/**
 * HiveTrust — Trust Score Service Adapter
 * Re-exports from trust-scoring.js with normalized names
 * for consumption by routes/api.js and mcp-server.js.
 */

import {
  getTrustScore,
  getScoreHistory,
  quickRiskCheck,
} from './trust-scoring.js';

export { getTrustScore };

export async function getTrustScoreHistory(agentId, { limit = 50 } = {}) {
  return getScoreHistory(agentId, limit);
}

export async function getAgentRisk(agentId) {
  return quickRiskCheck(agentId);
}
