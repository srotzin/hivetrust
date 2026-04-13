/**
 * HiveTrust — Platform Statistics Service
 * Aggregates platform-wide metrics for the /v1/stats endpoint and MCP tool.
 */

import db from '../db.js';

/**
 * Retrieve platform-wide statistics.
 */
export function getPlatformStats() {
  const totalAgents = db.prepare('SELECT COUNT(*) as count FROM agents').get().count;
  const activeAgents = db.prepare("SELECT COUNT(*) as count FROM agents WHERE status = 'active'").get().count;

  const tierCounts = db
    .prepare(`
      SELECT trust_tier, COUNT(*) as count
      FROM agents
      GROUP BY trust_tier
    `)
    .all()
    .reduce((acc, row) => {
      acc[row.trust_tier] = row.count;
      return acc;
    }, {});

  const avgScore = db
    .prepare('SELECT AVG(trust_score) as avg FROM agents WHERE trust_score IS NOT NULL')
    .get().avg || 0;

  const totalCredentials = db.prepare('SELECT COUNT(*) as count FROM credentials').get().count;
  const activeCredentials = db
    .prepare("SELECT COUNT(*) as count FROM credentials WHERE status = 'active'")
    .get().count;

  const totalPolicies = db.prepare('SELECT COUNT(*) as count FROM insurance_policies').get().count;
  const activePolicies = db
    .prepare("SELECT COUNT(*) as count FROM insurance_policies WHERE status = 'active'")
    .get().count;

  const totalInsuredValue = db
    .prepare("SELECT COALESCE(SUM(coverage_amount_usdc), 0) as total FROM insurance_policies WHERE status = 'active'")
    .get().total;

  const totalClaims = db.prepare('SELECT COUNT(*) as count FROM insurance_claims').get().count;
  const pendingClaims = db
    .prepare("SELECT COUNT(*) as count FROM insurance_claims WHERE status = 'filed'")
    .get().count;

  const totalDisputes = db.prepare('SELECT COUNT(*) as count FROM disputes').get().count;
  const openDisputes = db
    .prepare("SELECT COUNT(*) as count FROM disputes WHERE status = 'open'")
    .get().count;

  const totalEvents = db.prepare('SELECT COUNT(*) as count FROM behavioral_events').get().count;

  const federationPeers = db
    .prepare("SELECT COUNT(*) as count FROM federation_peers WHERE status = 'active'")
    .get().count;

  return {
    agents: {
      total: totalAgents,
      active: activeAgents,
      by_tier: tierCounts,
      avg_trust_score: parseFloat(avgScore.toFixed(2)),
    },
    credentials: {
      total: totalCredentials,
      active: activeCredentials,
    },
    insurance: {
      total_policies: totalPolicies,
      active_policies: activePolicies,
      total_insured_value_usdc: parseFloat(totalInsuredValue.toFixed(6)),
      total_claims: totalClaims,
      pending_claims: pendingClaims,
    },
    disputes: {
      total: totalDisputes,
      open: openDisputes,
    },
    telemetry: {
      total_events: totalEvents,
    },
    federation: {
      active_peers: federationPeers,
    },
    computed_at: new Date().toISOString(),
  };
}
