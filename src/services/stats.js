/**
 * HiveTrust — Platform Statistics Service
 * Aggregates platform-wide metrics for the /v1/stats endpoint and MCP tool.
 */

import { query } from '../db.js';

/**
 * Retrieve platform-wide statistics.
 */
export async function getPlatformStats() {
  const totalAgentsResult = await query('SELECT COUNT(*) as count FROM agents');
  const totalAgents = totalAgentsResult.rows[0].count;

  const activeAgentsResult = await query("SELECT COUNT(*) as count FROM agents WHERE status = $1", ['active']);
  const activeAgents = activeAgentsResult.rows[0].count;

  const tierResult = await query(`
      SELECT trust_tier, COUNT(*) as count
      FROM agents
      GROUP BY trust_tier
    `);
  const tierCounts = tierResult.rows.reduce((acc, row) => {
    acc[row.trust_tier] = row.count;
    return acc;
  }, {});

  const avgScoreResult = await query('SELECT AVG(trust_score) as avg FROM agents WHERE trust_score IS NOT NULL');
  const avgScore = avgScoreResult.rows[0].avg || 0;

  const totalCredentialsResult = await query('SELECT COUNT(*) as count FROM credentials');
  const totalCredentials = totalCredentialsResult.rows[0].count;

  const activeCredentialsResult = await query("SELECT COUNT(*) as count FROM credentials WHERE status = $1", ['active']);
  const activeCredentials = activeCredentialsResult.rows[0].count;

  const totalPoliciesResult = await query('SELECT COUNT(*) as count FROM insurance_policies');
  const totalPolicies = totalPoliciesResult.rows[0].count;

  const activePoliciesResult = await query("SELECT COUNT(*) as count FROM insurance_policies WHERE status = $1", ['active']);
  const activePolicies = activePoliciesResult.rows[0].count;

  const totalInsuredValueResult = await query("SELECT COALESCE(SUM(coverage_amount_usdc), 0) as total FROM insurance_policies WHERE status = $1", ['active']);
  const totalInsuredValue = totalInsuredValueResult.rows[0].total;

  const totalClaimsResult = await query('SELECT COUNT(*) as count FROM insurance_claims');
  const totalClaims = totalClaimsResult.rows[0].count;

  const pendingClaimsResult = await query("SELECT COUNT(*) as count FROM insurance_claims WHERE status = $1", ['filed']);
  const pendingClaims = pendingClaimsResult.rows[0].count;

  const totalDisputesResult = await query('SELECT COUNT(*) as count FROM disputes');
  const totalDisputes = totalDisputesResult.rows[0].count;

  const openDisputesResult = await query("SELECT COUNT(*) as count FROM disputes WHERE status = $1", ['open']);
  const openDisputes = openDisputesResult.rows[0].count;

  const totalEventsResult = await query('SELECT COUNT(*) as count FROM behavioral_events');
  const totalEvents = totalEventsResult.rows[0].count;

  const federationPeersResult = await query("SELECT COUNT(*) as count FROM federation_peers WHERE status = $1", ['active']);
  const federationPeers = federationPeersResult.rows[0].count;

  return {
    agents: {
      total: totalAgents,
      active: activeAgents,
      by_tier: tierCounts,
      avg_trust_score: parseFloat(Number(avgScore).toFixed(2)),
    },
    credentials: {
      total: totalCredentials,
      active: activeCredentials,
    },
    insurance: {
      total_policies: totalPolicies,
      active_policies: activePolicies,
      total_insured_value_usdc: parseFloat(Number(totalInsuredValue).toFixed(6)),
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
