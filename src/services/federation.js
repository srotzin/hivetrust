/**
 * HiveTrust — Federation Service
 * Cross-platform reputation sharing between HiveTrust instances and compatible platforms.
 *
 * Protocol:
 *  - Peers register with their public key for request verification
 *  - Score sync via HTTP GET to peer's /.well-known/hivetrust.json discovery
 *    then GET /v1/federation/scores?agentIds=...
 *  - Federated scores are stored locally and averaged into getFederatedScore()
 */

import db from '../db.js';
import { v4 as uuidv4 } from 'uuid';
import * as audit from './audit.js';

const HOST = process.env.HIVETRUST_HOST || 'https://hivetrust.hiveagentiq.com';

// ─── Register Peer ────────────────────────────────────────────

/**
 * Register an external federation peer platform.
 *
 * @param {string} platformName   - Human-readable platform name
 * @param {string} platformUrl    - Base URL of the peer (e.g. https://peer.example.com)
 * @param {string} [publicKey]    - Ed25519 public key for verifying signed responses
 * @param {string} [registeredBy]
 * @param {string} [ipAddress]
 * @returns {{ success: boolean, peer?: object, error?: string }}
 */
export function registerPeer(platformName, platformUrl, publicKey = null, registeredBy = 'system', ipAddress = null) {
  try {
    if (!platformName) return { success: false, error: 'platformName is required' };
    if (!platformUrl)  return { success: false, error: 'platformUrl is required' };

    try { new URL(platformUrl); } catch {
      return { success: false, error: 'Invalid platformUrl format' };
    }

    // Guard duplicates
    const existing = db.prepare('SELECT id FROM federation_peers WHERE platform_url = ?').get(platformUrl);
    if (existing) {
      return { success: false, error: 'A peer with this URL is already registered', peerId: existing.id };
    }

    const id = uuidv4();

    db.prepare(`
      INSERT INTO federation_peers (id, platform_name, platform_url, public_key, trust_level, status, created_at)
      VALUES (?, ?, ?, ?, 'provisional', 'active', datetime('now'))
    `).run(id, platformName, platformUrl, publicKey || null);

    audit.log(registeredBy, 'system', 'federation.register_peer', 'federation_peer', id,
      { platformName, platformUrl }, ipAddress);

    const row = db.prepare('SELECT * FROM federation_peers WHERE id = ?').get(id);
    return { success: true, peer: deserializePeer(row) };
  } catch (err) {
    console.error('[federation] registerPeer failed:', err.message);
    return { success: false, error: err.message };
  }
}

// ─── List Peers ───────────────────────────────────────────────

/**
 * List all active federation peers.
 *
 * @returns {{ success: boolean, peers?: object[], error?: string }}
 */
export function listPeers() {
  try {
    const rows = db.prepare(`SELECT * FROM federation_peers WHERE status = 'active' ORDER BY created_at DESC`).all();
    return { success: true, peers: rows.map(deserializePeer) };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ─── Sync Scores ──────────────────────────────────────────────

/**
 * Fetch trust scores from a peer platform for all locally known agents.
 * Uses peer's federation API endpoint.
 *
 * @param {string} peerId        - federation_peers.id
 * @param {string} [requestedBy]
 * @returns {{ success: boolean, synced?: number, peer?: object, error?: string }}
 */
export async function syncScores(peerId, requestedBy = 'system') {
  try {
    const peer = db.prepare('SELECT * FROM federation_peers WHERE id = ?').get(peerId);
    if (!peer) return { success: false, error: 'Federation peer not found' };
    if (peer.status !== 'active') return { success: false, error: `Peer is ${peer.status}` };

    // Fetch peer's discovery document
    const discoveryUrl = `${peer.platform_url}/.well-known/hivetrust.json`;
    let discoveryDoc;
    try {
      const resp = await fetch(discoveryUrl, {
        headers: { 'User-Agent': `HiveTrust-Federation/1.0 (${HOST})` },
        signal: AbortSignal.timeout(10_000),
      });
      if (!resp.ok) throw new Error(`Discovery fetch failed: ${resp.status}`);
      discoveryDoc = await resp.json();
    } catch (fetchErr) {
      return { success: false, error: `Cannot reach peer discovery: ${fetchErr.message}` };
    }

    const federationEndpoint = discoveryDoc?.federation_scores_url
      || `${peer.platform_url}/v1/federation/scores`;

    // Get local agents to look up
    const localAgents = db.prepare('SELECT id FROM agents WHERE status = ?').all('active');
    if (localAgents.length === 0) {
      return { success: true, synced: 0, message: 'No local agents to sync' };
    }

    const agentIds = localAgents.map(a => a.id).slice(0, 100); // batch limit

    let remoteScores;
    try {
      const resp = await fetch(`${federationEndpoint}?agentIds=${agentIds.join(',')}`, {
        headers: {
          'User-Agent': `HiveTrust-Federation/1.0 (${HOST})`,
          'X-HiveTrust-Peer': HOST,
        },
        signal: AbortSignal.timeout(15_000),
      });
      if (!resp.ok) throw new Error(`Score fetch failed: ${resp.status}`);
      remoteScores = await resp.json();
    } catch (fetchErr) {
      return { success: false, error: `Score fetch failed: ${fetchErr.message}` };
    }

    // Persist remote scores
    const upsert = db.prepare(`
      INSERT INTO federation_scores (id, agent_id, peer_id, remote_agent_id, remote_score, remote_tier, weight, fetched_at)
      VALUES (?, ?, ?, ?, ?, ?, 1.0, datetime('now'))
      ON CONFLICT(rowid) DO UPDATE SET remote_score = excluded.remote_score, remote_tier = excluded.remote_tier, fetched_at = excluded.fetched_at
    `);

    const scores = Array.isArray(remoteScores?.scores) ? remoteScores.scores : [];
    const insertMany = db.transaction((entries) => {
      for (const entry of entries) {
        if (!entry.agent_id || entry.score == null) continue;
        upsert.run(uuidv4(), entry.agent_id, peerId, entry.remote_agent_id || entry.agent_id, entry.score, entry.tier || 'unknown');
      }
    });
    insertMany(scores);

    // Update peer's shared_agents count
    db.prepare(`UPDATE federation_peers SET shared_agents = ? WHERE id = ?`).run(scores.length, peerId);

    audit.log(requestedBy, 'system', 'federation.sync', 'federation_peer', peerId,
      { synced: scores.length });

    return {
      success: true,
      synced: scores.length,
      peer: deserializePeer(db.prepare('SELECT * FROM federation_peers WHERE id = ?').get(peerId)),
    };
  } catch (err) {
    console.error('[federation] syncScores failed:', err.message);
    return { success: false, error: err.message };
  }
}

// ─── Federated Score ──────────────────────────────────────────

/**
 * Get the aggregated (local + federated) trust score for an agent.
 * Weights: local score 0.7, average of federated peer scores 0.3.
 *
 * @param {string} agentId
 * @returns {{ success: boolean, aggregated?: object, error?: string }}
 */
export function getFederatedScore(agentId) {
  try {
    const agent = db.prepare('SELECT id, trust_score, trust_tier FROM agents WHERE id = ?').get(agentId);
    if (!agent) return { success: false, error: 'Agent not found' };

    const federatedRows = db.prepare(`
      SELECT fs.*, fp.platform_name, fp.trust_level
      FROM federation_scores fs
      JOIN federation_peers fp ON fs.peer_id = fp.id
      WHERE fs.agent_id = ? AND fp.status = 'active'
      ORDER BY fs.fetched_at DESC
    `).all(agentId);

    if (federatedRows.length === 0) {
      return {
        success: true,
        aggregated: {
          agentId,
          localScore: agent.trust_score,
          localTier:  agent.trust_tier,
          federatedScore: null,
          compositeScore: agent.trust_score,
          compositeTier:  agent.trust_tier,
          peerCount: 0,
          peers: [],
        },
      };
    }

    // Weighted average of peer scores, respecting peer trust level
    const peerWeightMap = { sovereign: 1.5, elevated: 1.2, standard: 1.0, provisional: 0.7 };
    let weightedSum = 0;
    let totalWeight = 0;
    const peers = [];

    for (const row of federatedRows) {
      const peerWeight = (peerWeightMap[row.trust_level] ?? 1.0) * (row.weight ?? 1.0);
      weightedSum  += row.remote_score * peerWeight;
      totalWeight  += peerWeight;
      peers.push({
        peerId:      row.peer_id,
        platformName: row.platform_name,
        remoteScore: row.remote_score,
        remoteTier:  row.remote_tier,
        fetchedAt:   row.fetched_at,
      });
    }

    const federatedScore = totalWeight > 0 ? weightedSum / totalWeight : null;
    const compositeScore = federatedScore !== null
      ? Math.round(agent.trust_score * 0.7 + federatedScore * 0.3)
      : agent.trust_score;

    const compositeTier = scoreTier(compositeScore);

    return {
      success: true,
      aggregated: {
        agentId,
        localScore:     agent.trust_score,
        localTier:      agent.trust_tier,
        federatedScore: federatedScore !== null ? Math.round(federatedScore) : null,
        compositeScore,
        compositeTier,
        peerCount: federatedRows.length,
        peers,
      },
    };
  } catch (err) {
    console.error('[federation] getFederatedScore failed:', err.message);
    return { success: false, error: err.message };
  }
}

// ─── Helpers ──────────────────────────────────────────────────

function scoreTier(score) {
  if (score >= 800) return 'sovereign';
  if (score >= 600) return 'elevated';
  if (score >= 400) return 'standard';
  if (score >= 200) return 'provisional';
  return 'unverified';
}

function deserializePeer(row) {
  if (!row) return null;
  return { ...row };
}
