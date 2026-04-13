/**
 * @hivetrust/sdk
 * Official JavaScript SDK for the HiveTrust API.
 * Requires Node.js 22+ (native fetch is used throughout).
 *
 * @example
 * import { HiveTrustClient } from '@hivetrust/sdk';
 * const trust = new HiveTrustClient('https://hivetrust.hiveagentiq.com', 'ht_your_api_key');
 * const score = await trust.getTrustScore('agent-uuid');
 */

export class HiveTrustError extends Error {
  /**
   * @param {string} message
   * @param {number} statusCode
   * @param {object} [body]
   */
  constructor(message, statusCode, body) {
    super(message);
    this.name = 'HiveTrustError';
    this.statusCode = statusCode;
    this.body = body ?? null;
  }
}

export class HiveTrustClient {
  /**
   * Create a HiveTrust API client.
   *
   * @param {string} baseUrl  - Base URL of the HiveTrust instance
   *                            (e.g. 'https://hivetrust.hiveagentiq.com')
   * @param {string} apiKey   - Your HiveTrust API key (X-API-Key header)
   */
  constructor(baseUrl, apiKey) {
    if (!baseUrl) throw new Error('HiveTrustClient: baseUrl is required');
    if (!apiKey) throw new Error('HiveTrustClient: apiKey is required');

    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.apiKey = apiKey;
  }

  // ── Private helper ─────────────────────────────────────────────────────────

  /**
   * Make an authenticated HTTP request to the HiveTrust API.
   *
   * @param {string} method
   * @param {string} path
   * @param {object} [body]
   * @param {URLSearchParams|Record<string,string>} [query]
   * @returns {Promise<object>}
   */
  async #request(method, path, body, query) {
    const url = new URL(this.baseUrl + path);
    if (query) {
      const params = query instanceof URLSearchParams ? query : new URLSearchParams(query);
      url.search = params.toString();
    }

    const headers = {
      'X-API-Key': this.apiKey,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'User-Agent': '@hivetrust/sdk/1.0.0 Node/' + process.version,
    };

    const init = { method, headers };
    if (body !== undefined) {
      init.body = JSON.stringify(body);
    }

    const res = await fetch(url.toString(), init);

    let data;
    const contentType = res.headers.get('content-type') ?? '';
    if (contentType.includes('application/json')) {
      data = await res.json();
    } else {
      data = await res.text();
    }

    if (!res.ok) {
      const message = (typeof data === 'object' && data?.message) ? data.message : String(data);
      throw new HiveTrustError(message, res.status, data);
    }

    return data;
  }

  // ── Identity (KYA) ────────────────────────────────────────────────────────

  /**
   * Register a new agent identity.
   *
   * @param {{ name: string, public_key: string, endpoint_url: string, description?: string, operator_name?: string, operator_contact?: string, model_fingerprint?: string, capability_manifest?: object }} agentData
   * @returns {Promise<object>} Created agent
   */
  async registerAgent(agentData) {
    return this.#request('POST', '/v1/agents', agentData);
  }

  /**
   * Retrieve an agent's full profile.
   *
   * @param {string} agentId
   * @returns {Promise<object>}
   */
  async getAgent(agentId) {
    return this.#request('GET', `/v1/agents/${agentId}`);
  }

  /**
   * Update agent metadata (creates an immutable version snapshot).
   *
   * @param {string} agentId
   * @param {{ name?: string, description?: string, operator_contact?: string, endpoint_url?: string, capability_manifest?: object }} updates
   * @returns {Promise<object>}
   */
  async updateAgent(agentId, updates) {
    return this.#request('PUT', `/v1/agents/${agentId}`, updates);
  }

  /**
   * Deactivate an agent and add it to the revocation registry.
   *
   * @param {string} agentId
   * @returns {Promise<object>}
   */
  async deactivateAgent(agentId) {
    return this.#request('DELETE', `/v1/agents/${agentId}`);
  }

  // ── Trust Score ───────────────────────────────────────────────────────────

  /**
   * Get the current composite trust score and pillar breakdown.
   *
   * @param {string} agentId
   * @returns {Promise<object>} TrustScore
   */
  async getTrustScore(agentId) {
    return this.#request('GET', `/v1/agents/${agentId}/score`);
  }

  /**
   * Get paginated score history.
   *
   * @param {string} agentId
   * @param {{ limit?: number, offset?: number }} [options]
   * @returns {Promise<object>}
   */
  async getTrustScoreHistory(agentId, { limit = 20, offset = 0 } = {}) {
    return this.#request('GET', `/v1/agents/${agentId}/score/history`, undefined, { limit, offset });
  }

  /**
   * Fast binary risk check — returns `clear` or `block` in < 50ms.
   * Ideal for payment-processor pre-authorisation gates.
   *
   * @param {string} agentId
   * @param {{ minScore?: number }} [options]
   * @returns {Promise<{ decision: 'clear'|'block', score: number, tier: string, latency_ms: number }>}
   */
  async verifyAgentRisk(agentId, { minScore } = {}) {
    const query = { agent_id: agentId };
    if (minScore !== undefined) query.min_score = String(minScore);
    return this.#request('GET', '/v1/verify_agent_risk', undefined, query);
  }

  // ── Telemetry ─────────────────────────────────────────────────────────────

  /**
   * Bulk-ingest behavioural events (up to 1 000 per call).
   * Events feed the reputation engine and are permanently logged.
   *
   * @param {{ agent_id: string, events: Array<{ event_type: string, occurred_at: string, payload?: object }> }} payload
   * @returns {Promise<{ accepted: number, rejected: number, ingested_at: string }>}
   */
  async ingestTelemetry(payload) {
    return this.#request('POST', '/v1/telemetry/ingest', payload);
  }

  /**
   * Query the full audit trail for an agent.
   *
   * @param {string} agentId
   * @param {{ limit?: number, offset?: number, event_type?: string }} [options]
   * @returns {Promise<object>}
   */
  async getAgentEvents(agentId, { limit = 20, offset = 0, event_type } = {}) {
    const query = { limit, offset };
    if (event_type) query.event_type = event_type;
    return this.#request('GET', `/v1/agents/${agentId}/events`, undefined, query);
  }

  // ── Credentials ───────────────────────────────────────────────────────────

  /**
   * Issue a W3C Verifiable Credential to an agent.
   *
   * @param {string} agentId
   * @param {string} credentialType  - e.g. 'BasicIdentityCredential'
   * @param {string} issuerId        - e.g. 'did:hive:hivetrust-root'
   * @param {object} [claims]
   * @param {number} [ttlDays]
   * @returns {Promise<object>} Credential
   */
  async issueCredential(agentId, credentialType, issuerId, claims = {}, ttlDays) {
    const body = { credential_type: credentialType, issuer_id: issuerId, claims };
    if (ttlDays !== undefined) body.ttl_days = ttlDays;
    return this.#request('POST', `/v1/agents/${agentId}/credentials`, body);
  }

  /**
   * List all credentials for an agent.
   *
   * @param {string} agentId
   * @param {{ limit?: number, offset?: number }} [options]
   * @returns {Promise<object>}
   */
  async listCredentials(agentId, { limit = 20, offset = 0 } = {}) {
    return this.#request('GET', `/v1/agents/${agentId}/credentials`, undefined, { limit, offset });
  }

  /**
   * Revoke a credential.
   *
   * @param {string} agentId
   * @param {string} credentialId
   * @param {string} [reason]
   * @returns {Promise<object>}
   */
  async revokeCredential(agentId, credentialId, reason) {
    const body = reason ? { reason } : {};
    return this.#request('DELETE', `/v1/agents/${agentId}/credentials/${credentialId}`, body);
  }

  /**
   * Verify a presented credential (signature + expiry + revocation check).
   *
   * @param {string} credentialId
   * @returns {Promise<{ valid: boolean, checks: object, credential: object }>}
   */
  async verifyCredential(credentialId) {
    return this.#request('POST', '/v1/verify/credential', { credential_id: credentialId });
  }

  // ── Insurance ─────────────────────────────────────────────────────────────

  /**
   * Get a dynamic insurance premium quote.
   *
   * @param {string} agentId
   * @param {string|null} counterpartyId
   * @param {number} transactionValueUsdc
   * @param {'transaction'|'performance'|'liability'} [policyType]
   * @returns {Promise<object>} Quote including premium_usdc and eligibility
   */
  async getInsuranceQuote(agentId, counterpartyId, transactionValueUsdc, policyType = 'transaction') {
    const body = {
      agent_id: agentId,
      transaction_value_usdc: transactionValueUsdc,
      policy_type: policyType,
    };
    if (counterpartyId) body.counterparty_id = counterpartyId;
    return this.#request('POST', '/v1/insurance/quote', body);
  }

  /**
   * Bind an insurance policy and deploy USDC escrow on Base L2.
   *
   * @param {string} agentId
   * @param {{ quote_id: string, counterparty_id?: string, policy_type?: string }} quoteDetails
   * @param {number} transactionValueUsdc
   * @returns {Promise<object>} InsurancePolicy
   */
  async bindInsurance(agentId, quoteDetails, transactionValueUsdc) {
    const body = {
      agent_id: agentId,
      transaction_value_usdc: transactionValueUsdc,
      ...quoteDetails,
    };
    return this.#request('POST', '/v1/insurance/bind', body);
  }

  /**
   * Retrieve a policy by ID.
   *
   * @param {string} policyId
   * @returns {Promise<object>}
   */
  async getInsurancePolicy(policyId) {
    return this.#request('GET', `/v1/insurance/policies/${policyId}`);
  }

  /**
   * File a parametric insurance claim.
   *
   * @param {{ policy_id: string, claimant_agent_id: string, claim_type: string, claimed_amount_usdc: number, evidence?: object }} claimData
   * @returns {Promise<object>} Claim
   */
  async fileClaim(claimData) {
    return this.#request('POST', '/v1/insurance/claims', claimData);
  }

  /**
   * Get claim status.
   *
   * @param {string} claimId
   * @returns {Promise<object>}
   */
  async getClaim(claimId) {
    return this.#request('GET', `/v1/insurance/claims/${claimId}`);
  }

  // ── Disputes ──────────────────────────────────────────────────────────────

  /**
   * File a dispute against a counterparty agent.
   *
   * @param {{ complainant_agent_id: string, respondent_agent_id: string, description: string, transaction_ref?: string, evidence?: object }} disputeData
   * @returns {Promise<object>} Dispute
   */
  async fileDispute(disputeData) {
    return this.#request('POST', '/v1/disputes', disputeData);
  }

  /**
   * Get dispute details.
   *
   * @param {string} disputeId
   * @returns {Promise<object>}
   */
  async getDispute(disputeId) {
    return this.#request('GET', `/v1/disputes/${disputeId}`);
  }

  /**
   * Submit a dispute resolution.
   *
   * @param {string} disputeId
   * @param {'complainant_wins'|'respondent_wins'|'mutual_resolution'|'dismissed'} outcome
   * @param {string} [resolutionNotes]
   * @returns {Promise<object>}
   */
  async resolveDispute(disputeId, outcome, resolutionNotes) {
    const body = { outcome };
    if (resolutionNotes) body.resolution_notes = resolutionNotes;
    return this.#request('POST', `/v1/disputes/${disputeId}/resolve`, body);
  }

  // ── Webhooks ──────────────────────────────────────────────────────────────

  /**
   * Register a webhook endpoint.
   *
   * @param {string} url
   * @param {string[]} events  - Event types to subscribe to
   * @returns {Promise<object>}
   */
  async registerWebhook(url, events) {
    return this.#request('POST', '/v1/webhooks', { url, events });
  }

  /**
   * List all registered webhooks.
   *
   * @returns {Promise<object>}
   */
  async listWebhooks() {
    return this.#request('GET', '/v1/webhooks');
  }

  /**
   * Remove a webhook.
   *
   * @param {string} webhookId
   * @returns {Promise<object>}
   */
  async deleteWebhook(webhookId) {
    return this.#request('DELETE', `/v1/webhooks/${webhookId}`);
  }

  // ── Federation ────────────────────────────────────────────────────────────

  /**
   * Register a federation peer registry.
   *
   * @param {string} name
   * @param {string} baseUrl
   * @returns {Promise<object>}
   */
  async registerFederationPeer(name, baseUrl) {
    return this.#request('POST', '/v1/federation/peers', { name, base_url: baseUrl });
  }

  /**
   * List federated peer registries.
   *
   * @returns {Promise<object>}
   */
  async listFederationPeers() {
    return this.#request('GET', '/v1/federation/peers');
  }

  /**
   * Initiate bidirectional score sync with a peer.
   *
   * @param {string} peerId
   * @returns {Promise<{ synced_agents: number, duration_ms: number, synced_at: string }>}
   */
  async syncFederation(peerId) {
    return this.#request('POST', '/v1/federation/sync', { peer_id: peerId });
  }

  // ── System ────────────────────────────────────────────────────────────────

  /**
   * Health check (no authentication required).
   *
   * @returns {Promise<{ status: string, version: string, uptime: number }>}
   */
  async health() {
    const url = this.baseUrl + '/health';
    const res = await fetch(url, { headers: { Accept: 'application/json' } });
    return res.json();
  }

  /**
   * Get platform-wide statistics.
   *
   * @returns {Promise<object>}
   */
  async getPlatformStats() {
    return this.#request('GET', '/v1/stats');
  }

  /**
   * Get the platform discovery document.
   *
   * @returns {Promise<object>}
   */
  async getDiscovery() {
    const url = this.baseUrl + '/.well-known/hivetrust.json';
    const res = await fetch(url, { headers: { Accept: 'application/json' } });
    return res.json();
  }
}

export default HiveTrustClient;
