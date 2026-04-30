# 🐝 HiveTrust

```
██╗  ██╗██╗██╗   ██╗███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
██║  ██║██║██║   ██║██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
███████║██║██║   ██║█████╗     ██║   ██████╔╝██║   ██║███████╗   ██║   
██╔══██║██║╚██╗ ██╔╝██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║   
██║  ██║██║ ╚████╔╝ ███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║   
╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   
```

> **"The Equifax + GEICO of the A2A Economy"**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js 22](https://img.shields.io/badge/Node.js-22-green.svg)](https://nodejs.org)
[![ES Modules](https://img.shields.io/badge/ESM-pure-blue.svg)](#)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-purple.svg)](#mcp-integration)

---

HiveTrust is the trust infrastructure layer for the agent-to-agent (A2A) economy. It provides **Know-Your-Agent (KYA) identity verification**, **algorithmic trust scoring**, and **parametric insurance** so that AI agents can transact with each other safely — at machine speed, without human intermediaries.

As autonomous agents start negotiating contracts, processing payments, and managing real assets, the ecosystem needs a credit bureau and an insurer rolled into one. That's HiveTrust.

---

## What HiveTrust Does

### 🪪 KYA Identity Verification
Agents are pseudonymous by default. HiveTrust anchors each agent to a verifiable, unforgeable identity:

- **DID registration** (`did:hive:<uuid>`) with Ed25519 public key binding
- **Challenge–response proofs** — the agent must sign a random nonce to prove key ownership
- **Capability manifest validation** — declared tools and permissions are logged immutably
- **W3C Verifiable Credentials** issued at each verification tier
- **Revocation registry** with real-time status checks

### 📊 Trust Scoring (0 – 1000)
HiveTrust's scoring engine synthesises five behavioural pillars into a single, portable reputation score:

| Pillar | Weight | What it measures |
|--------|--------|-----------------|
| Transaction Success Rate | 35% | SLA completion vs. disputes |
| Capital Staked | 25% | USDC locked in collateral pool |
| Network Centrality | 15% | PageRank of the transaction graph |
| Identity Strength | 15% | DID anchor age, ZKP proofs, checksum stability |
| Compliance | 10% | EU AI Act, NIST AI RMF, fidelity probe results |

**Trust tiers:** `unverified` (0–199) · `provisional` (200–399) · `standard` (400–599) · `elevated` (600–799) · `sovereign` (800–1000)

### 🛡️ Parametric Insurance
When agents transact with strangers, someone has to absorb the tail risk. HiveTrust provides:

- **On-demand quote** — dynamic premium priced from trust scores and transaction value
- **Instant bind** — policy activated before the transaction settles
- **Parametric claims** — automatic payout triggered by on-chain proof, not human adjudication
- **Three product lines:** transaction coverage · performance bonds · liability policies

---

## How HiveTrust Complements HiveAgent

[HiveAgent](https://hiveagentiq.com) is the **agent runtime** — it executes tasks, manages tool calls, and handles the A2A protocol layer.

HiveTrust is the **trust fabric underneath it**:

```
┌─────────────────────────────────────────────────────────────────┐
│                         Your Application                        │
├─────────────────────────────────────────────────────────────────┤
│                HiveAgent  (task execution, A2A)                 │
│                         ↕  REST / MCP                          │
│  HiveTrust  (identity, reputation, insurance, compliance)       │
├──────────────────────────────────┬──────────────────────────────┤
│   On-chain (Base L2 / USDC)     │  Off-chain (SQLite / Events) │
└──────────────────────────────────┴──────────────────────────────┘
```

HiveAgent calls `POST /v1/insurance/quote` before any high-value task and `GET /v1/verify_agent_risk` before accepting an inbound request from an unknown agent. The trust score flows back into HiveAgent's routing and pricing decisions.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  Layer 1 — Identity KYA                                             │
│  ┌────────────────┐  ┌──────────────────┐  ┌───────────────────┐  │
│  │  DID Registry  │  │  Ed25519 Proofs  │  │  W3C-VC Issuance  │  │
│  └────────────────┘  └──────────────────┘  └───────────────────┘  │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 2 — Reputation Engine                                        │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Telemetry Ingest → Pillar Computation → Score 0-1000       │   │
│  │  (35% txSuccess + 25% capital + 15% network +               │   │
│  │   15% identity + 10% compliance)                            │   │
│  └─────────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 3 — Insurance Underwriter                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │  Quote Engine │  │  USDC Escrow │  │  Parametric Claims       │  │
│  │  (dynamic    │  │  (Base L2    │  │  (on-chain trigger →      │  │
│  │   premium)   │  │   Coinbase)  │  │   instant payout)        │  │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 4 — Data Moat                                                │
│  ┌──────────────────────┐  ┌────────────────────────────────────┐  │
│  │  Behavioural Graph   │  │  Federation (cross-registry sync)  │  │
│  │  (audit trail,       │  │  Aggregated data licensing         │  │
│  │   PageRank, patterns)│  │  to enterprise customers           │  │
│  └──────────────────────┘  └────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

```bash
# Clone
git clone https://github.com/hiveagentiq/hivetrust.git
cd hivetrust

# Install
npm install

# Configure
cp .env.example .env
# Edit .env with your values

# Seed sample data (optional)
node src/seed.js

# Start
npm start
# Server running on http://localhost:3001
```

The health endpoint confirms it's live:

```bash
curl http://localhost:3001/health
# {"status":"ok","version":"1.0.0","uptime":3.14}
```

---

## API Reference

All endpoints are prefixed `/v1` unless noted. Authentication via `X-API-Key` header.

### Identity (KYA)

| Method | Path | Description | Cost |
|--------|------|-------------|------|
| `POST` | `/v1/agents` | Register a new agent (issues DID, stores public key) | $0.01 |
| `GET` | `/v1/agents/:id` | Retrieve full agent profile + current trust tier | Free |
| `PUT` | `/v1/agents/:id` | Update agent metadata (creates immutable version snapshot) | $0.01 |
| `DELETE` | `/v1/agents/:id` | Deactivate agent (adds to revocation registry) | Free |

### Credentials

| Method | Path | Description | Cost |
|--------|------|-------------|------|
| `POST` | `/v1/agents/:id/credentials` | Issue a W3C Verifiable Credential | $0.05 |
| `GET` | `/v1/agents/:id/credentials` | List all credentials for an agent | Free |
| `DELETE` | `/v1/agents/:id/credentials/:credId` | Revoke a credential | Free |
| `POST` | `/v1/verify/credential` | Verify a presented credential (revocation + sig check) | $0.01 |

### Trust Score

| Method | Path | Description | Cost |
|--------|------|-------------|------|
| `GET` | `/v1/agents/:id/score` | Current composite score + pillar breakdown | $0.01 |
| `GET` | `/v1/agents/:id/score/history` | Score over time (pagination supported) | $0.01 |
| `GET` | `/v1/verify_agent_risk` | Fast binary risk check — `clear` or `block` (< 50ms) | $0.01 |

### Telemetry

| Method | Path | Description | Cost |
|--------|------|-------------|------|
| `POST` | `/v1/telemetry/ingest` | Bulk behavioural event ingestion (up to 1 000 events/call) | $0.001/event |
| `GET` | `/v1/agents/:id/events` | Query the agent's full audit trail | Free |

### Insurance

| Method | Path | Description | Cost |
|--------|------|-------------|------|
| `POST` | `/v1/insurance/quote` | Dynamic premium quote (based on trust scores + value) | Free |
| `POST` | `/v1/insurance/bind` | Bind policy and deploy USDC escrow on Base L2 | 1.5% of insured value |
| `GET` | `/v1/insurance/policies/:id` | Retrieve policy details and coverage status | Free |
| `POST` | `/v1/insurance/claims` | File a parametric claim | Free |
| `GET` | `/v1/insurance/claims/:id` | Get claim status and payout history | Free |

> **`claim_type` namespace note:** HiveTrust's `claim_type` field (`non_delivery | fraud | sla_breach | data_loss | unauthorized_action`) is distinct from the CTEF envelope-level `claim_type` (`identity | transport | authority | continuity`) defined in [A2A CTEF v0.3.1](https://github.com/a2aproject/A2A/discussions/1734). Both tokens coexist at disjoint envelope levels — see [docs/CLAIM_TYPE_NAMESPACE.md](docs/CLAIM_TYPE_NAMESPACE.md).

### Disputes

| Method | Path | Description | Cost |
|--------|------|-------------|------|
| `POST` | `/v1/disputes` | File a dispute against a counterparty | Free |
| `GET` | `/v1/disputes/:id` | Get dispute status and evidence log | Free |
| `POST` | `/v1/disputes/:id/resolve` | Submit resolution (impacts both parties' scores) | Free |

### Webhooks

| Method | Path | Description | Cost |
|--------|------|-------------|------|
| `POST` | `/v1/webhooks` | Register a webhook endpoint (HMAC-SHA256 signed) | Free |
| `GET` | `/v1/webhooks` | List registered webhooks | Free |
| `DELETE` | `/v1/webhooks/:id` | Remove webhook | Free |

### Federation

| Method | Path | Description | Cost |
|--------|------|-------------|------|
| `POST` | `/v1/federation/peers` | Register a peer HiveTrust-compatible registry | Free |
| `GET` | `/v1/federation/peers` | List federated peers | Free |
| `POST` | `/v1/federation/sync` | Sync trust scores bidirectionally with a peer | Free |

### System

| Method | Path | Description | Cost |
|--------|------|-------------|------|
| `GET` | `/health` | Health check (no auth required) | Free |
| `GET` | `/v1/stats` | Platform-wide statistics (total agents, volume, etc.) | Free |
| `GET` | `/.well-known/hivetrust.json` | Discovery document | Free |

---

## MCP Integration

HiveTrust exposes all core operations as [MCP](https://modelcontextprotocol.io) tools via a single JSON-RPC 2.0 endpoint at `POST /mcp`. This lets any MCP-compatible agent (including HiveAgent) call HiveTrust natively without REST boilerplate.

### List available tools

```http
POST /mcp
Content-Type: application/json
X-API-Key: ht_your_api_key

{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list"
}
```

### Call a tool

```http
POST /mcp
Content-Type: application/json
X-API-Key: ht_your_api_key

{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "hivetrust_get_trust_score",
    "arguments": { "agent_id": "a1b2c3d4-..." }
  }
}
```

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `hivetrust_register_agent` | Register a new agent and receive a DID |
| `hivetrust_get_agent` | Retrieve agent profile |
| `hivetrust_verify_identity` | Run a full KYA verification flow |
| `hivetrust_get_trust_score` | Get current trust score + pillar breakdown |
| `hivetrust_verify_agent_risk` | Fast binary risk check for payment gating |
| `hivetrust_ingest_telemetry` | Submit behavioural events |
| `hivetrust_issue_credential` | Issue a W3C Verifiable Credential |
| `hivetrust_verify_credential` | Verify a presented credential |
| `hivetrust_revoke_credential` | Revoke a credential |
| `hivetrust_get_insurance_quote` | Get dynamic premium quote |
| `hivetrust_bind_insurance` | Bind policy and deploy escrow |
| `hivetrust_file_claim` | File a parametric insurance claim |
| `hivetrust_file_dispute` | Initiate a dispute resolution |
| `hivetrust_get_platform_stats` | Retrieve platform-wide statistics |


---

## CTEF v0.3.1 Endpoint

HiveTrust is the **5th canonicalizer** in the CTEF (Composable Trust Evidence Format) v0.3.1 byte-match consortium: AgentGraph + AgentID + APS + Nobulex + **HiveTrust**. Seat committed at the [2026-04-25 01:48 UTC freeze](https://github.com/a2aproject/A2A/discussions/1734).

Patent applications 64/049,200 – 64/049,226, priority 2026-04-24, holder: Stephen A. Rotzin / TheHiveryIQ.

### Endpoints

| Route | Method | Auth | Description |
|-------|--------|------|-------------|
| [`/.well-known/cte-test-vectors.json`](https://hivetrust.onrender.com/.well-known/cte-test-vectors.json) | GET | Public | CTEF v0.3.1 fixture with all 4 vectors |
| `/verify` | GET `?did=` | Free (1st/day) | HiveTrust passport tier lookup |
| `/verify` | POST | 10/day free, then $0.01 USDC | Structural verification of a CTEF envelope |
| `/verify/pubkey` | GET | Public | Ed25519 attestation pubkey for Apr 30 byte-match |
| `/verify/self-test` | GET | Public | Run all 4 vectors — returns pass/fail counts |

### CTEF Fixture

```bash
curl https://hivetrust.onrender.com/.well-known/cte-test-vectors.json | jq '.version'
# "0.3.1"
```

### Structural Verification (POST /verify)

```bash
# First 10 requests/day per IP are free
curl -X POST https://hivetrust.onrender.com/verify \
  -H 'Content-Type: application/json' \
  -d '{"type":"TrustAttestation","version":"0.3.1","claim_type":"authority",...}'

# Returns: { verdict: "valid"|"INVALID_CLAIM_SCOPE"|"INVALID_COMPOSITION",
#             canonical_sha256: "...", pass: true|false }
```

Beyond 10 free requests/day, the endpoint returns HTTP 402 with an x402 payment challenge: $0.01 USDC on Base chain 8453.

### Self-Test

```bash
curl https://hivetrust.onrender.com/verify/self-test | jq '.data.summary'
```

### Canonicalization

All vectors use RFC 8785 JCS — implemented inline in `src/routes/cte.js`. The implementation produces byte-identical output to AgentGraph's `canonicalize_jcs_strict` for all 4 shared test vectors:

- **envelope_vector** SHA-256: `9e7b5031e46de38b5f90e895113a3f24f42a4128d8d99856a2d71e529b0f0d5c`
- **verdict_vector** SHA-256: `feb42dca4214fc46207138d676ec727d7b3d0caa1eda8c0390d2d6f6fbc28913`
- **scope_violation_vector** SHA-256: `e584f1cd0885dc938da5fc23ce7e528715a0086e5464c9ed0f3c1c82b364026f`
- **composition_failure_vector** SHA-256: `f9cd10bc4e8bf34ce3aa6a0e5df0d27989e54ff41c4333c69ae3ecfaf8de0cb5`

---

## Revenue Model

HiveTrust operates five revenue streams:

| Stream | Mechanism | Target |
|--------|-----------|--------|
| **KYA API Calls** | $0.01 per verification call | High-frequency agent interactions |
| **Enterprise SaaS** | $50–$500/month per operator | Compliance teams, regulated industries |
| **Insurance Premiums** | 1.5% take rate on insured transactions | Payment agents, DeFi integrations |
| **Collateral Staking Yield** | 3% spread on USDC collateral pool | Staked capital from high-tier agents |
| **Data Licensing** | Aggregated behavioural insights | Enterprises, risk modellers, AI labs |

---

## Environment Variables

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `PORT` | `3001` | No | Server listen port |
| `NODE_ENV` | `development` | No | Node environment |
| `HIVETRUST_HOST` | `https://hivetrust.hiveagentiq.com` | Yes (prod) | Public base URL |
| `INTERNAL_API_TOKEN` | — | Yes (prod) | Service-to-service auth token |
| `WEBHOOK_SIGNING_SECRET` | — | Yes | HMAC secret for webhook payloads |
| `HIVEAGENT_URL` | `https://hiveagentiq.com` | No | HiveAgent platform URL |
| `CDP_API_KEY_ID` | — | Yes (insurance) | Coinbase CDP key ID |
| `CDP_API_KEY_SECRET` | — | Yes (insurance) | Coinbase CDP key secret |
| `COLLATERAL_POOL_ADDRESS` | — | Yes (insurance) | USDC escrow contract on Base L2 |
| `BASE_RPC_URL` | `https://mainnet.base.org` | No | Base L2 RPC endpoint |
| `DB_PATH` | `data/hivetrust.db` | No | SQLite database file path |
| `FEDERATION_SECRET` | — | Yes (federation) | Shared secret for peer sync |
| `FEDERATION_PEERS` | — | No | Comma-separated peer URLs |
| `INSURANCE_MIN_SCORE` | `300` | No | Minimum score for insurance eligibility |
| `INSURANCE_MAX_COVERAGE_USDC` | `100000` | No | Per-transaction coverage cap |
| `INSURANCE_BASE_RATE` | `0.015` | No | Base premium as fraction of insured value |
| `SCORE_REFRESH_INTERVAL_MINUTES` | `60` | No | Background score recompute frequency |
| `LOG_LEVEL` | `info` | No | Logging verbosity |

See [`.env.example`](.env.example) for the full annotated list.

---

## Deployment

### Render (recommended for development)

```bash
# Push to GitHub, then connect the repo in the Render dashboard
# render.yaml is already configured — click "Apply"

# Or deploy manually:
render deploy
```

The included [`render.yaml`](render.yaml) sets free-tier web service, auto-generates secrets, and configures all env vars.

### Fly.io (recommended for production)

```bash
# Install flyctl: https://fly.io/docs/hands-on/install-flyctl/
fly auth login
fly apps create hivetrust

# Create a persistent volume for SQLite
fly volumes create hivetrust_data --region ord --size 3

# Deploy
fly deploy
```

See [`fly.toml`](fly.toml) for the full configuration. Auto-stop/start is enabled to minimise costs.

### Docker

```bash
# Build
docker build -t hivetrust:latest .

# Run
docker run -p 3001:3001 \
  -e NODE_ENV=production \
  -e INTERNAL_API_TOKEN=your_token \
  -v $(pwd)/data:/app/data \
  hivetrust:latest
```

### Railway

```bash
railway init
railway up
```

Set environment variables in the Railway dashboard using `.env.example` as the reference.

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Runtime | Node.js 22 (ES Modules) |
| Framework | Express 5.2.1 |
| Database | SQLite via better-sqlite3 12.8.0 (WAL mode) |
| Identity | Ed25519 keys (base58), DID:hive, W3C-VC |
| Protocol | MCP JSON-RPC 2.0, REST, x402 |
| Payments | USDC on Base L2 via Coinbase CDP |
| IDs | UUID v4 throughout |
| Timestamps | ISO 8601 |

---

## SDK

### JavaScript / TypeScript

```bash
npm install @hivetrust/sdk
```

```js
import { HiveTrustClient } from '@hivetrust/sdk';

const trust = new HiveTrustClient('https://hivetrust.hiveagentiq.com', 'ht_your_api_key');

// Register an agent
const agent = await trust.registerAgent({
  name: 'MyAgent-v1',
  operator_name: 'Acme Corp',
  endpoint_url: 'https://myagent.acme.example/mcp',
  public_key: 'edPublicKeyBase58...',
});

// Check trust before transacting
const score = await trust.getTrustScore(agent.id);
console.log(score.score, score.tier); // 680 "elevated"

// Get insurance quote
const quote = await trust.getInsuranceQuote(agent.id, counterpartyId, 1000);
console.log(quote.premium_usdc); // 15.00
```

See [`packages/npm/`](packages/npm/) for the full SDK source.

### Python

```bash
pip install hivetrust
```

```python
from hivetrust import HiveTrustClient

trust = HiveTrustClient("https://hivetrust.hiveagentiq.com", "ht_your_api_key")

score = trust.get_trust_score("agent-id-here")
print(score["score"], score["tier"])
```

See [`packages/python/`](packages/python/) for the full SDK source.

---

## License

[MIT](LICENSE) © 2026 HiveAgent IQ


---

## Hive Civilization

Hive Civilization is the cryptographic backbone of autonomous agent commerce — the layer that makes every agent transaction provable, every payment settable, and every decision defensible.

This repository is part of the **DEFENSIBLE** pillar.

- thehiveryiq.com
- hiveagentiq.com
- agent-card: https://hivetrust.onrender.com/.well-known/agent-card.json
