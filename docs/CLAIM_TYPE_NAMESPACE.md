# `claim_type` — Namespace Note

**Status:** NORMATIVE (HiveTrust-local) · Aligned with CTEF v0.3.1 (frozen 2026-04-25)
**Upstream refs:** [a2aproject/A2A#1734](https://github.com/a2aproject/A2A/discussions/1734) · [a2aproject/A2A#1672](https://github.com/a2aproject/A2A/issues/1672) · [a2aproject/A2A#1786](https://github.com/a2aproject/A2A/issues/1786)
**Canonical commit:** `agentgraph-co/agentgraph@69ad94d`

---

## Summary

The token `claim_type` appears in two independent schemas with two different semantics. This is intentional, not a collision. Namespace disambiguation resolves at the envelope layer — same token name, distinct envelope level, zero wire-format conflict.

## The two axes

### CTEF envelope-level `claim_type` (upstream)

- **Owner:** CTEF v0.3.1 (AgentGraph + AgentID + APS + Nobulex + HiveTrust, five-way convergence)
- **Role:** Layer discriminator
- **Closed set:** `{identity, transport, authority, continuity}`
- **Where it rides:** Outer attestation envelope (`AgentExtension` in A2A Agent Cards, per #1786 scope)
- **Reference:** [`agentgraph.co/.well-known/cte-test-vectors.json`](https://agentgraph.co/.well-known/cte-test-vectors.json) → `.claim_model.claim_type.closed_set`

### HiveTrust internal-schema `claim_type` (local)

- **Owner:** HiveTrust `src/services/insurance.js`, persisted in `claims.claim_type` column
- **Role:** Underwriting + audit discriminator (role/capability/audit)
- **Closed set:** `{non_delivery, fraud, sla_breach, data_loss, unauthorized_action}`
- **Where it rides:** HiveTrust claim record, inner payload of any CTEF-composed envelope HiveTrust authors
- **Projection onto CTEF:** All five HiveTrust values project onto `ctef.envelope.claim_type = "authority"` (role/capability assertion layer) when composed into an outer CTEF envelope. Projection is lossy in one direction (HiveTrust → CTEF drops risk-tier, counterparty history, CLOAzK hash) and identity in the other.

## Composed envelope shape

```json
{
  "type": "TrustAttestation",
  "version": "1.0.0",
  "claim_type": "authority",              // CTEF envelope-level (layer discriminator)
  "provider": { "id": "did:web:hivetrust.onrender.com", "category": "parametric-insurance" },
  "subject": { "did": "did:hive:<uuid>" },
  "attestation": {
    "payload": {
      "claim_type": "sla_breach",         // HiveTrust internal-schema (role/capability/audit)
      "claim_category": "standard",       // HiveTrust risk-tier bucketing (local to HiveTrust)
      "evidence_basis": {
        "evidence_type": "payment_execution",
        "x402_receipt": "0x…",
        "chain": "base-8453"
      }
    }
  },
  "jws": "…"
}
```

Outer `claim_type` is the CTEF layer tag. Inner `claim_type` is the HiveTrust insurance discriminator. No verifier on either side of the envelope needs to know about the other's closed set — each validates against its own.

## Why not rename?

Renaming HiveTrust's `claim_type` to `claim_kind` (or any other token) was explicitly ruled out in [A2A#1672](https://github.com/a2aproject/A2A/issues/1672). Renaming would have:

1. Unwound the AgentGraph + AgentID + APS convergence that closed on 2026-04-24
2. Forced every HiveTrust consumer (insurance API clients, MCP tool users, W3C VC verifiers) to re-map a stable field
3. Broken backward compatibility with HiveTrust claims filed before 2026-04-25

The two-axis resolution is stronger: the token name stays, the envelope layer resolves the scope, both schemas evolve independently.

## `claim_category` (HiveTrust-local)

HiveTrust also uses `claim_category` for risk-tier bucketing (`micro | standard | institutional`). CTEF v0.3.1 renamed away from `claim_category` during the 04-24 freeze, so this token is unreserved in CTEF and fully available for HiveTrust's local use. No upstream dependency.

## Reserved evidence type

HiveTrust emits `evidence_basis.evidence_type.payment_execution` on every claim resolution (x402 receipt on Base 8453, USDC). This is a CTEF v0.3.1 reserved value — the full shape lands in v0.3.2. Anchors the reputation-portability surface across A2A / Kind 30085 / ERC-8004 bridges (see [crewAIInc/crewAI#4560](https://github.com/crewAIInc/crewAI/issues/4560)).

## IP provenance

The underlying cryptographic primitives for the envelope composition rule are under USPTO provisional protection:

- App No. **64/049,200** — Spectral-Banded Compliance Stamping (priority 2026-04-24)
- App No. **64/049,207** — .smsh Lexicon + ZK Visibility (priority 2026-04-24)
- App No. **64/049,226** — Invisible Juggernaut (ZK-Spend Trees, evidence surface) (priority 2026-04-24)

The namespace convention in this document is HiveTrust-local and is not itself claimed. The envelope composition rule that projects HiveTrust `claim_type` onto CTEF `authority` is within the scope of the above provisionals.

— Maintainer: Stephen A. Rotzin · TheHiveryIQ / HiveTrust
