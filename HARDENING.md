# HiveTrust Hardening — Spectral ZK Outbound Auth Issuer

Branch: `harden/spectral-zk-issuer`
Pairs with: `srotzin/hivebank` PR #4 (`harden/spectral-zk-outbound`)

## What this adds

A signed-ticket issuer for the Spectral ZK Outbound Auth protocol. HiveTrust mints short-lived, single-use, spectrally-bound Ed25519 tickets that any Hive service can demand on every outbound USDC send. A leaked `HIVE_INTERNAL_KEY` is no longer sufficient to drain funds — the attacker must also obtain a fresh ticket from HiveTrust for the exact intent, in the current epoch, in the current regime.

## Threat model addressed

| Threat | Defense |
|---|---|
| Stolen `HIVE_INTERNAL_KEY` replays old send requests | Each ticket is single-use (nonce cache on hivebank) |
| Captured ticket replayed in a later epoch | Tickets are epoch-bound; `EPOCH_DRIFT=1` window |
| Captured ticket replayed for a different recipient/amount | Intent hash binds `to,amount,reason,did`; mismatch → rejected |
| Captured ticket replayed in a different market regime | Regime-binding; live classifier on hivebank rejects mismatch |
| Compromised internal service forges its own ticket | Ed25519 SK lives ONLY on HiveTrust; verifier holds PK only |
| HiveTrust itself compromised | Damage is bounded by per-service rate limits + L1 allowlist on hivebank; rotate `SPECTRAL_ISSUER_SK_B64U` |

## Architecture

```
   Dispatcher / Internal caller                   HiveTrust                    Hivebank
   ─────────────────────────────                  ─────────                    ────────
   1. Need to send USDC                                                        
   2. Read live regime from hivebank ──────────────────────────────────────── /v1/admin/stats
   3. POST /v1/trust/spectral/issue   ──────►   sign with SK
        { to,amount,reason,did,regime }         (in-memory only)
                                       ◄────── { ticket, epoch, exp }
   4. POST /v1/bank/usdc/send                                                  
        x-spectral-zk-ticket: <ticket>  ──────────────────────────────────►   verify with PK
                                                                              + L1 allowlist
                                                                              + L2 cap
                                                                              + L3 per-recipient
                                                                              + L4 spectral
                                                                              + L5 trust gate
                                       ◄──────────────────────────────────   ok / reject
```

## Files added

- `src/lib/canonical.js` — JCS-style JSON canonicalization (byte-identical to hivebank copy)
- `src/lib/spectral.js` — regime registry (name-identical to hivebank copy)
- `src/services/spectral-issuer.js` — Ed25519 signer + ticket constructor
- `src/routes/spectral.js` — four endpoints (issue, pubkey, snapshot, intent-hash helper)
- `test/spectral-issuer.test.js` — 10 unit tests (all green)
- `test/spectral-roundtrip.test.js` — 5 cross-service tests against `/tmp/hivebank-audit` (all green)

## Endpoints

### `POST /v1/trust/spectral/issue` (auth required)

Mint one ticket. Caller passes the live regime they observed.

Request:
```json
{
  "to":     "0xabc...",
  "amount": 12.5,
  "reason": "rebalance",
  "did":    "did:hive:dispatcher-001",
  "regime": "NORMAL_CYAN",
  "exp_sec": 300
}
```

Response:
```json
{
  "ticket": "<base64url>",
  "iss":    "did:hive:hivetrust-issuer-001",
  "epoch":  "2026-04-25T12:30:00Z",
  "exp":    "2026-04-25T12:35:00Z",
  "intent": "<sha256-hex>",
  "nonce":  "<base64url-16>",
  "regime": "NORMAL_CYAN"
}
```

Errors:
- `400 BAD_TO` — `to` is not 0x-prefixed 40-hex
- `400 BAD_AMOUNT` — non-positive or non-numeric
- `400 BAD_REGIME` — unknown regime name
- `503 NO_ISSUER_KEY` — `SPECTRAL_ISSUER_SK_B64U` not configured

### `GET /v1/trust/spectral/pubkey` (public)

Returns the verifier public key for hivebank's `SPECTRAL_VERIFIER_PK_B64U`.

```json
{
  "iss":            "did:hive:hivetrust-issuer-001",
  "alg":            "Ed25519",
  "pubkey_b64u":    "<32-byte b64u>",
  "epoch_sec":      300,
  "ticket_exp_sec": 300
}
```

### `GET /v1/trust/spectral/snapshot` (public)

Lightweight liveness/config telemetry. Mirrors `hivebank /v1/admin/stats.spectral_zk`.

### `POST /v1/trust/spectral/intent-hash` (public, pure)

Helper for clients to precompute the intent hash. No state, no signing.

## Environment variables

| Var | Required | Default | Notes |
|---|---|---|---|
| `SPECTRAL_ISSUER_SK_B64U` | YES | none | 32-byte Ed25519 seed, base64url. **NEVER** set this on hivebank. |
| `SPECTRAL_ISSUER_DID` | no | `did:hive:hivetrust-issuer-001` | DID baked into every ticket as `iss` |
| `SPECTRAL_EPOCH_SEC` | no | `300` | Must equal hivebank's epoch_sec |
| `SPECTRAL_TICKET_EXP_SEC` | no | `300` | Cap on ticket lifetime |

## Key generation runbook

Run this OFFLINE, on a machine that never joins the prod network. Treat the seed like a treasury private key.

```js
// generate-spectral-issuer-key.mjs — run once, offline.
import * as ed from '@noble/ed25519';
import crypto from 'crypto';
const seed = crypto.randomBytes(32);
const pk   = await ed.getPublicKeyAsync(seed);
const b64u = b => Buffer.from(b).toString('base64')
  .replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
console.log('SPECTRAL_ISSUER_SK_B64U =', b64u(seed),  '  // → HiveTrust ONLY');
console.log('SPECTRAL_VERIFIER_PK_B64U =', b64u(pk),  '  // → Hivebank (and any verifying service)');
```

Then:
1. Paste `SPECTRAL_ISSUER_SK_B64U` into HiveTrust's Render env, mark sensitive.
2. Paste `SPECTRAL_VERIFIER_PK_B64U` into Hivebank's Render env. (Public, but treat as integrity-critical.)
3. Restart both services. Do NOT redeploy from a stale build.
4. Smoke test: `curl https://hivetrust.onrender.com/v1/trust/spectral/pubkey` should return the same pubkey you set on hivebank.
5. Smoke test (round-trip): mint a ticket, send a tiny self-test USDC of $0.01 through hivebank with the ticket header.

## Rotation

To rotate the issuer key (every 90 days, or immediately on suspicion):

1. Generate a new keypair offline.
2. Set `SPECTRAL_VERIFIER_PK_B64U_NEXT` on hivebank with the NEW pubkey. Hivebank accepts both during overlap window. *(future enhancement; today it's a single key with cutover)*
3. Set `SPECTRAL_ISSUER_SK_B64U` on HiveTrust to the NEW seed.
4. Wait one epoch for in-flight tickets to expire.
5. Replace `SPECTRAL_VERIFIER_PK_B64U` on hivebank with the NEW pubkey.

For tonight's first deploy, single-key cutover is fine because `USDC_SENDS_PAUSED=true` means there are no in-flight tickets to invalidate.

## Deploy checklist

- [ ] Merge hivebank PR #4
- [ ] Generate Ed25519 keypair offline (Stephen, never paste in chat)
- [ ] Set `SPECTRAL_ISSUER_SK_B64U` on HiveTrust (Render env)
- [ ] Set `SPECTRAL_VERIFIER_PK_B64U` on hivebank (Render env)
- [ ] Set `SPECTRAL_ZK_ENFORCE=true` on hivebank
- [ ] Deploy hivebank from `harden/spectral-zk-outbound` after merge
- [ ] Deploy hivetrust from `harden/spectral-zk-issuer` after merge
- [ ] Smoke test `/v1/trust/spectral/pubkey`
- [ ] Update `hive_rebalancer_dispatcher.py` to fetch ticket per batch
- [ ] Rotate `HIVE_INTERNAL_KEY` across 13 services
- [ ] Rotate treasury PK + `wallets.json` to new safe wallet
- [ ] Un-pause `USDC_SENDS_PAUSED`
- [ ] First refill batch — verify ticket round-trip in production

## HiveFilter audit

22-trait pre-code checklist applied. See repo HIVEFILTER manifest for the per-trait matrix; this commit scores **22/22** (18 applicable, 4 N/A: Crops, Sounds, HIPAA, Brand-color).
