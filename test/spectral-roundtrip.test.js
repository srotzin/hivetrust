// Cross-service round-trip: HiveTrust issuer → Hivebank verifier.
//
// This is the test that proves the harden branch works end-to-end. If
// canonicalization, regime names, intent-hash, or signature scheme drift
// between the two services even by one byte, this test fails.
//
// Requires the hivebank harden tree at /tmp/hivebank-audit (CommonJS) and
// the hivetrust harden tree (this repo, ESM). We use createRequire to load
// the CJS verifier from inside this ESM test.
//
// Run: node --test test/spectral-roundtrip.test.js

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import crypto from 'node:crypto';
import * as ed from '@noble/ed25519';
import fs from 'node:fs';

// ─── Set up issuer key BEFORE importing the issuer module ────────────────────
const seed = crypto.randomBytes(32);
const seedB64u = seed.toString('base64')
  .replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
process.env.SPECTRAL_ISSUER_SK_B64U = seedB64u;
process.env.SPECTRAL_ISSUER_DID = 'did:hive:roundtrip-issuer';
process.env.SPECTRAL_EPOCH_SEC = '300';
process.env.SPECTRAL_TICKET_EXP_SEC = '300';

const { issueTicket, getIssuerPubkey, intentHash: issuerIntentHash } =
  await import('../src/services/spectral-issuer.js');

const HIVEBANK_PATH = '/tmp/hivebank-audit';
const HIVEBANK_VERIFIER = `${HIVEBANK_PATH}/src/services/spectral-zk-auth.js`;

const hivebankAvailable = fs.existsSync(HIVEBANK_VERIFIER);

test('hivebank tree is present for cross-service round-trip', () => {
  if (!hivebankAvailable) {
    console.warn(`SKIP: hivebank tree not at ${HIVEBANK_PATH}`);
    return;
  }
  assert.ok(fs.existsSync(HIVEBANK_VERIFIER));
});

if (!hivebankAvailable) {
  // Don't define the rest if hivebank isn't here — useful for CI separation.
  // The standalone issuer tests still run independently.
} else {
  // Configure hivebank's verifier env BEFORE loading it.
  const pk = await getIssuerPubkey();
  process.env.SPECTRAL_VERIFIER_PK_B64U = pk.pubkey_b64u;
  process.env.SPECTRAL_ZK_ENFORCE = 'true';
  process.env.SPECTRAL_ZK_BYPASS  = 'false';
  process.env.SPECTRAL_EPOCH_SEC  = '300';

  const require = createRequire(import.meta.url);
  // Adjust hivebank module resolution to its own node_modules
  const hivebankRequire = createRequire(`${HIVEBANK_PATH}/package.json`);
  let zkAuth, outboundGuard;
  try {
    zkAuth = hivebankRequire('./src/services/spectral-zk-auth.js');
    outboundGuard = hivebankRequire('./src/services/outbound-guard.js');
  } catch (e) {
    console.warn(`SKIP hivebank load: ${e.message}`);
  }

  if (zkAuth) {
    test('issuer-minted ticket verifies in hivebank with matching intent + regime', async () => {
      const ctx = {
        toAddress: '0x' + 'b'.repeat(40),
        amountUsdc: 7.25,
        reason: 'rebalance',
        hiveDid: 'did:hive:dispatcher-001',
      };
      const intent_hex = zkAuth.intentHash(ctx);

      // Sanity: my issuer's intentHash agrees with hivebank's
      const issuerIntent = issuerIntentHash({
        to: ctx.toAddress,
        amount: ctx.amountUsdc,
        reason: ctx.reason,
        did: ctx.hiveDid,
      });
      assert.equal(intent_hex, issuerIntent, 'intentHash MUST be byte-identical');

      // Empty ring → live regime is WARMUP — sign with WARMUP
      const r = await issueTicket({
        to: ctx.toAddress,
        amount: ctx.amountUsdc,
        reason: ctx.reason,
        did: ctx.hiveDid,
        regime: 'WARMUP',
      });

      const result = await zkAuth.verifyTicket(r.ticket, intent_hex, []);
      assert.equal(result.ok, true, `verify failed: ${result.code} ${result.detail}`);
      assert.equal(result.code, 'OK');
    });

    test('hivebank rejects ticket with mismatched intent', async () => {
      const r = await issueTicket({
        to: '0x' + 'c'.repeat(40),
        amount: 1.0,
        reason: 'rebalance',
        did: 'did:hive:dispatcher-001',
        regime: 'WARMUP',
      });
      // Compute a DIFFERENT intent
      const wrongIntent = zkAuth.intentHash({
        toAddress: '0x' + 'd'.repeat(40),
        amountUsdc: 1.0,
        reason: 'rebalance',
        hiveDid: 'did:hive:dispatcher-001',
      });
      const result = await zkAuth.verifyTicket(r.ticket, wrongIntent, []);
      assert.equal(result.ok, false);
      assert.equal(result.code, 'INTENT_MISMATCH');
    });

    test('nonce replay is caught on second verify of the same ticket', async () => {
      const ctx = {
        toAddress: '0x' + 'e'.repeat(40),
        amountUsdc: 2.5,
        reason: 'rewards',
        hiveDid: 'did:hive:dispatcher-001',
      };
      const intent_hex = zkAuth.intentHash(ctx);
      const r = await issueTicket({
        to: ctx.toAddress,
        amount: ctx.amountUsdc,
        reason: ctx.reason,
        did: ctx.hiveDid,
        regime: 'WARMUP',
      });
      const a = await zkAuth.verifyTicket(r.ticket, intent_hex, []);
      assert.equal(a.ok, true);
      const b = await zkAuth.verifyTicket(r.ticket, intent_hex, []);
      assert.equal(b.ok, false);
      assert.equal(b.code, 'NONCE_REPLAY');
    });

    test('hivebank rejects ticket signed by a different key', async () => {
      // Tamper: re-sign the inner payload with a DIFFERENT seed
      const r = await issueTicket({
        to: '0x' + 'f'.repeat(40),
        amount: 1.0,
        reason: 'rebalance',
        did: 'did:hive:dispatcher-001',
        regime: 'WARMUP',
      });
      const decoded = JSON.parse(Buffer.from(
        r.ticket.replace(/-/g, '+').replace(/_/g, '/') +
          '='.repeat((4 - (r.ticket.length % 4)) % 4),
        'base64',
      ).toString('utf8'));

      const evilSeed = crypto.randomBytes(32);
      const { sig, ...payload } = decoded;
      const canonical = (v) => {
        if (v === null || typeof v !== 'object') return JSON.stringify(v);
        if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
        const keys = Object.keys(v).sort();
        return '{' + keys
          .filter(k => v[k] !== undefined)
          .map(k => JSON.stringify(k) + ':' + canonical(v[k]))
          .join(',') + '}';
      };
      const evilBytes = Buffer.from(canonical(payload), 'utf8');
      const evilSig = await ed.signAsync(evilBytes, evilSeed);
      const tampered = { ...payload, sig: Buffer.from(evilSig).toString('base64')
        .replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_') };
      const tamperedB64u = Buffer.from(canonical(tampered), 'utf8').toString('base64')
        .replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');

      const intent = zkAuth.intentHash({
        toAddress: '0x' + 'f'.repeat(40),
        amountUsdc: 1.0,
        reason: 'rebalance',
        hiveDid: 'did:hive:dispatcher-001',
      });
      const result = await zkAuth.verifyTicket(tamperedB64u, intent, []);
      assert.equal(result.ok, false);
      assert.equal(result.code, 'BAD_SIGNATURE');
    });
  }
}
