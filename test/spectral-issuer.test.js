// HiveTrust — Spectral Issuer unit tests.
//
// Run: node --test test/spectral-issuer.test.js
//
// Generates a fresh Ed25519 keypair per run, sets it as the issuer SK env
// var, then exercises issue/verify round-trip and edge cases.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as ed from '@noble/ed25519';
import crypto from 'crypto';

// ─── Set up issuer key BEFORE importing the issuer module ────────────────────
const seed = crypto.randomBytes(32);
const seedB64u = seed.toString('base64')
  .replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
process.env.SPECTRAL_ISSUER_SK_B64U = seedB64u;
process.env.SPECTRAL_ISSUER_DID = 'did:hive:test-issuer';
process.env.SPECTRAL_EPOCH_SEC = '300';
process.env.SPECTRAL_TICKET_EXP_SEC = '300';

const { issueTicket, getIssuerPubkey, snapshot, intentHash } =
  await import('../src/services/spectral-issuer.js');

// ─── Helpers ────────────────────────────────────────────────────────────────
function b64uToBytes(s) {
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const std = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(std, 'base64');
}

function canonicalize(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalize).join(',') + ']';
  const keys = Object.keys(v).sort();
  const parts = [];
  for (const k of keys) {
    if (v[k] === undefined) continue;
    parts.push(JSON.stringify(k) + ':' + canonicalize(v[k]));
  }
  return '{' + parts.join(',') + '}';
}

const VALID = {
  to: '0x' + 'a'.repeat(40),
  amount: 12.5,
  reason: 'rebalance',
  did: 'did:hive:test-caller',
  regime: 'NORMAL_CYAN',
};

// ─── Tests ──────────────────────────────────────────────────────────────────

test('issueTicket returns a base64url-decodable, sig-bearing ticket', async () => {
  const r = await issueTicket(VALID);
  assert.ok(r.ticket);
  assert.equal(r.iss, 'did:hive:test-issuer');
  assert.equal(r.regime, 'NORMAL_CYAN');

  const decoded = JSON.parse(b64uToBytes(r.ticket).toString('utf8'));
  assert.equal(decoded.v, 1);
  assert.ok(decoded.sig);
  assert.equal(decoded.iss, 'did:hive:test-issuer');
  assert.equal(decoded.regime, 'NORMAL_CYAN');
  assert.equal(decoded.intent, intentHash(VALID));
});

test('signature verifies against the published pubkey (round-trip)', async () => {
  const r = await issueTicket(VALID);
  const pk = await getIssuerPubkey();
  const pkBytes = b64uToBytes(pk.pubkey_b64u);

  const decoded = JSON.parse(b64uToBytes(r.ticket).toString('utf8'));
  const { sig, ...payload } = decoded;
  const bytes = Buffer.from(canonicalize(payload), 'utf8');

  const valid = await ed.verifyAsync(b64uToBytes(sig), bytes, pkBytes);
  assert.equal(valid, true, 'issuer signature must verify against published pubkey');
});

test('rejects bad to address', async () => {
  await assert.rejects(
    () => issueTicket({ ...VALID, to: 'not-an-address' }),
    /to must be a 0x-prefixed/,
  );
  await assert.rejects(
    () => issueTicket({ ...VALID, to: '0x123' }),
    /to must be a 0x-prefixed/,
  );
});

test('rejects bad amount', async () => {
  await assert.rejects(
    () => issueTicket({ ...VALID, amount: 0 }),
    /amount must be a positive number/,
  );
  await assert.rejects(
    () => issueTicket({ ...VALID, amount: -5 }),
    /amount must be a positive number/,
  );
  await assert.rejects(
    () => issueTicket({ ...VALID, amount: 'banana' }),
    /amount must be a positive number/,
  );
});

test('rejects unknown regime', async () => {
  await assert.rejects(
    () => issueTicket({ ...VALID, regime: 'BANANA_PURPLE' }),
    /regime must be one of the published spectral regimes/,
  );
});

test('intentHash is deterministic and case-insensitive on `to`', () => {
  const h1 = intentHash({ to: '0xABC', amount: 1, reason: 'x', did: 'did:y' });
  const h2 = intentHash({ to: '0xabc', amount: 1, reason: 'x', did: 'did:y' });
  assert.equal(h1, h2);

  const h3 = intentHash({ to: '0xabc', amount: 1.000000, reason: 'x', did: 'did:y' });
  assert.equal(h1, h3, 'amount.toFixed(6) normalizes representation');
});

test('two tickets for the same intent have different nonces', async () => {
  const a = await issueTicket(VALID);
  const b = await issueTicket(VALID);
  assert.notEqual(a.nonce, b.nonce, 'replay protection requires fresh nonce');
});

test('exp_sec is capped at TICKET_EXP_SEC', async () => {
  const r = await issueTicket({ ...VALID, exp_sec: 999999 });
  const expMs = new Date(r.exp).getTime();
  const nowMs = Date.now();
  assert.ok(expMs - nowMs <= 305_000, 'exp must be capped near 300s');
});

test('snapshot reports issuer configured', () => {
  const s = snapshot();
  assert.equal(s.issuer_configured, true);
  assert.equal(s.iss, 'did:hive:test-issuer');
  assert.equal(s.epoch_sec, 300);
  assert.equal(s.ticket_exp_sec, 300);
  assert.match(s.current_epoch, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
});

test('pubkey endpoint returns 32-byte public key', async () => {
  const pk = await getIssuerPubkey();
  assert.equal(pk.alg, 'Ed25519');
  const pkBytes = b64uToBytes(pk.pubkey_b64u);
  assert.equal(pkBytes.length, 32);
});
