// HiveTrust — Hive Supermodel Schema v1 unit tests.
//
// Run: node --test test/supermodel-schema.test.js

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  SUPERMODEL_CONTEXT_V1,
  SUPERMODEL_SPEC_V1,
  validateSupermodelClaims,
} from '../src/lib/supermodel-schema.js';

// ─── @context shape ─────────────────────────────────────────────────────────

test('SUPERMODEL_CONTEXT_V1 declares the HiveSupermodelCredential type', () => {
  assert.ok(SUPERMODEL_CONTEXT_V1['@context']);
  assert.ok(SUPERMODEL_CONTEXT_V1['@context'].HiveSupermodelCredential);
  const cred = SUPERMODEL_CONTEXT_V1['@context'].HiveSupermodelCredential;
  assert.equal(cred['@id'], 'hsm:HiveSupermodelCredential');
  // Core fields must be present in the inner @context
  for (const f of [
    'codename', 'wallet', 'pool_disposition', 'pool_workers',
    'tier_target', 'contrail_color', 'carousel_priority',
    'roster_position', 'issued_at',
  ]) {
    assert.ok(cred['@context'][f], `missing field in context: ${f}`);
  }
});

test('SUPERMODEL_SPEC_V1 advertises the canonical context URL + credential type', () => {
  assert.equal(SUPERMODEL_SPEC_V1.credential_type, 'HiveSupermodelCredential');
  assert.match(
    SUPERMODEL_SPEC_V1.context,
    /^https:\/\/.+\/v1\/trust\/schema\/supermodel\/v1\.jsonld$/,
  );
  assert.equal(SUPERMODEL_SPEC_V1.proof_format, 'Ed25519Signature2020');
});

// ─── Validator: happy path ──────────────────────────────────────────────────

test('validateSupermodelClaims accepts a complete valid claim', () => {
  const r = validateSupermodelClaims({
    codename: 'LOREN',
    vibe: 'Sophia — disciplined, prolific, classic',
    wallet: '0x6b11b1bcaf253c6a4e6f72f9d8827a69c3df3c72',
    wallet_chain: 'base',
    pool_disposition: 'kimi1',
    pool_workers: ['Hive3', 'Hive4'],
    tier_target: 'FENR',
    contrail_color: 'garnet',
    carousel_priority: ['compute_prime'],
    roster_position: 2,
  });
  assert.equal(r.ok, true);
});

test('validateSupermodelClaims accepts the minimum required fields', () => {
  const r = validateSupermodelClaims({
    codename: 'WELCH',
    wallet: '0x653ad34dcb283f50f2317a6cadec4dd1f7e94456',
    pool_disposition: 'kimi2',
  });
  assert.equal(r.ok, true);
});

// ─── Validator: rejection paths ─────────────────────────────────────────────

test('validateSupermodelClaims rejects missing codename', () => {
  const r = validateSupermodelClaims({
    wallet: '0x6b11b1bcaf253c6a4e6f72f9d8827a69c3df3c72',
    pool_disposition: 'kimi1',
  });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'MISSING_CODENAME');
});

test('validateSupermodelClaims rejects lowercase codename', () => {
  const r = validateSupermodelClaims({
    codename: 'loren',
    wallet: '0x6b11b1bcaf253c6a4e6f72f9d8827a69c3df3c72',
    pool_disposition: 'kimi1',
  });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'INVALID_CODENAME');
});

test('validateSupermodelClaims rejects malformed wallet address', () => {
  const r = validateSupermodelClaims({
    codename: 'LOREN',
    wallet: '0xnotahex',
    pool_disposition: 'kimi1',
  });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'INVALID_WALLET');
});

test('validateSupermodelClaims rejects unknown pool_disposition', () => {
  const r = validateSupermodelClaims({
    codename: 'LOREN',
    wallet: '0x6b11b1bcaf253c6a4e6f72f9d8827a69c3df3c72',
    pool_disposition: 'farmville',
  });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'INVALID_POOL_DISPOSITION');
});

test('validateSupermodelClaims rejects unknown tier_target', () => {
  const r = validateSupermodelClaims({
    codename: 'LOREN',
    wallet: '0x6b11b1bcaf253c6a4e6f72f9d8827a69c3df3c72',
    pool_disposition: 'kimi1',
    tier_target: 'BANANA',
  });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'INVALID_TIER_TARGET');
});

test('validateSupermodelClaims rejects out-of-range roster_position', () => {
  const r = validateSupermodelClaims({
    codename: 'LOREN',
    wallet: '0x6b11b1bcaf253c6a4e6f72f9d8827a69c3df3c72',
    pool_disposition: 'kimi1',
    roster_position: 0,
  });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'INVALID_ROSTER_POSITION');
});
