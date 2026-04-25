// HiveTrust — Spectral ZK Outbound Auth Issuer.
//
// Mints short-lived, single-use Ed25519-signed tickets that hivebank and any
// other Hive service can demand on every outbound USDC send.
//
// SECURITY MODEL
// ──────────────
// The Ed25519 secret key (32-byte seed, base64url) lives ONLY in this
// service's environment as `SPECTRAL_ISSUER_SK_B64U`. It is never logged,
// never returned over the wire, never written to disk. Hivebank holds the
// matching public key only.
//
// The canonicalization is byte-identical to
// hivebank/src/services/spectral-zk-auth.js — any drift breaks verification.

import * as ed from '@noble/ed25519';
import crypto from 'crypto';
import { canonicalize, canonicalBytes } from '../lib/canonical.js';
import { isValidRegime } from '../lib/spectral.js';

// ─── Config ──────────────────────────────────────────────────────────────────
const ISSUER_SK_B64U = process.env.SPECTRAL_ISSUER_SK_B64U || '';
const ISSUER_DID     = process.env.SPECTRAL_ISSUER_DID || 'did:hive:hivetrust-issuer-001';
const EPOCH_SEC      = parseInt(process.env.SPECTRAL_EPOCH_SEC || '300', 10);
const TICKET_EXP_SEC = parseInt(process.env.SPECTRAL_TICKET_EXP_SEC || '300', 10);

// Cache the loaded secret key bytes once on first use.
let _skBytes = null;
let _pkBytes = null;

function loadSk() {
  if (_skBytes) return _skBytes;
  if (!ISSUER_SK_B64U) {
    const e = new Error('SPECTRAL_ISSUER_SK_B64U not configured on HiveTrust');
    e.code = 'NO_ISSUER_KEY';
    throw e;
  }
  _skBytes = b64uToBytes(ISSUER_SK_B64U);
  if (_skBytes.length !== 32) {
    const e = new Error(`SPECTRAL_ISSUER_SK_B64U must decode to 32 bytes (got ${_skBytes.length})`);
    e.code = 'BAD_KEY_LEN';
    throw e;
  }
  return _skBytes;
}

async function loadPk() {
  if (_pkBytes) return _pkBytes;
  _pkBytes = await ed.getPublicKeyAsync(loadSk());
  return _pkBytes;
}

// ─── Helpers ────────────────────────────────────────────────────────────────
function bytesToB64u(b) {
  return Buffer.from(b).toString('base64')
    .replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function b64uToBytes(s) {
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const std = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(std, 'base64');
}

function currentEpoch(now = Date.now()) {
  const bucketed = Math.floor(now / 1000 / EPOCH_SEC) * EPOCH_SEC;
  return new Date(bucketed * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

// Compute sha256(canonicalize({to, amount, reason, did})) — must match the
// `intentHash` function in hivebank/src/services/spectral-zk-auth.js.
export function intentHash({ to, amount, reason, did }) {
  const norm = canonicalize({
    to:     String(to || '').toLowerCase(),
    amount: Number(amount).toFixed(6),
    reason: reason || '',
    did:    did || '',
  });
  return crypto.createHash('sha256').update(norm).digest('hex');
}

// ─── Public API ─────────────────────────────────────────────────────────────
//
// issueTicket — sign one ticket. Returns the base64url-encoded ticket string
// the caller will pass as the `x-spectral-zk-ticket` header to hivebank.
//
// args:
//   to        — destination address (0x-hex)
//   amount    — USDC amount (number)
//   reason    — outbound route tag, e.g. 'rebalance', 'rewards', 'pay'
//   did       — caller's hive DID (for audit only; hashed into intent)
//   regime    — current spectral regime as observed by the requester
//               (hivebank /v1/admin/stats.outbound_guard.snapshot.last_regime)
//   exp_sec   — optional, defaults to TICKET_EXP_SEC, capped at TICKET_EXP_SEC
//
export async function issueTicket({ to, amount, reason, did, regime, exp_sec }) {
  if (!to || !/^0x[a-fA-F0-9]{40}$/.test(to)) {
    const e = new Error('to must be a 0x-prefixed 40-hex-char address');
    e.code = 'BAD_TO'; e.status = 400; throw e;
  }
  if (!Number.isFinite(Number(amount)) || Number(amount) <= 0) {
    const e = new Error('amount must be a positive number');
    e.code = 'BAD_AMOUNT'; e.status = 400; throw e;
  }
  if (!regime || !isValidRegime(regime)) {
    const e = new Error(`regime must be one of the published spectral regimes (got ${regime})`);
    e.code = 'BAD_REGIME'; e.status = 400; throw e;
  }

  const expSec = Math.min(parseInt(exp_sec ?? TICKET_EXP_SEC, 10), TICKET_EXP_SEC);
  const epoch = currentEpoch();
  const exp   = new Date(Date.now() + expSec * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const nonce = bytesToB64u(crypto.randomBytes(16));
  const intent = intentHash({ to, amount, reason, did });

  const ticket = {
    v: 1,
    iss: ISSUER_DID,
    epoch,
    regime: String(regime).toUpperCase(),
    intent,
    nonce,
    exp,
  };

  const bytes = canonicalBytes(ticket);
  const sig = await ed.signAsync(bytes, loadSk());
  ticket.sig = bytesToB64u(sig);

  const ticketB64u = bytesToB64u(Buffer.from(canonicalize(ticket), 'utf8'));

  return {
    ticket: ticketB64u,
    iss: ISSUER_DID,
    epoch,
    exp,
    intent,
    nonce,
    regime: ticket.regime,
  };
}

export async function getIssuerPubkey() {
  const pk = await loadPk();
  return {
    iss: ISSUER_DID,
    alg: 'Ed25519',
    pubkey_b64u: bytesToB64u(pk),
    epoch_sec: EPOCH_SEC,
    ticket_exp_sec: TICKET_EXP_SEC,
  };
}

export function snapshot() {
  return {
    issuer_configured: !!ISSUER_SK_B64U,
    iss: ISSUER_DID,
    epoch_sec: EPOCH_SEC,
    ticket_exp_sec: TICKET_EXP_SEC,
    current_epoch: currentEpoch(),
  };
}
