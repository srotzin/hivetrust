/**
 * smash.prov — Ed25519 signature middleware (ESM)
 * did:hive:hivetrust
 *
 * Doctrine: Every discovery surface (200 response) must ship Ed25519
 * signature headers so any agent can verify provenance for free, without paying.
 */
import * as ed from '@noble/ed25519';
import { createHash, randomBytes } from 'crypto';
import { readFileSync, writeFileSync, existsSync } from 'fs';

export const PROV_SERVICE_DID = 'did:hive:hivetrust';
const SEED_FILE        = '/tmp/.hive_prov_seed';
const PROV_PUBKEY_PATH = '/v1/prov/pubkey';

let _privKey = null;
let _pubKey  = null;

function b64uEncode(buf) { return Buffer.from(buf).toString('base64url'); }
function b64uDecode(str) { return Buffer.from(str, 'base64url'); }

export async function loadOrCreateKey() {
  if (_privKey) return { privKey: _privKey, pubKey: _pubKey };
  let seed = null;
  const envSeed = (process.env.HIVE_PROV_SEED || '').trim();
  if (envSeed) { try { const d = b64uDecode(envSeed); if (d.length === 32) seed = d; } catch (_) {} }
  if (!seed && existsSync(SEED_FILE)) { try { const r = readFileSync(SEED_FILE); if (r.length === 32) seed = r; } catch (_) {} }
  if (!seed) { seed = randomBytes(32); try { writeFileSync(SEED_FILE, seed, { mode: 0o600 }); } catch (_) {} }
  _privKey = Uint8Array.from(seed);
  _pubKey  = await ed.getPublicKeyAsync(_privKey);
  return { privKey: _privKey, pubKey: _pubKey };
}

export async function getPubkeyInfo() {
  const { pubKey } = await loadOrCreateKey();
  return { issuer: PROV_SERVICE_DID, algorithm: 'Ed25519', pubkey_b64u: b64uEncode(pubKey), pubkey_hex: Buffer.from(pubKey).toString('hex'), doctrine: 'smash.prov — every door 200s, every byte signed' };
}

export async function signResponse(method, path, bodyBytes, ts) {
  const { privKey } = await loadOrCreateKey();
  if (ts == null) ts = Math.floor(Date.now() / 1000);
  const bodyHash = b64uEncode(createHash('sha256').update(bodyBytes || Buffer.alloc(0)).digest());
  const payload  = `${method.toUpperCase()} ${path} ${bodyHash} ${ts}`;
  const sigBytes = await ed.signAsync(Buffer.from(payload, 'ascii'), privKey);
  return { 'X-Hive-Prov-Iss': PROV_SERVICE_DID, 'X-Hive-Prov-Ts': String(ts), 'X-Hive-Prov-Sig': b64uEncode(sigBytes), 'X-Hive-Prov-Pubkey': PROV_PUBKEY_PATH, 'X-Hive-Prov-Payload': payload };
}

const STAMP_EXACT = new Set(['/', '/health', '/llms.txt', '/robots.txt', '/sitemap.xml', '/favicon.ico', '/openapi.json', '/docs', '/redoc', '/.well-known/agent.json', '/v1/prov/pubkey']);
const STAMP_PREFIX = ['/.well-known/', '/v1/x402/', '/v1/prov/', '/v1/a2a/'];

export function shouldStamp(path) {
  if (STAMP_EXACT.has(path)) return true;
  return STAMP_PREFIX.some(p => path.startsWith(p));
}

export function smashProvMiddleware(req, res, next) {
  const originalSend = res.send.bind(res);
  res.send = async function provSend(body) {
    const path = req.path || '/';
    const stamp = shouldStamp(path) || (res.statusCode || 200) === 200;
    if (stamp) {
      try {
        let bodyBuf = Buffer.isBuffer(body) ? body : typeof body === 'string' ? Buffer.from(body, 'utf8') : body == null ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body), 'utf8');
        const headers = await signResponse(req.method, path, bodyBuf);
        for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
        res.setHeader('Access-Control-Expose-Headers', 'X-Hive-Prov-Iss, X-Hive-Prov-Ts, X-Hive-Prov-Sig, X-Hive-Prov-Pubkey, X-Hive-Prov-Payload');
      } catch (err) { console.error('[smash.prov] signing error:', err.message); }
    }
    return originalSend(body);
  };
  next();
}

export async function verifyProvSig({ method, path, body_b64u = '', ts, sig_b64u }) {
  const bodyBytes = body_b64u ? b64uDecode(body_b64u) : Buffer.alloc(0);
  const bodyHash  = b64uEncode(createHash('sha256').update(bodyBytes).digest());
  const payload   = `${method.toUpperCase()} ${path} ${bodyHash} ${ts}`;
  const { pubKey } = await loadOrCreateKey();
  const sigBytes   = b64uDecode(sig_b64u);
  let valid = false;
  try { valid = await ed.verifyAsync(sigBytes, Buffer.from(payload, 'ascii'), pubKey); } catch (_) {}
  const skew = Math.abs(Math.floor(Date.now() / 1000) - Number(ts));
  return { valid, fresh: skew <= 300, skew_seconds: skew, issuer: PROV_SERVICE_DID, payload };
}
