/**
 * HiveTrust — MPP (Machine Payments Protocol) Middleware
 *
 * Runs ALONGSIDE existing x402 middleware. Either rail satisfies payment.
 * Implements IETF draft-ryan-httpauth-payment Payment header scheme.
 * MPP receipts emit Spectral receipts with payment_method: "mpp".
 *
 * Treasury: Monroe Base 0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E
 * Tempo RPC: https://rpc.tempo.xyz
 * Tempo treasury: same Monroe Base address (EVM-compatible)
 *
 * References:
 *   https://github.com/wevm/mppx
 *   https://datatracker.ietf.org/doc/draft-ryan-httpauth-payment/
 *   https://github.com/tempoxyz/mpp
 */

// ─── Configuration ───────────────────────────────────────────

const PAYMENT_ADDRESS = (
  process.env.HIVE_PAYMENT_ADDRESS ||
  process.env.HIVETRUST_PAYMENT_ADDRESS ||
  '0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E'
).toLowerCase();

const TEMPO_RPC_URL = process.env.TEMPO_RPC_URL || 'https://rpc.tempo.xyz';
const BASE_RPC_URL  = process.env.BASE_RPC_URL  || 'https://mainnet.base.org';
const USDC_CONTRACT = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
// Tempo USDCe contract (TIP-20)
const TEMPO_USDCE   = '0x20c000000000000000000000b9537d11c60e8b50';
const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const RECEIPT_ENDPOINT = 'https://hive-receipt.onrender.com/v1/receipt/sign';

// In-memory MPP payment cache (TTL 10 min)
const mppPaymentCache = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of mppPaymentCache) {
    if (now - v.timestamp > 600_000) mppPaymentCache.delete(k);
  }
}, 60_000);

// ─── Spectral Receipt (non-blocking) ─────────────────────────

async function emitMppSpectralReceipt({ path, amount, txHash, rail }) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4_000);
    await fetch(RECEIPT_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({
        issuer_did:     'did:hive:hivetrust',
        event_type:     'api_payment',
        amount_usd:     amount,
        currency:       'USDC',
        network:        rail === 'tempo' ? 'tempo' : 'base',
        pay_to:         PAYMENT_ADDRESS,
        endpoint:       path,
        tx_hash:        txHash,
        payment_method: 'mpp',        // ← MPP rail identifier (vs "x402")
        rail:           rail,         // "tempo" | "base"
        timestamp:      new Date().toISOString(),
      }),
    });
    clearTimeout(timer);
  } catch (_) {
    // Non-blocking — never interrupts the fee path
  }
}

// ─── On-chain USDC verification (Base or Tempo) ──────────────

async function verifyMppOnChain(txHash, expectedAmount, rail) {
  const rpcUrl = rail === 'tempo' ? TEMPO_RPC_URL : BASE_RPC_URL;
  const usdcContract = rail === 'tempo' ? TEMPO_USDCE : USDC_CONTRACT;

  try {
    const rpcRes = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0', id: 1, method: 'eth_getTransactionReceipt',
        params: [txHash],
      }),
      signal: AbortSignal.timeout(8_000),
    });
    const { result: receipt } = await rpcRes.json();
    if (!receipt || receipt.status !== '0x1') {
      return { ok: false, reason: 'tx not confirmed or reverted' };
    }
    for (const log of receipt.logs) {
      if (
        log.address?.toLowerCase() === usdcContract &&
        log.topics?.[0] === TRANSFER_TOPIC
      ) {
        const toAddr = '0x' + log.topics[2].slice(26).toLowerCase();
        if (toAddr === PAYMENT_ADDRESS) {
          const transferAmount = parseInt(log.data, 16) / 1e6;
          if (transferAmount >= expectedAmount - 0.001) {
            return { ok: true, transferAmount };
          }
          return { ok: false, reason: `insufficient: got ${transferAmount}, need ${expectedAmount}` };
        }
      }
    }
    return { ok: false, reason: 'no matching USDC Transfer to treasury found' };
  } catch (e) {
    return { ok: false, reason: e.message };
  }
}

// ─── MPP Payment Header Parser ───────────────────────────────
//
// IETF draft-ryan-httpauth-payment Payment header format:
//   Payment: scheme="mpp", tx_hash="0x...", rail="tempo", amount="0.10"
//
// Also accepts the mppx Payment-Credential header format.

function parseMppHeader(req) {
  // Primary: IETF draft Payment header
  const paymentHdr = req.headers['payment'] || req.headers['x-payment'] || '';
  if (paymentHdr) {
    const params = {};
    for (const part of paymentHdr.split(',')) {
      const m = part.trim().match(/^([\w-]+)="([^"]*)"$/);
      if (m) params[m[1]] = m[2];
    }
    if (params.scheme === 'mpp' || params.tx_hash) {
      return {
        found:   true,
        txHash:  params.tx_hash || params.credential || '',
        rail:    params.rail || 'tempo',
        amount:  parseFloat(params.amount || '0') || null,
      };
    }
  }

  // Fallback: mppx Payment-Credential header
  const credHdr = req.headers['payment-credential'] || '';
  if (credHdr) {
    return {
      found:   true,
      txHash:  credHdr,
      rail:    req.headers['x-mpp-rail'] || 'tempo',
      amount:  parseFloat(req.headers['x-mpp-amount'] || '0') || null,
    };
  }

  return { found: false };
}

// ─── Fee table (mirrors x402 fee table exactly) ──────────────

import { getApiCallPrice } from '../services/pricing-engine.js';
import { getLeasePrice } from '../services/data-oracle.js';

const DID_CREDENTIAL_PRICING = {
  '/trust/did/generate':     1.00,
  '/trust/vc/issue':         0.50,
  '/trust/reputation/proof': 0.10,
  '/enterprise/subscribe':   500.00,
};

function getMppPrice(path, method) {
  if (DID_CREDENTIAL_PRICING[path]) return DID_CREDENTIAL_PRICING[path];
  if (path.startsWith('/trust/score/')) return 0.10;
  if (method === 'POST' && /^\/agents\/[^/]+\/credentials$/.test(path)) return 0.10;
  if (method === 'DELETE' && /^\/agents\/[^/]+\/credentials\/[^/]+$/.test(path)) return 0.10;
  // Default per-call price from pricing engine
  return getApiCallPrice().amount;
}

// ─── Free-path list (mirrors x402 isFreePath) ────────────────

const FREE_PATHS = new Set([
  '/health', '/stats', '/pricing/status', '/pricing/quote',
  '/pricing/verify-subscription', '/pricing/verify-payment',
  '/.well-known/hivetrust.json', '/.well-known/hive-payments.json',
  '/insurance/quote',
]);

function isFreePath(path) {
  if (FREE_PATHS.has(path)) return true;
  if (path.startsWith('/verify_agent_risk')) return true;
  if (path.startsWith('/pricing')) return true;
  if (path.startsWith('/identity/')) return true;
  if (path === '/trust/wallet-attestation' || path === '/trust/zk-status') return true;
  if (path === '/trust/register' || path === '/trust/issue-smsh' || path.startsWith('/trust/lookup')) return true;
  if (path.startsWith('/trust/schema/')) return true;
  if (path.startsWith('/trust/vc/supermodel')) return true;
  return false;
}

// ─── Main MPP Middleware ──────────────────────────────────────

/**
 * MPP middleware. Runs AFTER x402Middleware.
 *
 * Decision tree:
 *   1. Free path → skip (x402 already handled)
 *   2. Payment header found → verify on-chain → grant or reject
 *   3. No Payment header → do nothing (x402 or next middleware handles 402)
 *
 * The 402 WWW-Authenticate already advertises both rails from the combined
 * middleware injected in server.js. This middleware ONLY handles MPP accept.
 */
async function mppMiddleware(req, res, next) {
  // Skip free paths — already passed through x402
  if (isFreePath(req.path)) return next();

  const mpp = parseMppHeader(req);
  if (!mpp.found) {
    // No MPP credential — pass to x402 or next (x402 fires before this)
    return next();
  }

  const { txHash, rail, amount: headerAmount } = mpp;
  const expectedAmount = getMppPrice(req.path, req.method);
  const amountToVerify = headerAmount || expectedAmount;

  // Cache check (prevent re-verification for same tx)
  if (mppPaymentCache.has(txHash)) {
    const cached = mppPaymentCache.get(txHash);
    if (cached.ok) {
      res.set('Payment-Receipt', `mpp:${txHash}:verified`);
      res.set('X-Hive-Payment-Rail', 'mpp');
      res.set('X-Hive-Payment-Method', 'mpp');
      return next();
    }
    return res.status(402).json({
      error: 'MPP payment verification failed (cached)',
      code:  'MPP_PAYMENT_INVALID',
      reason: cached.reason,
    });
  }

  // On-chain verification
  const verification = await verifyMppOnChain(txHash, amountToVerify, rail || 'tempo');
  mppPaymentCache.set(txHash, { ...verification, timestamp: Date.now() });

  if (!verification.ok) {
    return res.status(402).json({
      error:  'MPP payment verification failed',
      code:   'MPP_PAYMENT_INVALID',
      reason: verification.reason,
      hint:   'Provide a confirmed Tempo or Base USDC transaction in the Payment header.',
    });
  }

  // Payment verified — emit Spectral receipt (non-blocking)
  emitMppSpectralReceipt({
    path:   req.path,
    amount: amountToVerify,
    txHash,
    rail:   rail || 'tempo',
  }).catch(() => {});

  res.set('Payment-Receipt',        `mpp:${txHash}:${rail || 'tempo'}`);
  res.set('X-Hive-Payment-Rail',   'mpp');
  res.set('X-Hive-Payment-Method', 'mpp');
  return next();
}

export default mppMiddleware;
export { mppPaymentCache };
