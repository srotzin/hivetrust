/**
 * HiveTrust — AI Revenue Endpoint
 * GET /v1/trust/ai/:did/brief  ($0.03/call)
 *
 * Know Your Agent (KYA) brief: assess counterparty trust based on network signals.
 */

import { Router } from 'express';
import { query } from '../db.js';
import { ok } from '../ritz.js';

const router = Router();

const HIVE_AI_URL = 'https://hive-ai-1.onrender.com/v1/chat/completions';
// Leaked-key purge 2026-04-25: lazy read, fail closed if env missing.
const { getInternalKey } = require('../lib/internal-key');
const MODEL = 'meta-llama/llama-3.1-8b-instruct';
const PRICE_USDC = 0.03;

function staticFallback(did) {
  return {
    success: true,
    did,
    brief: `Agent ${did} has not established a verifiable on-chain trust footprint. Proceed with caution and limit exposure until more signals are available.`,
    trust_level: 'unknown',
    transact_recommended: false,
    price_usdc: PRICE_USDC,
    _fallback: true,
  };
}

/**
 * GET /v1/trust/ai/:did/brief
 */
router.get('/:did/brief', async (req, res) => {
  try {
    const { did } = req.params;

    if (!did || !did.startsWith('did:')) {
      return res.status(400).json({
        success: false,
        error: 'Valid DID required (e.g. did:hive:xxx)',
      });
    }

    // Attempt to fetch existing trust data from DB
    let trustContext = `DID: ${did}\nNetwork signals: No registered data found.`;
    try {
      const result = await query(
        `SELECT trust_score, trust_tier, status, created_at FROM agents WHERE did = $1 LIMIT 1`,
        [did]
      );
      if (result?.rows?.length > 0) {
        const row = result.rows[0];
        trustContext = `DID: ${did}
Trust Score: ${row.trust_score ?? 'N/A'}
Trust Tier: ${row.trust_tier ?? 'unranked'}
Agent Status: ${row.status ?? 'unknown'}
Registered Since: ${row.created_at ? new Date(row.created_at).toISOString() : 'unknown'}`;
      }
    } catch (_dbErr) {
      // DB unavailable — proceed with DID-only context
    }

    let aiResponse;
    try {
      const response = await fetch(HIVE_AI_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${getInternalKey()}`,
        },
        body: JSON.stringify({
          model: MODEL,
          max_tokens: 200,
          messages: [
            {
              role: 'system',
              content: 'You are HiveTrust — the KYA (Know Your Agent) layer. Assess counterparty trust based on network signals. 2-3 sentences. Direct risk assessment.',
            },
            {
              role: 'user',
              content: `Assess this agent:\n${trustContext}`,
            },
          ],
        }),
        signal: AbortSignal.timeout(8000),
      });

      if (!response.ok) throw new Error(`HiveAI returned ${response.status}`);

      const data = await response.json();
      const brief = data?.choices?.[0]?.message?.content?.trim() || '';
      if (!brief) throw new Error('Empty response from HiveAI');

      // Infer trust_level from brief
      const lower = brief.toLowerCase();
      let trust_level = 'medium';
      if (lower.includes('low trust') || lower.includes('unknown') || lower.includes('no record') || lower.includes('unverified')) {
        trust_level = 'unknown';
      } else if (lower.includes('high trust') || lower.includes('trusted') || lower.includes('excellent') || lower.includes('reliable')) {
        trust_level = 'high';
      } else if (lower.includes('low') || lower.includes('risky') || lower.includes('caution') || lower.includes('suspicious')) {
        trust_level = 'low';
      }

      const transact_recommended = trust_level === 'high' || trust_level === 'medium';

      aiResponse = { brief, trust_level, transact_recommended };
    } catch (aiErr) {
      console.warn('[HiveTrust AI] HiveAI unavailable, using fallback:', aiErr.message);
      return res.json(staticFallback(did));
    }

    return res.json({
      success: true,
      did,
      brief: aiResponse.brief,
      trust_level: aiResponse.trust_level,
      transact_recommended: aiResponse.transact_recommended,
      price_usdc: PRICE_USDC,
    });
  } catch (err) {
    console.error('[HiveTrust AI] Unexpected error:', err.message);
    return res.json(staticFallback(req.params?.did || 'unknown'));
  }
});

export default router;
