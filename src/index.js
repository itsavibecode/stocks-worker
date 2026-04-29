// stocks-worker — Cloudflare Worker proxying SnapTrade API calls behind Firebase auth.
//
// Browser → Worker: `Authorization: Bearer <Firebase ID token>` on every request.
// Worker verifies token via Firebase's JWKS, then signs the upstream SnapTrade
// request with HMAC-SHA256(consumerKey) per SnapTrade's auth spec.

import { jwtVerify, createRemoteJWKSet } from 'jose';

// SnapTrade endpoints
const SNAPTRADE_BASE = 'https://api.snaptrade.com/api/v1';

// Firebase token verification — JWKs cached automatically by jose.
let JWKS = null;
function getJWKS() {
  if (!JWKS) {
    JWKS = createRemoteJWKSet(
      new URL('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com')
    );
  }
  return JWKS;
}

async function verifyFirebaseToken(token, projectId) {
  const { payload } = await jwtVerify(token, getJWKS(), {
    issuer: `https://securetoken.google.com/${projectId}`,
    audience: projectId,
  });
  if (!payload.sub) throw new Error('Token has no subject');
  return payload; // payload.sub = Firebase UID
}

// ─────────────────────────────────────────────────────────────────
// SnapTrade request signing
// ─────────────────────────────────────────────────────────────────
// Per SnapTrade docs: build {content, path, query} JSON, HMAC-SHA256 with
// consumerKey, base64-encode, send as `Signature` header. Query string
// must include clientId + timestamp (sorted alphabetically) but NOT Signature.

async function hmacSha256Base64(key, message) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(message));
  const bytes = new Uint8Array(sig);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function buildQuery(params) {
  // Alphabetical sort of keys, URL-encoded values.
  const keys = Object.keys(params).sort();
  return keys.map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(params[k])}`).join('&');
}

async function snaptradeFetch(env, { method, path, query = {}, body = null }) {
  const ts = Math.floor(Date.now() / 1000).toString();
  const allQuery = { ...query, clientId: env.SNAPTRADE_CLIENT_ID, timestamp: ts };
  const queryString = buildQuery(allQuery);
  const sigPayload = JSON.stringify({
    content: body,
    path,
    query: queryString,
  });
  const signature = await hmacSha256Base64(env.SNAPTRADE_CONSUMER_KEY, sigPayload);

  const url = `${SNAPTRADE_BASE}${path}?${queryString}`;
  const resp = await fetch(url, {
    method,
    headers: {
      'Content-Type': 'application/json',
      Signature: signature,
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const text = await resp.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { _raw: text }; }
  if (!resp.ok) {
    return { ok: false, status: resp.status, error: data };
  }
  return { ok: true, status: resp.status, data };
}

// ─────────────────────────────────────────────────────────────────
// CORS
// ─────────────────────────────────────────────────────────────────
function corsHeaders(origin, allowed) {
  const allow = allowed.includes(origin) ? origin : '';
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}

function jsonResponse(body, status, cors) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...cors },
  });
}

// ─────────────────────────────────────────────────────────────────
// Handlers
// ─────────────────────────────────────────────────────────────────
async function handleRegister(request, env, uid, cors) {
  // SnapTrade userId = Firebase UID. Idempotent: SnapTrade returns existing
  // user data if you re-register the same userId.
  const r = await snaptradeFetch(env, {
    method: 'POST',
    path: '/snapTrade/registerUser',
    body: { userId: uid },
  });
  if (!r.ok) return jsonResponse({ error: 'SnapTrade registerUser failed', detail: r.error }, r.status || 502, cors);
  return jsonResponse(
    {
      snaptradeUserId: r.data.userId,
      snaptradeUserSecret: r.data.userSecret,
    },
    200,
    cors
  );
}

async function handleConnectUrl(request, env, uid, cors) {
  const body = await request.json().catch(() => ({}));
  const { snaptradeUserId, snaptradeUserSecret, immediateRedirect } = body;
  if (!snaptradeUserId || !snaptradeUserSecret) {
    return jsonResponse({ error: 'snaptradeUserId and snaptradeUserSecret required' }, 400, cors);
  }
  if (snaptradeUserId !== uid) {
    return jsonResponse({ error: 'snaptradeUserId must match the authenticated Firebase UID' }, 403, cors);
  }
  const r = await snaptradeFetch(env, {
    method: 'POST',
    path: '/snapTrade/login',
    query: { userId: snaptradeUserId, userSecret: snaptradeUserSecret },
    body: immediateRedirect ? { immediateRedirect: true } : {},
  });
  if (!r.ok) return jsonResponse({ error: 'SnapTrade login failed', detail: r.error }, r.status || 502, cors);
  return jsonResponse({ redirectURI: r.data.redirectURI || r.data.redirectUri || r.data }, 200, cors);
}

async function handleTransactions(request, env, uid, cors) {
  const body = await request.json().catch(() => ({}));
  const { snaptradeUserId, snaptradeUserSecret, startDate, endDate } = body;
  if (!snaptradeUserId || !snaptradeUserSecret) {
    return jsonResponse({ error: 'snaptradeUserId and snaptradeUserSecret required' }, 400, cors);
  }
  if (snaptradeUserId !== uid) {
    return jsonResponse({ error: 'snaptradeUserId must match the authenticated Firebase UID' }, 403, cors);
  }

  // Default window: last 90 days
  const today = new Date();
  const past = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
  const start = startDate || past.toISOString().slice(0, 10);
  const end = endDate || today.toISOString().slice(0, 10);

  // SnapTrade exposes activities at /activities — accepts userId/userSecret + date range.
  // No accountId filter needed; returns activities across all the user's connected accounts.
  const r = await snaptradeFetch(env, {
    method: 'GET',
    path: '/activities',
    query: {
      userId: snaptradeUserId,
      userSecret: snaptradeUserSecret,
      startDate: start,
      endDate: end,
    },
  });
  if (!r.ok) {
    return jsonResponse({ error: 'SnapTrade /activities failed', detail: r.error }, r.status || 502, cors);
  }
  return jsonResponse({ activities: r.data || [], window: { startDate: start, endDate: end } }, 200, cors);
}

async function handleAccounts(request, env, uid, cors) {
  const body = await request.json().catch(() => ({}));
  const { snaptradeUserId, snaptradeUserSecret } = body;
  if (!snaptradeUserId || !snaptradeUserSecret) {
    return jsonResponse({ error: 'snaptradeUserId and snaptradeUserSecret required' }, 400, cors);
  }
  if (snaptradeUserId !== uid) {
    return jsonResponse({ error: 'snaptradeUserId must match the authenticated Firebase UID' }, 403, cors);
  }

  const accountsR = await snaptradeFetch(env, {
    method: 'GET',
    path: '/accounts',
    query: { userId: snaptradeUserId, userSecret: snaptradeUserSecret },
  });
  if (!accountsR.ok) {
    return jsonResponse({ error: 'SnapTrade /accounts failed', detail: accountsR.error }, accountsR.status || 502, cors);
  }

  // Pull positions for each account in parallel
  const accounts = Array.isArray(accountsR.data) ? accountsR.data : [];
  const enriched = await Promise.all(
    accounts.map(async (acct) => {
      const posR = await snaptradeFetch(env, {
        method: 'GET',
        path: `/accounts/${encodeURIComponent(acct.id)}/positions`,
        query: { userId: snaptradeUserId, userSecret: snaptradeUserSecret },
      });
      return { ...acct, positions: posR.ok ? posR.data : [], positionsError: posR.ok ? null : posR.error };
    })
  );

  return jsonResponse({ accounts: enriched }, 200, cors);
}

// ─────────────────────────────────────────────────────────────────
// Router
// ─────────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const allowed = (env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
    const cors = corsHeaders(origin, allowed);

    // Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    // Health check (no auth — useful for "is the worker up")
    if (url.pathname === '/health' && request.method === 'GET') {
      return jsonResponse({ ok: true, ts: Date.now() }, 200, cors);
    }

    // All other endpoints require Firebase auth
    const authHeader = request.headers.get('Authorization') || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if (!token) {
      return jsonResponse({ error: 'Missing Authorization Bearer token' }, 401, cors);
    }

    let uid;
    try {
      const payload = await verifyFirebaseToken(token, env.FIREBASE_PROJECT_ID);
      uid = payload.sub;
    } catch (e) {
      return jsonResponse({ error: 'Invalid Firebase ID token', detail: String(e.message || e) }, 401, cors);
    }

    try {
      if (url.pathname === '/register' && request.method === 'POST') {
        return await handleRegister(request, env, uid, cors);
      }
      if (url.pathname === '/connect-url' && request.method === 'POST') {
        return await handleConnectUrl(request, env, uid, cors);
      }
      if (url.pathname === '/accounts' && request.method === 'POST') {
        return await handleAccounts(request, env, uid, cors);
      }
      if (url.pathname === '/transactions' && request.method === 'POST') {
        return await handleTransactions(request, env, uid, cors);
      }
      return jsonResponse({ error: 'Not found' }, 404, cors);
    } catch (e) {
      console.error('Handler error:', e);
      return jsonResponse({ error: 'Internal error', detail: String(e.message || e) }, 500, cors);
    }
  },
};
