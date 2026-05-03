// stocks-worker — Cloudflare Worker proxying SnapTrade API calls behind Firebase auth,
// plus a daily cron that sends dividend ex-date / pay-date reminder emails via Resend.
//
// Browser → Worker: `Authorization: Bearer <Firebase ID token>` on every request.
// Worker verifies token via Firebase's JWKS, then signs the upstream SnapTrade
// request with HMAC-SHA256(consumerKey) per SnapTrade's auth spec.
//
// Cron → Worker: scheduled handler runs once daily, reads OWNER_UID's portfolio doc
// from Firestore (via service account), pulls fresh dividend dates from Finnhub,
// and emails any new reminders via Resend.

import { jwtVerify, createRemoteJWKSet } from 'jose';

// SnapTrade endpoints
const SNAPTRADE_BASE = 'https://api.snaptrade.com/api/v1';
// Firestore + Identity Toolkit base URLs
const FIRESTORE_BASE = 'https://firestore.googleapis.com/v1';
const IDENTITY_BASE = 'https://identitytoolkit.googleapis.com/v1';
const FINNHUB_BASE = 'https://finnhub.io/api/v1';
const RESEND_BASE = 'https://api.resend.com';

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
      // Manual cron trigger — useful for testing without waiting for the schedule.
      // Auth: must be signed in as OWNER_UID (single-user model). Body optional.
      if (url.pathname === '/run-reminders' && request.method === 'POST') {
        if (uid !== env.OWNER_UID) {
          return jsonResponse({ error: 'Manual reminder trigger restricted to OWNER_UID' }, 403, cors);
        }
        const result = await runDailyReminders(env);
        return jsonResponse(result, 200, cors);
      }
      return jsonResponse({ error: 'Not found' }, 404, cors);
    } catch (e) {
      console.error('Handler error:', e);
      return jsonResponse({ error: 'Internal error', detail: String(e.message || e) }, 500, cors);
    }
  },

  // Scheduled (cron) handler — runs daily at the time configured in wrangler.toml's
  // [triggers] crons. Single user (OWNER_UID); see runDailyReminders for the logic.
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      runDailyReminders(env).catch((err) => {
        console.error('Cron run failed:', err);
      })
    );
  },
};

// ═════════════════════════════════════════════════════════════════════
// SERVICE ACCOUNT AUTH (Google OAuth2 JWT exchange) — used to call
// Firestore REST and Identity Toolkit on behalf of the project.
// ═════════════════════════════════════════════════════════════════════

let _accessTokenCache = null; // { token, expiresAt }

async function getServiceAccountToken(env) {
  if (_accessTokenCache && _accessTokenCache.expiresAt > Date.now() + 60_000) {
    return _accessTokenCache.token;
  }

  const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT_JSON);
  const now = Math.floor(Date.now() / 1000);
  const claim = {
    iss: sa.client_email,
    scope: 'https://www.googleapis.com/auth/datastore https://www.googleapis.com/auth/identitytoolkit',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now,
  };

  const enc = new TextEncoder();
  const headerB64 = b64url(btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const claimB64 = b64url(btoa(JSON.stringify(claim)));
  const unsigned = `${headerB64}.${claimB64}`;

  const privateKey = await pemToCryptoKey(sa.private_key);
  const sigBuf = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, enc.encode(unsigned));
  const sigB64 = b64url(arrayBufferToBase64(sigBuf));

  const jwt = `${unsigned}.${sigB64}`;

  const resp = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
  });
  if (!resp.ok) {
    const errTxt = await resp.text();
    throw new Error(`Service account token exchange failed: ${resp.status} ${errTxt}`);
  }
  const data = await resp.json();
  _accessTokenCache = {
    token: data.access_token,
    expiresAt: Date.now() + (data.expires_in - 120) * 1000,
  };
  return data.access_token;
}

function b64url(b64) {
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function arrayBufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

async function pemToCryptoKey(pem) {
  // Strip PEM header/footer + whitespace, base64-decode, import as PKCS#8.
  const stripped = pem
    .replace('-----BEGIN PRIVATE KEY-----', '')
    .replace('-----END PRIVATE KEY-----', '')
    .replace(/\s/g, '');
  const der = Uint8Array.from(atob(stripped), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey(
    'pkcs8',
    der.buffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

// ═════════════════════════════════════════════════════════════════════
// FIRESTORE REST helpers — translate to/from Firestore's typed-value
// JSON format and provide minimal get/patch over documents.
// ═════════════════════════════════════════════════════════════════════

async function firestoreGetDoc(env, accessToken, path) {
  const url = `${FIRESTORE_BASE}/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents/${path}`;
  const resp = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (resp.status === 404) return null;
  if (!resp.ok) {
    const errTxt = await resp.text();
    throw new Error(`Firestore GET ${path} failed: ${resp.status} ${errTxt}`);
  }
  return resp.json();
}

// PATCH with field-path mask — only the specified field paths get touched, leaving
// other fields in the doc intact. Avoids racing with browser-side prefs writes.
async function firestorePatchFields(env, accessToken, path, fieldPathsToValues) {
  // fieldPathsToValues: { "prefs.notifiedReminders": <jsValue> }
  // Build update mask + reconstruct the nested fields shape that Firestore expects.
  const fields = {};
  const masks = [];
  for (const [fp, value] of Object.entries(fieldPathsToValues)) {
    masks.push(fp);
    setNestedFsValue(fields, fp.split('.'), value);
  }
  const mask = masks.map((m) => `updateMask.fieldPaths=${encodeURIComponent(m)}`).join('&');
  const url = `${FIRESTORE_BASE}/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents/${path}?${mask}`;
  const resp = await fetch(url, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields }),
  });
  if (!resp.ok) {
    const errTxt = await resp.text();
    throw new Error(`Firestore PATCH ${path} failed: ${resp.status} ${errTxt}`);
  }
  return resp.json();
}

function setNestedFsValue(target, parts, jsValue) {
  // Walk the path and build nested mapValue wrappers. Final part gets the typed value.
  if (parts.length === 1) {
    target[parts[0]] = jsToFsValue(jsValue);
    return;
  }
  if (!target[parts[0]]) target[parts[0]] = { mapValue: { fields: {} } };
  setNestedFsValue(target[parts[0]].mapValue.fields, parts.slice(1), jsValue);
}

function fsValueToJs(v) {
  if (!v) return undefined;
  if ('stringValue' in v) return v.stringValue;
  if ('integerValue' in v) return parseInt(v.integerValue, 10);
  if ('doubleValue' in v) return v.doubleValue;
  if ('booleanValue' in v) return v.booleanValue;
  if ('nullValue' in v) return null;
  if ('timestampValue' in v) return v.timestampValue;
  if ('arrayValue' in v) {
    return (v.arrayValue.values || []).map(fsValueToJs);
  }
  if ('mapValue' in v) {
    const out = {};
    for (const [k, val] of Object.entries(v.mapValue.fields || {})) out[k] = fsValueToJs(val);
    return out;
  }
  return undefined;
}

function jsToFsValue(v) {
  if (v === null || v === undefined) return { nullValue: null };
  if (typeof v === 'string') return { stringValue: v };
  if (typeof v === 'boolean') return { booleanValue: v };
  if (typeof v === 'number') {
    if (Number.isInteger(v)) return { integerValue: String(v) };
    return { doubleValue: v };
  }
  if (Array.isArray(v)) return { arrayValue: { values: v.map(jsToFsValue) } };
  if (typeof v === 'object') {
    const fields = {};
    for (const [k, val] of Object.entries(v)) fields[k] = jsToFsValue(val);
    return { mapValue: { fields } };
  }
  return { nullValue: null };
}

// ═════════════════════════════════════════════════════════════════════
// IDENTITY TOOLKIT — look up a user's email by Firebase UID.
// ═════════════════════════════════════════════════════════════════════

async function getUserEmail(env, accessToken, uid) {
  const url = `${IDENTITY_BASE}/projects/${env.FIREBASE_PROJECT_ID}/accounts:lookup`;
  const resp = await fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ localId: [uid] }),
  });
  if (!resp.ok) {
    const errTxt = await resp.text();
    throw new Error(`Identity Toolkit lookup failed: ${resp.status} ${errTxt}`);
  }
  const data = await resp.json();
  return data.users && data.users[0] && data.users[0].email;
}

// ═════════════════════════════════════════════════════════════════════
// FINNHUB — re-pull dividend dates per ticker on each cron run. The
// browser doesn't sync DV (per-ticker dividend metadata) to Firestore
// for built-in tickers, so the worker has to fetch its own copy.
// ═════════════════════════════════════════════════════════════════════

async function fetchDividendData(finnhubKey, ticker, fromDate, toDate) {
  const url = `${FINNHUB_BASE}/stock/dividend?symbol=${encodeURIComponent(ticker)}&from=${fromDate}&to=${toDate}&token=${finnhubKey}`;
  const resp = await fetch(url);
  if (!resp.ok) {
    const txt = await resp.text().catch(() => '');
    throw new Error(`Finnhub ${resp.status}${txt ? ': ' + txt.slice(0, 100) : ''}`);
  }
  const data = await resp.json();
  return Array.isArray(data) ? data : [];
}

// ═════════════════════════════════════════════════════════════════════
// RESEND — send a single rolled-up reminder email per cron run.
// ═════════════════════════════════════════════════════════════════════

async function sendReminderEmail(env, { to, subject, html, text }) {
  const resp = await fetch(`${RESEND_BASE}/emails`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: env.SENDER_FROM, to, subject, html, text }),
  });
  if (!resp.ok) {
    const errTxt = await resp.text();
    throw new Error(`Resend send failed: ${resp.status} ${errTxt}`);
  }
  return resp.json();
}

function buildReminderEmail(reminders) {
  // Split into pay-date and ex-date columns; each sorted by closest first.
  const sortAsc = (a, b) => {
    if (a.daysToEvent !== b.daysToEvent) return a.daysToEvent - b.daysToEvent;
    return a.ticker.localeCompare(b.ticker);
  };
  const payList = reminders.filter((r) => r.type === 'pay').sort(sortAsc);
  const exList = reminders.filter((r) => r.type === 'ex').sort(sortAsc);

  const subject = `📊 Stockfolio: ${reminders.length} dividend reminder${reminders.length !== 1 ? 's' : ''}`;

  const fmtWhenText = (r) =>
    r.daysToEvent === 0 ? 'today' : `in ${r.daysToEvent} day${r.daysToEvent !== 1 ? 's' : ''}`;
  const fmtWhenHtml = (r) =>
    r.daysToEvent === 0
      ? '<strong>today</strong>'
      : `in <strong>${r.daysToEvent} day${r.daysToEvent !== 1 ? 's' : ''}</strong>`;

  // ── Plain-text version ──
  const textPayLines = payList
    .map((r) => {
      const total = (r.amount || 0) * (r.totalShares || 0);
      return `  • ${r.ticker} ${fmtWhenText(r)} (${r.date}) — $${total.toFixed(2)} incoming (${r.totalShares} sh × $${r.amount}/sh)`;
    })
    .join('\n');
  const textExLines = exList
    .map((r) => `  • ${r.ticker} ${fmtWhenText(r)} (${r.date}) — buy by today to receive next dividend`)
    .join('\n');
  const text =
    (payList.length ? `PAY DATES (${payList.length})\n${textPayLines}\n\n` : '') +
    (exList.length ? `EX-DIVIDEND DATES (${exList.length})\n${textExLines}\n` : '');

  // ── HTML version ──
  const cardHtml = (r) => {
    let detail;
    if (r.type === 'ex') {
      detail = 'Buy by end of today to receive next dividend';
    } else {
      const total = (r.amount || 0) * (r.totalShares || 0);
      detail = `<strong style="color:#34d399">$${total.toFixed(2)}</strong> incoming · ${r.totalShares} sh × $${r.amount}/sh`;
    }
    return `
      <div style="background:#131c2e;border:1px solid #1a2540;border-radius:8px;padding:10px 12px;margin-bottom:8px">
        <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:4px">
          <span style="font-family:'JetBrains Mono',monospace;font-size:15px;font-weight:700;color:#dfe6f0">${r.ticker}</span>
          <span style="font-size:10.5px;color:#5a6e8a;font-family:'JetBrains Mono',monospace">${r.date}</span>
        </div>
        <div style="font-size:12px;color:#c1ccdd;margin-bottom:3px">${fmtWhenHtml(r)}</div>
        <div style="font-size:12px;color:#c1ccdd">${detail}</div>
      </div>`;
  };

  const colHtml = (label, count, color, list) => `
    <td valign="top" width="50%" style="padding:0 6px;vertical-align:top">
      <div style="font-size:11px;font-weight:700;color:${color};text-transform:uppercase;letter-spacing:.5px;padding:6px 4px;margin-bottom:6px;border-bottom:1px solid #1a2540">
        ${label} (${count})
      </div>
      ${list.length ? list.map(cardHtml).join('') : '<div style="font-size:11px;color:#5a6e8a;font-style:italic;padding:8px 4px">No upcoming events</div>'}
    </td>`;

  const html = `<html><body style="font-family:system-ui,-apple-system,sans-serif;background:#0d1420;color:#dfe6f0;padding:20px;margin:0">
  <div style="max-width:680px;margin:0 auto">
    <h2 style="color:#4e8cff;margin:0 0 6px;font-size:20px">📊 Stockfolio Daily Reminder</h2>
    <p style="color:#c1ccdd;margin:0 0 14px;font-size:13px">
      ${reminders.length} upcoming dividend event${reminders.length !== 1 ? 's' : ''} —
      ${payList.length} pay date${payList.length !== 1 ? 's' : ''}, ${exList.length} ex-date${exList.length !== 1 ? 's' : ''}.
    </p>
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="border-collapse:separate">
      <tr>
        ${colHtml('💰 Pay Dates', payList.length, '#34d399', payList)}
        ${colHtml('📅 Ex-Dividend Dates', exList.length, '#fbbf24', exList)}
      </tr>
    </table>
    <p style="color:#5a6e8a;font-size:11px;margin-top:18px;border-top:1px solid #1a2540;padding-top:12px">
      From your Portfolio Command Center · <a href="https://itsavibecode.github.io/stocks/" style="color:#4e8cff">Open app</a> · Manage in Settings → Dividend Reminders
    </p>
  </div>
</body></html>`;
  return { subject, html, text };
}

// ═════════════════════════════════════════════════════════════════════
// CRON HANDLER — read user portfolio, compute upcoming reminders,
// send a single rolled-up email per run, dedupe via prefs.notifiedReminders.
// ═════════════════════════════════════════════════════════════════════

async function runDailyReminders(env) {
  const uid = env.OWNER_UID;
  if (!uid) {
    return { ok: false, reason: 'OWNER_UID env var not set' };
  }
  const accessToken = await getServiceAccountToken(env);
  const doc = await firestoreGetDoc(env, accessToken, `portfolios/${uid}`);
  if (!doc || !doc.fields) {
    return { ok: false, reason: 'Portfolio doc not found for OWNER_UID' };
  }

  const tks = fsValueToJs(doc.fields.tickers) || [];
  const lots = fsValueToJs(doc.fields.lots) || {};
  const prefs = fsValueToJs(doc.fields.prefs) || {};
  // dvCache is written by the browser (stocks v0.7.19+) — keyed by ticker, each
  // entry has the same shape as the in-app DV: { ex, pd, np, a, y, ... }.
  const dvCache = fsValueToJs(doc.fields.dvCache) || {};
  const dvCacheTs = fsValueToJs(doc.fields.dvCacheTs) || 0;

  if (!prefs.remEnabled) return { ok: true, reason: 'Reminders disabled by user', sent: 0 };
  if (Object.keys(dvCache).length === 0) {
    return { ok: false, reason: 'dvCache is empty in Firestore — open the stocks app at least once while signed in to seed it' };
  }

  const userEmail = await getUserEmail(env, accessToken, uid);
  if (!userEmail) return { ok: false, reason: 'Could not look up user email from Firebase Auth' };

  const daysEx = prefs.remDaysEx == null ? 1 : Number(prefs.remDaysEx);
  const daysPay = prefs.remDaysPay == null ? 1 : Number(prefs.remDaysPay);
  const optOut = prefs.remOptOut || {};
  const notified = { ...(prefs.notifiedReminders || {}) };

  const today = new Date();
  today.setUTCHours(0, 0, 0, 0); // Compare as UTC midnight

  const sharesByTicker = {};
  tks.forEach((t) => {
    const ts = lots[t] || [];
    sharesByTicker[t] = ts.reduce((s, lot) => s + (Number(lot.s) || 0), 0);
  });
  const tickersToCheck = tks.filter((t) => !optOut[t] && sharesByTicker[t] > 0 && dvCache[t]);

  const reminders = [];
  const errors = [];
  // No Finnhub call needed — we read pay/ex dates straight from dvCache.
  // 1 Firestore read + 1 Identity Toolkit lookup + 1 Resend send = 3 subrequests
  // total, well under Cloudflare's 50/invocation free-tier limit.
  for (const ticker of tickersToCheck) {
    const dv = dvCache[ticker];
    if (!dv) continue;
    const totalShares = sharesByTicker[ticker];
    const isDivStock = (dv.rt && dv.rt !== 'None') || (dv.a && dv.a > 0);
    if (!isDivStock) continue;

    // Ex-date check
    if (dv.ex && dv.ex !== 'N/A') {
      const exMs = Date.parse(dv.ex + 'T12:00:00Z');
      if (!isNaN(exMs)) {
        const daysToEx = Math.ceil((exMs - today.getTime()) / 86400000);
        if (daysToEx >= 0 && daysToEx <= daysEx) {
          const key = `${ticker}-ex-${dv.ex}`;
          if (!notified[key]) {
            reminders.push({ ticker, type: 'ex', date: dv.ex, daysToEvent: daysToEx, amount: dv.np || 0, totalShares });
            notified[key] = Date.now();
          }
        }
      }
    }
    // Pay-date check
    if (dv.pd && dv.pd !== 'N/A') {
      const payMs = Date.parse(dv.pd + 'T12:00:00Z');
      if (!isNaN(payMs)) {
        const daysToPay = Math.ceil((payMs - today.getTime()) / 86400000);
        if (daysToPay >= 0 && daysToPay <= daysPay) {
          const key = `${ticker}-pay-${dv.pd}`;
          if (!notified[key]) {
            reminders.push({ ticker, type: 'pay', date: dv.pd, daysToEvent: daysToPay, amount: dv.np || 0, totalShares });
            notified[key] = Date.now();
          }
        }
      }
    }
  }

  if (reminders.length === 0) {
    return {
      ok: true,
      reason: 'No new reminders to send',
      sent: 0,
      checkedTickers: tickersToCheck.length,
      dvCacheAgeHours: dvCacheTs ? Math.round((Date.now() - dvCacheTs) / 3600000) : null,
      errors,
    };
  }

  // Auto-prune notified entries older than 60 days; keep last 200 by recency.
  const sixtyAgo = Date.now() - 60 * 86400000;
  for (const k of Object.keys(notified)) {
    if (notified[k] < sixtyAgo) delete notified[k];
  }
  const keys = Object.keys(notified);
  if (keys.length > 200) {
    keys.sort((a, b) => notified[a] - notified[b]);
    keys.slice(0, keys.length - 200).forEach((k) => delete notified[k]);
  }

  // Send the email
  const { subject, html, text } = buildReminderEmail(reminders);
  const sendResult = await sendReminderEmail(env, { to: userEmail, subject, html, text });

  // Write back updated notifiedReminders (only this nested field)
  await firestorePatchFields(env, accessToken, `portfolios/${uid}`, {
    'prefs.notifiedReminders': notified,
  });

  return {
    ok: true,
    sent: reminders.length,
    to: userEmail,
    resendId: sendResult && sendResult.id,
    checkedTickers: tickersToCheck.length,
    dvCacheAgeHours: dvCacheTs ? Math.round((Date.now() - dvCacheTs) / 3600000) : null,
    errors,
  };
}

function isoDate(d) {
  return d.toISOString().slice(0, 10);
}
