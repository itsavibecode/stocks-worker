# stocks-worker

Cloudflare Worker backend for [itsavibecode/stocks](https://github.com/itsavibecode/stocks). Proxies SnapTrade API calls with Firebase-authenticated requests so the SnapTrade `consumerKey` (a private secret) never reaches the browser.

## Endpoints

All endpoints require `Authorization: Bearer <Firebase ID token>` header.

| Method | Path | Body | Returns |
|---|---|---|---|
| `POST` | `/register` | — | `{ snaptradeUserId, snaptradeUserSecret }` |
| `POST` | `/connect-url` | `{ snaptradeUserId, snaptradeUserSecret, immediateRedirect?: boolean }` | `{ redirectURI }` |
| `POST` | `/accounts` | `{ snaptradeUserId, snaptradeUserSecret }` | `{ accounts: [...with positions inline] }` |
| `POST` | `/transactions` | `{ snaptradeUserId, snaptradeUserSecret, startDate?, endDate? }` | `{ activities: [...], window: {startDate, endDate} }` |
| `POST` | `/run-reminders` | — (must be OWNER_UID) | Manually trigger the dividend-reminder cron logic; returns `{ok, sent, to, resendId, checkedTickers, errors}` |
| `GET` | `/health` | — | `{ ok: true, ts }` |

## Daily dividend-reminder cron

Triggered by `0 14 * * *` (9am US Eastern / 14:00 UTC). Since v0.7.1 this same daily fire also runs the monthly payout digest when it's the 1st of the month (UTC) — the digest's separate `0 12 1 * *` trigger was removed to free one of the account's 5 free-plan cron slots. Single-user (Path B) implementation: reads `OWNER_UID`'s portfolio from Firestore via service account, fetches fresh dividend dates from Finnhub for each ticker with shares set, and sends a single rolled-up email via Resend if there's anything in the user's reminder window. Deduplicates with `prefs.notifiedReminders` (60-day auto-prune, 200 cap) so the same ex/pay-date never fires twice.

Required Worker secrets/vars (in addition to the SnapTrade ones):
- `FIREBASE_SERVICE_ACCOUNT_JSON` (secret) — full service account JSON pasted via `wrangler secret put`
- `RESEND_API_KEY` (secret) — Resend API key
- `OWNER_UID` (var) — Firebase UID of the single user
- `SENDER_FROM` (var) — formatted Resend sender, e.g. `Display Name <noreply@your-verified-domain.com>`

`snaptradeUserId` is always the user's Firebase UID. `snaptradeUserSecret` is opaque — the browser receives it from `/register` and stores it in its own Firestore portfolio doc, then sends it back on every subsequent call.

## Setup (one-time)

```bash
# in this folder
npm install
wrangler login            # already done
wrangler secret put SNAPTRADE_CLIENT_ID
wrangler secret put SNAPTRADE_CONSUMER_KEY
wrangler deploy
```

`wrangler secret put` opens an interactive stdin prompt — paste the secret directly. It never appears in source, in chat, or on disk outside Cloudflare's encrypted secret store.

## Local dev

```bash
# put dev-only secrets in .dev.vars (gitignored)
echo 'SNAPTRADE_CLIENT_ID=PERS-...' > .dev.vars
echo 'SNAPTRADE_CONSUMER_KEY=...' >> .dev.vars
npm run dev
```

## Auth flow

1. Browser obtains a Firebase ID token via `firebase.auth().currentUser.getIdToken()`.
2. Browser sends `Authorization: Bearer <token>` on every Worker request.
3. Worker verifies the token against Firebase's JWKS endpoint (`securetoken@system.gserviceaccount.com`), checks issuer = `https://securetoken.google.com/<project>` and audience = `<project>`.
4. Verified token's `sub` (Firebase UID) is used as the SnapTrade `userId` for the request.
5. Worker signs the SnapTrade request with HMAC-SHA256(consumerKey, request_data) and forwards to `api.snaptrade.com`.

## Why a worker

The SnapTrade `consumerKey` is the private half of our developer credential. Anything in browser JS or in a public GitHub Pages bundle is *public*, so the secret has to live somewhere only we control. Cloudflare Workers store secrets in their encrypted runtime env; the Worker is the only thing that ever sees the consumerKey.
