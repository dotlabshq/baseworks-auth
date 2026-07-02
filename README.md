# @baseworks/auth

Authentication utilities for the baseworks monorepo. Uses subpath imports so each environment only pulls in what it needs.

## Subpath Imports

| Import | Runtime | Contents |
|--------|---------|----------|
| `@baseworks/auth` | Any | token helpers, verifyHs256Jwt, verifyOidcToken, pkce, cli-auth, url-helpers |
| `@baseworks/auth/jwt` | Node.js | HS256 JWT verification |
| `@baseworks/auth/hono` | Node.js + Hono | `requireAuth` middleware |
| `@baseworks/auth/oidc` | Workers / Node / Browser | OIDC token verification via JWKS |
| `@baseworks/auth/oidc-human` | Any | OIDC → DB user resolver factory |
| `@baseworks/auth/pkce` | Workers / Node / Browser | PKCE generation + OIDC auth URL builder |
| `@baseworks/auth/token` | Workers / Node / Browser | hashToken, looksLikeJwt, stripBearer |
| `@baseworks/auth/cli-auth` | Node.js CLI | Browser-based polling auth flow |
| `@baseworks/auth/session` | Next.js (Server) | OIDC cookie session, token exchange, refresh |
| `@baseworks/auth/edge` | Next.js (Edge/Server) | Pomerium JWT assertions + cookie fallback |
| `@baseworks/auth/url-helpers` | Next.js | Auth/account public URL builders |

---

## File Reference

### `jwt.ts` → `@baseworks/auth/jwt`
**Runtime:** Node.js — uses `node:crypto`

HS256 JWT verification. Used by Flect services (`org-service`, `account-service`) to verify service-to-service JWTs signed with `JWT_SECRET`.

```ts
import { verifyHs256Jwt } from '@baseworks/auth/jwt'

const claims = verifyHs256Jwt(token, process.env.JWT_SECRET)
// null → invalid signature or expired
```

---

### `hono.ts` → `@baseworks/auth/hono`
**Runtime:** Node.js + Hono — peer dep: `hono`

Hono middleware. Reads `Authorization: Bearer <token>`, verifies with `jwt.ts`, sets `c.var.auth` (typed as `ServiceAuthUser`).

```ts
import { requireAuth } from '@baseworks/auth/hono'

app.use('*', requireAuth)
app.get('/me', (c) => {
  const { userId, orgId } = c.var.auth
})
```

> `ContextVariableMap` is augmented here — do not re-declare it in services.

---

### `oidc.ts` → `@baseworks/auth/oidc`
**Runtime:** Workers / Node / Browser — dep: `jose`

Provider-agnostic OIDC JWT verification. Fetches the public key from the JWKS endpoint, verifies the signature, and returns a normalised `OidcIdentity`.

```ts
import { verifyOidcToken } from '@baseworks/auth/oidc'

const identity = await verifyOidcToken(bearerToken, {
  issuer:   'https://auth.example.com',
  audience: 'my-app',
})
// null → verification failed
```

JWKS endpoint: `{issuer}/oauth/v2/keys` (Zitadel-compatible).

---

### `oidc-human.ts` → `@baseworks/auth/oidc-human`
**Runtime:** Any — dep: `oidc.ts`, `jose`

Combines `verifyOidcToken` with a DB user upsert into a single resolver. The `findOrCreate` callback stays app-specific.

```ts
import { createOidcHumanResolver } from '@baseworks/auth/oidc-human'

const resolve = createOidcHumanResolver({
  issuer:       process.env.OIDC_ISSUER,
  findOrCreate: async (identity) => db.users.upsert(identity),
})

const user = await resolve(bearerToken) // null → verification failed
```

Fast-fail: if the issuer doesn't match it returns null before hitting the JWKS endpoint.

---

### `pkce.ts` → `@baseworks/auth/pkce`
**Runtime:** Workers / Node / Browser — dep: Web Crypto API, `@baseworks/core`

PKCE (RFC 7636) `code_verifier` + `code_challenge` generation. OIDC authorization URL builder compatible with any provider (Zitadel, Auth0, Keycloak, etc.).

```ts
import { generatePkce, buildOidcAuthUrl } from '@baseworks/auth/pkce'

const { verifier, challenge } = await generatePkce()
const url = buildOidcAuthUrl({ issuer, clientId, redirectUri, challenge })
```

---

### `token.ts` → `@baseworks/auth/token`
**Runtime:** Workers / Node / Browser — dep: Web Crypto API

General-purpose token helpers.

```ts
import { hashToken, looksLikeJwt, stripBearer } from '@baseworks/auth/token'

const hash   = await hashToken(rawToken, 'optional-pepper') // SHA-256 hex
const raw    = stripBearer(request.headers.get('Authorization')) // null if missing
const isJwt  = looksLikeJwt(token) // true if 3-part dot-separated
```

---

### `cli-auth.ts` → `@baseworks/auth/cli-auth`
**Runtime:** Node.js CLI — dep: `fetch`

CLI → browser auth polling flow. Used by commands like `flect login`. The user opens a URL in the browser; the CLI polls until auth completes.

```ts
import { startCliAuth, pollCliAuth } from '@baseworks/auth/cli-auth'

const { state, url } = await startCliAuth('https://api.flect.run')
console.log(`Open: ${url}`)
const { token } = await pollCliAuth('https://api.flect.run', state)
```

---

### `session.ts` → `@baseworks/auth/session`
**Runtime:** Next.js (Server Components, Route Handlers) — dep: `next`

Full OIDC PKCE session management for Next.js. Handles cookie set/clear, authorization code exchange, and token refresh. Uses `@baseworks/core` for base64url encoding and `pkce.ts` for PKCE generation.

```ts
import {
  buildAuthorizationRedirect,
  handleAuthorizationCallback,
  getSessionFromCookies,
  getServerAccessToken,
  buildLogoutResponse,
} from '@baseworks/auth/session'
```

Reads env vars: `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` (optional).

---

### `edge.ts` → `@baseworks/auth/edge`
**Runtime:** Next.js (Middleware, Server Components) — dep: `next`

Reads the session from two sources in priority order: **Pomerium JWT assertion headers** (`x-pomerium-jwt-assertion`) first, then **OIDC cookie** fallback. Returns an `EdgeSession`.

```ts
import { getEdgeSession } from '@baseworks/auth/edge'

const session = await getEdgeSession()
// session.provider: 'pomerium' | 'cookie' | 'anonymous'
```

---

### `url-helpers.ts` → `@baseworks/auth/url-helpers`
**Runtime:** Next.js — dep: none

Reads Next.js env vars and exposes URL builder functions.

```ts
import { buildAuthLoginUrl, buildAuthLogoutUrl } from '@baseworks/auth/url-helpers'

const loginUrl  = buildAuthLoginUrl('/dashboard')
const logoutUrl = buildAuthLogoutUrl('/')
```

Env vars read: `NEXT_PUBLIC_AUTH_URL`, `NEXT_PUBLIC_ACCOUNT_URL`, `APP_PUBLIC_URL`, `NEXT_PUBLIC_SITE_URL`.

---

### `_internal.ts` — not exported
Shared internal helpers. Not part of the public API.

- `parseJwtPayload(token)` — splits a JWT and decodes the payload using `@baseworks/core/codec`. Used by `session.ts` and `edge.ts`.

---

## Internal Dependencies

```
@baseworks/core/codec
  └── base64urlEncode / base64urlDecodeString
        ├── pkce.ts        (PKCE verifier/challenge generation)
        ├── session.ts     (cookie encode/decode)
        └── _internal.ts  (parseJwtPayload)
                └── edge.ts
```

## When to Use What

```
Service-to-service JWT verification (Hono/Node)
  └─ @baseworks/auth/hono         →  requireAuth middleware

Raw HS256 JWT verify
  └─ @baseworks/auth/jwt          →  verifyHs256Jwt

User OIDC token verification (Workers/Node)
  └─ @baseworks/auth/oidc         →  verifyOidcToken

OIDC token + DB user sync in one step
  └─ @baseworks/auth/oidc-human   →  createOidcHumanResolver

API key hashing / Bearer header parsing
  └─ @baseworks/auth/token        →  hashToken / stripBearer

Next.js OIDC login / callback / logout
  └─ @baseworks/auth/session      →  buildAuthorizationRedirect / handleAuthorizationCallback

Who is this user in Next.js Middleware?
  └─ @baseworks/auth/edge         →  getEdgeSession

CLI browser auth
  └─ @baseworks/auth/cli-auth     →  startCliAuth / pollCliAuth
```
