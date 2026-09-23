# @baseworks/auth

Identity for a baseworks realm: verifying tokens, issuing them, and the sign-in
commands a CLI needs.

A **realm** is one deployment of the plane — one auth-service, one signing key
pair, and the services that trust it. A token issued in a realm is accepted by
every service in it and by no other.

```
npm i @baseworks/auth
```

Subpath imports, so a Worker or a browser bundle never pulls in Node-only code.
The task-oriented guide is below; a per-file reference follows it.

---

## I have a service that needs to verify tokens

The common case, and usually one line:

```ts
import { requireAuth } from '@baseworks/auth/hono'

app.use('*', requireAuth)
app.get('/things', (c) => {
  const { userId, tokenType } = c.get('auth')
  …
})
```

Configured entirely from the environment, so the code above never changes:

| Variable | Meaning |
|---|---|
| `AUTH_JWKS_URI` | `https://auth.example.com/.well-known/jwks.json` |
| `AUTH_ISSUER` | Expected `iss`. Unset means "do not check" |
| `AUTH_AUDIENCE` | Expected `aud`. Unset means "do not check" |
| `JWT_SECRET` | Legacy HS256 secret, accepted alongside ES256 while set |

Set both `AUTH_JWKS_URI` and `JWT_SECRET` during a migration and both kinds of
token are accepted. With only `JWT_SECRET`, behaviour is exactly what it was
before JWKS existed — so a service can be upgraded before the realm has keys.

**Set `AUTH_ISSUER` and `AUTH_AUDIENCE` in production.** Without them, a token
from any realm whose key set you happen to fetch will verify.

A service with neither a JWKS URI nor a secret answers **500, not 401**: a
misconfigured service must not look like a rejected caller, or whoever is paged
goes looking at the user's credentials.

Not using Hono? Build the verifier directly:

```ts
import { verifier } from '@baseworks/auth/identity'

const verify = verifier({
  jwksUri:  process.env.AUTH_JWKS_URI,
  issuer:   process.env.AUTH_ISSUER,
  audience: process.env.AUTH_AUDIENCE,
})

const claims = await verify(token)   // null when the token is not acceptable
```

Build it **once per process**. It owns the JWKS cache; rebuilding per request
refetches the key set every time and puts auth-service on the critical path of
every request in the realm.

`verify` returns `null` instead of throwing, so a request handler has one 401
path rather than a taxonomy of crypto errors. Pass `onError` to log the reason.

### What is in a token

```
iss  aud  sub  iat  exp  jti   type: human | service | assistant
```

**No organisation, no role.** Membership changes while a token lives, so a token
carrying a role goes stale and lies. Ask the org service and cache the answer for
a minute; that is the only way it can be current.

`type` matters for authorisation: `service` and `assistant` open doors a plain
user token must not. `requireAuth` maps anything unrecognised to `user`, the
least privileged reading.

---

## I am the issuer

Only auth-service does this. The private key never leaves it, which is exactly
why every other service can be trusted with the public half and nothing else.

```ts
import { loadSigningKey, jwks, mint } from '@baseworks/auth/identity'

const key = await loadSigningKey(process.env.AUTH_SIGNING_KEY!)

app.get('/.well-known/jwks.json', (c) => c.json(jwks(key)))

const token = await mint(key, { sub: userId, type: 'human' }, {
  issuer: 'https://auth.example.com',
  audience: 'example-realm',
  expiresInSeconds: 86400,
})
```

`loadSigningKey` takes a PKCS#8 PEM **or base64 of one**, because environment
variables, Kubernetes Secrets and CI variables all mangle the newlines a PEM
needs. The key id is the RFC 7638 thumbprint of the key itself, so it is
identical everywhere and never needs configuring.

`jwks(key, retired)` publishes retired public keys alongside the current one.
That is how rotation works: publish both for longer than a token lives, sign with
the new key, drop the old one when its tokens have expired.

---

## I am building a CLI

```ts
import { addAuthCommands } from '@baseworks/auth/cli'

addAuthCommands(program, {
  cliName: 'mycli',
  authBase: () => 'https://auth.example.com',
  onToken:  (token) => config.patch({ token }),
  onLogout: () => config.patch({ token: undefined }),
  getToken: () => config.load().token,
  tokenOrigin: () => config.writePath,
  statusRows: () => [['url', apiBase()]],
  nextSteps: 'mycli whoami',
})
```

The user gets three commands:

```
mycli login          sign in through the browser
mycli logout         forget the saved token
mycli auth status    who am I, and how long is this token good for
```

```
$ mycli auth status
  url         https://example.com
  user        01a05840-b6aa-7421-80d7-6eb192551584
  token type  human
  expires     2026-09-13 14:33 UTC (in 23h 57m)
  token from  /Users/me/.mycli/config.toml
```

Storage stays yours — this module never touches the filesystem. Pass `getToken`
and `auth status` appears; leave it out and it does not. `logout` warns when a
token is still reachable afterwards, which is what happens when an environment
variable outranks the config file.

Use [`@baseworks/config`](../baseworks-config) for the file, with
`scope: 'global'`: it writes `0600` under `~/.<app>/`. A project-local config
sits inside a working tree, and a token there gets committed.

### Driving the flow yourself

```ts
import { startCliAuth, pollCliAuth } from '@baseworks/auth/cli-auth'

const start = await startCliAuth(base)
console.log(`Approve at: ${start.url}`)
const { token } = await pollCliAuth(base, start.state, {
  timeoutMs: start.expiresIn * 1000,
})
```

**Poll until exactly `expiresIn`, no sooner.** A shorter client timeout reports
failure while the link still works — the default used to be five minutes against
a ten-minute handle, which produced exactly that bug.

---

## Migrating off a shared HMAC secret

A shared secret does not merely let a service *check* tokens, it lets that
service **issue** them — including a token claiming to be another user. Not
hypothetical: a product API in this plane was minting
`{ sub: <another user>, type: 'user' }` to act on that user's behalf.

Each step is safe on its own; the power actually goes away at step 5.

1. Deploy auth-service **without** a signing key. It keeps issuing HS256.
2. Upgrade verifiers to this version and give them `AUTH_JWKS_URI`. Both
   algorithms are accepted now.
3. Give auth-service `AUTH_SIGNING_KEY`. New tokens are ES256; existing ones keep
   verifying until they expire.
4. Move anything that was *minting* onto `POST /service-token` (a service acting
   as itself) or `POST /exchange` (a narrowed copy of the caller's own token).
   There is deliberately no replacement for minting as an arbitrary user — grant
   the service the permission instead.
5. Remove `JWT_SECRET` everywhere.

---

## Subpaths

| Import | Runtime | Contents |
|---|---|---|
| `@baseworks/auth/identity` | Node | **Realm tokens: `mint`, `jwks`, `verifier`** |
| `@baseworks/auth/hono` | Node + Hono | `requireAuth` middleware |
| `@baseworks/auth/cli` | Node CLI | `login` / `logout` / `auth status` commands |
| `@baseworks/auth/cli-auth` | Node CLI | The device flow, without the commands |
| `@baseworks/auth/jwt` | Node | HS256 sign/verify, `parseJwtPayload`. Legacy |
| `@baseworks/auth/oidc` | Any | OIDC token verification via JWKS |
| `@baseworks/auth/oidc-human` | Any | OIDC → user resolver factory |
| `@baseworks/auth/pkce` | Any | PKCE generation, OIDC auth URL builder |
| `@baseworks/auth/token` | Any | `hashToken`, `looksLikeJwt`, `stripBearer` |

`hono` is an optional peer dependency: only `@baseworks/auth/hono` pulls it in.

There is no browser-session subpath. Up to 0.3 the package carried a Next.js
sign-in (`session`, `edge`, `url-helpers`); it trusted an unsigned cookie and an
unverified id_token, and nothing used it. Signing a person in is auth-service's
job — an app sends the browser to `/v1/auth/login` and reads `/v1/auth/session`.

## Known gaps

- **No revocation.** A token is valid until it expires. Every token carries a
  `jti`, so a deny list can be added without a format change — but none exists.
- **`@baseworks/auth/jwt` still exports `signHs256Jwt`.** That is the shared
  secret era. Reach for `identity`; this stays only until the last consumer has
  migrated.

## Development

```
pnpm test        # vitest
pnpm build       # tsup
pnpm typecheck
```

---

# Per-file reference


### `jwt.ts` → `@baseworks/auth/jwt`
**Runtime:** Node.js — uses `node:crypto`

HS256 sign and verify, plus `parseJwtPayload`. **Legacy** — the shared-secret era. New code uses `@baseworks/auth/identity`; this remains until the last consumer migrates.

```ts
import { verifyHs256Jwt } from '@baseworks/auth/jwt'

const claims = verifyHs256Jwt(token, process.env.JWT_SECRET)
// null → invalid signature or expired
```

---

### `hono.ts` → `@baseworks/auth/hono`
**Runtime:** Node.js + Hono — peer dep: `hono`

Hono middleware. Reads `Authorization: Bearer <token>`, verifies against the realm JWKS (and the legacy secret while one is set), sets `c.var.auth` (typed as `ServiceAuthUser`).

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

## Internal Dependencies

```
@baseworks/core/codec
  └── base64urlEncode / base64urlDecodeString
        └── pkce.ts        (PKCE verifier/challenge generation)
```

## When to Use What

```
Service-to-service JWT verification (Hono/Node)
  └─ @baseworks/auth/hono         →  requireAuth middleware

Mint a realm token / publish a JWKS (auth-service only)
  └─ @baseworks/auth/identity     →  mint / jwks / loadSigningKey

Verify without Hono
  └─ @baseworks/auth/identity     →  verifier

Raw HS256 JWT verify (legacy)
  └─ @baseworks/auth/jwt          →  verifyHs256Jwt

User OIDC token verification (Workers/Node)
  └─ @baseworks/auth/oidc         →  verifyOidcToken

OIDC token + DB user sync in one step
  └─ @baseworks/auth/oidc-human   →  createOidcHumanResolver

API key hashing / Bearer header parsing
  └─ @baseworks/auth/token        →  hashToken / stripBearer

Sign a person in from a web app
  └─ not this package             →  redirect to auth-service /v1/auth/login

CLI browser auth
  └─ @baseworks/auth/cli          →  login / logout / auth status commands
  └─ @baseworks/auth/cli-auth     →  startCliAuth / pollCliAuth (raw flow)
```
