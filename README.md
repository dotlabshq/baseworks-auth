# @baseworks/auth

Identity for a baseworks realm: verifying tokens, issuing them, and the sign-in
commands a CLI needs.

A **realm** is one deployment of the plane — one auth-service, one signing key
pair, and the services that trust it. A token issued in a realm is accepted by
every service in it and by no other.

```
npm i @baseworks/auth
```

**2.x goes with auth-service 2.x.** The package's major follows the service's,
so which pair belongs together is never a question. 2.0.0 itself changes no
behaviour and no export: what moved is the service (pages at its root, the API
under `/api`; published at `/auth` and `/v1/auth`), and the addresses this
package is handed follow from that:

- `serviceToken({ auth_url })` — through a gateway, `https://<host>/v1/auth` as
  before; calling auth-service directly, `http://<auth>/api` (was the bare
  origin).
- `addAuthCommands({ authBase })` — the origin the realm is published on, as
  before. Not auth-service's own port.
- A web app sends a person to the sign-in page, `/auth/login`.

Moving from 1.x is a deliberate step, not an automatic one: a `^1` range does
not pick this up. Change the range when the realm you talk to runs
auth-service 2. 1.x is kept on branch `1.x` for realms that do not yet.

Subpath imports, so a Worker or a browser bundle never pulls in Node-only code.
The task-oriented guide is below; a per-file reference follows it.

---

## I have a service that needs to verify tokens

The common case, and usually one line:

```ts
import { requireAuth } from '@baseworks/auth/hono'

app.use('*', requireAuth)
app.get('/things', (c) => {
  const { user_id, token_type } = c.get('auth')
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

const token = await mint(key, { sub: user_id, type: 'human' }, {
  issuer: 'https://auth.example.com',
  audience: 'example-realm',
  expires_in_seconds: 86400,
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
job — an app sends the browser to auth-service's sign-in page, `/auth/login`
(auth-service 2.0; `/v1/auth/login` on 1.x, still served through 2.x), and reads
`/v1/auth/session`.

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
  const { user_id, org_id } = c.var.auth
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
  └─ not this package             →  redirect to auth-service /auth/login

CLI browser auth
  └─ @baseworks/auth/cli          →  login / logout / auth status commands
  └─ @baseworks/auth/cli-auth     →  startCliAuth / pollCliAuth (raw flow)
```

## Who is acting (`@baseworks/auth/principal`, 2.2.0)

Workspace ADR 0004. A verified token names one of four kinds of principal:
`human`, `agent` (works for a person, never more than that person), `machine`
(an organization key) and `service`. `requireAuth` reads it once and sets it on
the request:

```ts
const p = c.get('principal')      // also auth.principal
p.kind          // 'human' | 'agent' | 'machine' | 'service'
p.actor         // 'user:<id>' | 'agent:dev@basri' | 'machine:ci@acme' | 'service:billing'
p.via           // 'session' | 'token' | 'key' | 'oauth' | 'client'
p.on_behalf_of  // for an agent: 'user:<id>' of the person it works for
p.act           // 2.4: set when it acts as a role agent: { actor: 'agent:claude-code@basri' }, the connection
p.session_id    // 2.4: the MCP session (a client window) the call belongs to
isSession(p)    // true only for a person who signed in
```

An event is appended with `auditOf(c, { org_id })`: the actor, the request id
as the correlation id, and `metadata.audit` with the same fields in every
service (`kind`, `actor`, `actor_id`, `via`, `on_behalf_of`, `credential_id`,
`client`, `org_id`, `request_id`, and from 2.4 `act` and `session_id` when there are any). A
service does not write an actor by hand.

```ts
await customers.emit(id, 0, 'CustomerCreated', payload, auditOf(c, { org_id }))
```

`X-Request-Id` is kept when it looks like one and minted otherwise;
`X-Baseworks-Client: cli/bw` says which surface a request came through.

Tokens minted before this say only `type`. They are read as what they were:
`human` (and any type this package does not know) is a person who signed in,
`service` is a service, and `assistant` is an agent for its person, so it is
no longer mistaken for a session. `auth.token_type` is kept and now derived
from the principal; it gains `machine`. Nothing mints the new claims yet:
auth-service and iam follow.

### What is believed, and what is not

- An `actor` claim is believed only if it is exactly one actor of the token's
  kind (`^(agent|machine|service):[A-Za-z0-9._-]+(@[A-Za-z0-9._-]+)?$`);
  otherwise it is rebuilt. A person's actor is always built here, and a `sub`
  goes into an actor through the same sanitiser (`id` keeps the raw string).
- `principalOf` never throws: a `sub` that is not a string or a number reads as
  empty.
- **`access` fails closed.** Only an absent claim means no limit. A claim that
  is there but unusable (empty, junk, not an array) is `access: []`: `mayRead`
  and `mayWrite` are both false.
- An agent (`kind: agent`) carries `on_behalf_of` only as `user:<id>`. Without
  it the principal has no `on_behalf_of`, `personOf` is `undefined`, and it can
  do nothing: an agent with nobody behind it has no standing. Only the old
  `assistant` token (no `kind`) defaults to `user:<sub>`.
- **Every minted token must keep `type` beside `kind`.** The verifier rejects a
  token without `type` (and without `sub` or `exp`), so a token with only `kind`
  is a 401.

### API tokens (`bwt_…`) are exchanged where they first arrive (2.2.0)

A bearer that starts with `bwt_` is an API token (iam-service issues them). The
realm keeps one kind of token inside, so `requireAuth` hands it to auth-service
(`POST <AUTH_URL>/exchange-key`, where `AUTH_URL` is auth's API base, e.g.
`http://127.0.0.1:3003/api`), gets a realm token that lives at most five
minutes, and verifies that exactly like any other bearer. Afterwards:

```ts
c.get('principal')    // the agent, the machine or the person the API token stands for
c.get('realm_token')  // the JWT the request was authenticated with: forward THIS, never the bwt_
```

- Without `AUTH_URL` an API token is a 401: it cannot be accepted here.
- Kept in the process by `sha256(token)` until 30 seconds before the realm token
  ends, at most 5 000 entries. A refusal (401 from auth) is kept 10 seconds. An
  error (5xx, network, an answer without a token) is not kept and answers
  `502 auth_unavailable`. Requests with one token at the same moment share one
  call.
- **The cost, said plainly:** a revoked API token keeps working for as long as a
  realm token minted before the revocation lives (up to five minutes), and a
  refused one is asked about again after 10 seconds. `AUTH_EXCHANGE_CACHE=off`
  turns the memory off, for realms that want revocation at once.
- The secret is only ever in the request body to auth. It is never logged or put
  in an error. `resetAuthExchange()` clears the memory (tests).

### Remembering an authorization answer: key it on the credential (2.2.1)

A service that keeps what org-service said a caller may do must key it on
`credentialKey(principal)` (from `@baseworks/auth/principal`), not on the user
id: a session and a read-only token of the same person, or an agent of theirs,
are decided differently, and an answer given to one must never be served to
another. `requireAuth` also runs once per request however many routers register
it.

## snake_case names (2.3.0)

`serviceAudit(name)` and `servicePrincipal(name)` (from `@baseworks/auth/principal`) give an event with no request behind it the actor `service:<name>`.

Data field names are snake_case in code as well as on the wire (workspace ADR
0003). From 2.3.0:

| Now | Deprecated spelling (same value, still set) |
|---|---|
| `auth.user_id`, `auth.org_id`, `auth.token_type` | `auth.userId`, `auth.orgId`, `auth.tokenType` |
| `c.get('request_id')` | `c.get('requestId')` |
| `c.get('realm_token')` | `c.get('realmToken')` |
| `mint(…, { expires_in_seconds })` | `expiresInSeconds` |
| `verifier({ jwks_uri, legacy_hs256_secret })` | `jwksUri`, `legacyHs256Secret` |
| `serviceToken({ auth_url, client_id, client_secret, expires_in, renew_before })` | `authUrl`, `clientId`, `clientSecret`, `expiresIn`, `renewBefore` |

The deprecated names are accepted and set so that a service that has not moved
keeps working unchanged. They go when the last service has moved. Not renamed:
the CLI helpers (`cli`, `cli-auth`, `pkce`, `oidc`), which belong to the apps.

## Acting as a role agent, and sessions (2.4.0)

One OAuth connection (Claude Code) can act as any of its person's agents
(`software@basri`). The realm token then names the **role agent** as the
principal and the connection under RFC 8693's `act`:

```
sub, actor      the role agent (agent:software@basri)
act             { sub: <connection agent id>, actor: "agent:claude-code@basri" }
sid             the MCP session id, when the exchange was given one
```

- `Principal.act?: { actor: string }` and `Principal.session_id?: string`, read
  by `principalOf` from `act` and `sid`. `act` is believed only as an object
  whose `actor` is one `agent:` actor; `sid` only as 1 to 64 visible ASCII
  characters. Anything else reads as absent. Only an agent principal has
  either: on a person, machine or service token they are ignored.
- `auditOf` / `emitAs` write `metadata.audit.act` (the connection's actor
  string) and `metadata.audit.session_id`. Absent on every other event.
- **`credentialKey` includes the connection a role agent acts through**, so a
  permission answer cached for `software` is never served to `platform`, nor to
  the connection itself. A principal without `act` has exactly the key it had.
  The session is not in the key: it decides nothing.
- Acting as adds no authority: what a call may do is the person's standing cut
  by `access` and the agent's standing in the organization. Nothing here
  changes `mayRead`, `mayWrite` or `personOf`.

Additive: no existing name changed.
