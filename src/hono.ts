import { createHash } from 'node:crypto'
import type { Context, Next } from 'hono'
import { verifier, type IdentityClaims, type Verifier } from './identity.js'
import {
  clientOf, emitAs, principalOf, type AuditContext, type ClientInfo, type Principal,
} from './principal.js'

export interface ServiceAuthUser {
  userId:    string
  orgId?:    string
  role?:     string
  email?:    string
  /**
   * The older reading of who is calling. `assistant` is an agent, `machine` an
   * organization key; neither is a person at a keyboard. New code reads
   * `principal`.
   */
  tokenType: 'user' | 'service' | 'assistant' | 'machine'
  /** Who is acting, as every service says it (workspace ADR 0004). */
  principal: Principal
}

declare module 'hono' {
  interface ContextVariableMap {
    auth: ServiceAuthUser
    /** Who is acting. Set by `requireAuth`, the same object as `auth.principal`. */
    principal: Principal
    /** One id for this request across the services it reaches (`X-Request-Id`, or minted here). */
    requestId: string
    /** The surface the request came through (`X-Baseworks-Client`). */
    client: ClientInfo
    /**
     * The realm token this request was authenticated with: the bearer itself
     * when it was a JWT, or what auth-service exchanged an API token (`bwt_…`)
     * for. Forward this to other services, never the API token.
     */
    realmToken: string
  }
}

/**
 * Where the realm's public keys are, and what to expect in a token.
 *
 * Read from the environment so a service picks this up with no code of its own:
 *
 *   AUTH_JWKS_URI   e.g. https://auth.example.com/.well-known/jwks.json
 *   AUTH_ISSUER     expected `iss`; unset means "do not check"
 *   AUTH_AUDIENCE   expected `aud`; unset means "do not check"
 *   JWT_SECRET      legacy HS256 secret, accepted alongside ES256 while set
 *
 * With only JWT_SECRET set, behaviour is exactly what it was before JWKS
 * existed, so a service can be upgraded before the realm has keys.
 */
function fromEnv(env: NodeJS.ProcessEnv): Verifier | { error: string } {
  const jwksUri = env['AUTH_JWKS_URI']
  const legacy = env['JWT_SECRET']
  if (!jwksUri && !legacy) {
    return { error: 'neither AUTH_JWKS_URI nor JWT_SECRET is configured' }
  }
  return verifier({
    ...(jwksUri ? { jwksUri } : {}),
    ...(env['AUTH_ISSUER'] ? { issuer: env['AUTH_ISSUER'] } : {}),
    ...(env['AUTH_AUDIENCE'] ? { audience: env['AUTH_AUDIENCE'] } : {}),
    ...(legacy ? { legacyHs256Secret: legacy } : {}),
  })
}

// Built once: the verifier owns a JWKS cache, and rebuilding it per request
// would refetch the key set on every call.
let cachedVerifier: Verifier | { error: string } | undefined

/** Tests change the environment between cases. */
export function resetAuthVerifier(): void {
  cachedVerifier = undefined
}

function claimsToUser(claims: IdentityClaims): ServiceAuthUser {
  const principal = principalOf(claims)
  return {
    userId:    String(claims.sub ?? ''),
    orgId:     claims['org_id'] as string | undefined,
    role:      claims['role'] as string | undefined,
    email:     claims['email'] as string | undefined,
    // Derived from the principal, so the two can never disagree. Only a
    // service token opens a service's doors, and only a person is a `user`.
    tokenType: principal.kind === 'service' ? 'service'
      : principal.kind === 'human' ? 'user'
      : principal.kind === 'machine' ? 'machine'
      : 'assistant',
    principal,
  }
}

// ── API tokens (`bwt_…`), exchanged where they first arrive (ADR 0004 §7) ────

type Exchanged =
  | { status: 'ok'; token: string }
  | { status: 'refused' }
  | { status: 'unconfigured' }
  | { status: 'error' }

/** Kept until 30 seconds before the realm token ends; a refusal for 10 seconds. */
const EXCHANGE_MARGIN_MS = 30_000
const REFUSAL_MS = 10_000
const EXCHANGE_MAX_ENTRIES = 5_000

const exchanged = new Map<string, { result: Exchanged; until: number }>()
const exchanging = new Map<string, Promise<Exchanged>>()

/** Tests change the environment and the clock between cases. */
export function resetAuthExchange(): void {
  exchanged.clear()
  exchanging.clear()
}

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex')

/**
 * Ask auth-service (`AUTH_URL`, its API base, e.g. `http://127.0.0.1:3003/api`)
 * for a realm token in place of an API token. The secret is never logged or put
 * in an error: it is in the request body and nowhere else.
 */
async function callExchange(apiToken: string): Promise<{ result: Exchanged; ttlMs: number }> {
  const base = (process.env['AUTH_URL'] ?? '').replace(/\/+$/, '')
  if (!base) return { result: { status: 'unconfigured' }, ttlMs: 0 }
  try {
    const res = await fetch(`${base}/exchange-key`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: apiToken }),
    })
    if (res.status === 401) return { result: { status: 'refused' }, ttlMs: REFUSAL_MS }
    if (!res.ok) {
      console.error(`[auth] exchange answered ${res.status}`)
      return { result: { status: 'error' }, ttlMs: 0 }
    }
    const body = (await res.json().catch(() => null)) as { token?: unknown; expires_in?: unknown } | null
    if (typeof body?.token !== 'string' || !body.token) {
      console.error('[auth] exchange answered without a token')
      return { result: { status: 'error' }, ttlMs: 0 }
    }
    const seconds = typeof body.expires_in === 'number' && body.expires_in > 0 ? body.expires_in : 0
    return { result: { status: 'ok', token: body.token }, ttlMs: seconds * 1000 - EXCHANGE_MARGIN_MS }
  } catch (err) {
    console.error(`[auth] exchange failed: ${(err as Error).name}`)
    return { result: { status: 'error' }, ttlMs: 0 }
  }
}

async function exchangeApiToken(apiToken: string): Promise<Exchanged> {
  const key = sha256(apiToken)
  const memory = process.env['AUTH_EXCHANGE_CACHE'] !== 'off'
  if (memory) {
    const hit = exchanged.get(key)
    if (hit && hit.until > Date.now()) return hit.result
    if (hit) exchanged.delete(key)
  }
  const running = exchanging.get(key)
  if (running) return running
  const run = (async () => {
    const { result, ttlMs } = await callExchange(apiToken)
    if (memory && ttlMs > 0) {
      if (exchanged.size >= EXCHANGE_MAX_ENTRIES) exchanged.clear()
      exchanged.set(key, { result, until: Date.now() + ttlMs })
    }
    return result
  })().finally(() => exchanging.delete(key))
  exchanging.set(key, run)
  return run
}

/** A request id somebody else minted is kept only if it looks like one. */
const requestIdOf = (header: string | undefined): string =>
  header && /^[A-Za-z0-9._-]{8,128}$/.test(header) ? header : crypto.randomUUID()

/**
 * What to append an event with, for this request: the actor, the audit
 * envelope and the request id (workspace ADR 0004 §6). `org_id` is the
 * organization the request was resolved to, when the route has one.
 *
 *     await customers.emit(id, 0, 'CustomerCreated', payload, auditOf(c, { org_id }))
 */
export function auditOf(c: Context, ctx: Pick<AuditContext, 'org_id'> = {}) {
  return emitAs(c.get('principal'), { ...ctx, client: c.get('client'), request_id: c.get('requestId') })
}

/**
 * Hono middleware — verifies the realm's identity token from
 * `Authorization: Bearer` and sets `c.var.auth`.
 *
 * ES256 verified against the realm's published JWKS, plus HS256 while a legacy
 * secret is configured. The shared secret is a migration door: any service
 * holding it can also MINT tokens, including one claiming to be another user,
 * so it should be removed once the realm issues ES256 everywhere.
 */
export async function requireAuth(c: Context, next: Next) {
  const header = c.req.header('Authorization')
  if (!header?.startsWith('Bearer ')) return c.json({ error: 'Unauthorized' }, 401)

  cachedVerifier ??= fromEnv(process.env)
  if (typeof cachedVerifier !== 'function') {
    // A misconfigured service must not look like a rejected caller: 500 tells
    // the operator it is their problem, 401 would send the user in circles.
    console.error(`[auth] ${cachedVerifier.error}`)
    return c.json({ error: 'auth is not configured' }, 500)
  }

  // An API token is exchanged for a realm token where it first arrives; from
  // here on the request is authenticated by that JWT, exactly like any other.
  let bearer = header.slice(7)
  if (bearer.startsWith('bwt_')) {
    const r = await exchangeApiToken(bearer)
    // No AUTH_URL: an API token cannot be accepted here. A refusal is a 401.
    if (r.status === 'unconfigured' || r.status === 'refused') return c.json({ error: 'Unauthorized' }, 401)
    if (r.status === 'error') return c.json({ error: 'auth_unavailable' }, 502)
    bearer = r.token
  }

  const claims = await cachedVerifier(bearer)
  if (!claims) return c.json({ error: 'Unauthorized' }, 401)

  const auth = claimsToUser(claims)
  c.set('auth', auth)
  c.set('principal', auth.principal)
  c.set('realmToken', bearer)
  c.set('requestId', requestIdOf(c.req.header('X-Request-Id')))
  c.set('client', clientOf(c.req.header('X-Baseworks-Client')))
  return next()
}
