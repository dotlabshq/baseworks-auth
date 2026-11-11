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

  const claims = await cachedVerifier(header.slice(7))
  if (!claims) return c.json({ error: 'Unauthorized' }, 401)

  const auth = claimsToUser(claims)
  c.set('auth', auth)
  c.set('principal', auth.principal)
  c.set('requestId', requestIdOf(c.req.header('X-Request-Id')))
  c.set('client', clientOf(c.req.header('X-Baseworks-Client')))
  return next()
}
