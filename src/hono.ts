import type { Context, Next } from 'hono'
import { verifier, type IdentityClaims, type Verifier } from './identity.js'

export interface ServiceAuthUser {
  userId:    string
  orgId?:    string
  role?:     string
  email?:    string
  tokenType: 'user' | 'service' | 'assistant'
}

declare module 'hono' {
  interface ContextVariableMap {
    auth: ServiceAuthUser
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
  const type = claims.type
  return {
    userId:    String(claims.sub ?? ''),
    orgId:     claims['org_id'] as string | undefined,
    role:      claims['role'] as string | undefined,
    email:     claims['email'] as string | undefined,
    // Anything unrecognised is treated as a user token: `service` and
    // `assistant` open doors a plain user token must not, so they are named
    // explicitly and everything else falls to the least privileged reading.
    tokenType: type === 'service' ? 'service' : type === 'assistant' ? 'assistant' : 'user',
  }
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

  c.set('auth', claimsToUser(claims))
  return next()
}
