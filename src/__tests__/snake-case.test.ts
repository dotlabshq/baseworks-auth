/**
 * @baseworks/auth 2.3.0: data field names are snake_case. The camelCase
 * spellings stay for the services that have not moved yet, with the same values.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Hono } from 'hono'
import { generateKeyPair, exportPKCS8 } from 'jose'
import { jwks, loadSigningKey, mint, verifier } from '../identity.js'
import { signHs256Jwt } from '../jwt.js'
import { auditOf, requireAuth, resetAuthExchange, resetAuthVerifier } from '../hono.js'
import { serviceToken } from '../service-token.js'

const SECRET = 'test-secret-32-chars-long-enough!'
const saved = { ...process.env }

beforeEach(() => {
  process.env = { ...saved, JWT_SECRET: SECRET }
  delete process.env['AUTH_JWKS_URI']
  resetAuthVerifier(); resetAuthExchange()
})
afterEach(() => { process.env = { ...saved }; resetAuthVerifier(); resetAuthExchange(); vi.restoreAllMocks() })

function app() {
  const a = new Hono()
  a.use('*', requireAuth)
  a.get('/who', (c) => c.json({
    auth: c.get('auth'),
    keys: {
      request_id: c.get('request_id'), requestId: c.get('requestId'),
      realm_token: c.get('realm_token'), realmToken: c.get('realmToken'),
    },
    audit: auditOf(c, { org_id: 'org-1' }),
  }))
  return a
}
const get = async (token: string, headers: Record<string, string> = {}) => {
  const res = await app().fetch(new Request('http://x/who', { headers: { Authorization: `Bearer ${token}`, ...headers } }))
  return { status: res.status, body: (await res.json()) as any }
}

describe('ServiceAuthUser', () => {
  it('a person: snake_case fields, the deprecated spellings carry the same values', async () => {
    const token = signHs256Jwt({ sub: 'u1', type: 'human', org_id: 'o1', role: 'admin', email: 'a@b.c' }, SECRET, 60)
    const { status, body } = await get(token)
    expect(status).toBe(200)
    const { principal, ...rest } = body.auth
    expect(principal.kind).toBe('human')
    expect(rest).toEqual({
      user_id: 'u1', org_id: 'o1', role: 'admin', email: 'a@b.c', token_type: 'user',
      userId: 'u1', orgId: 'o1', tokenType: 'user',
    })
  })

  it.each([
    ['service', { sub: 'svc', type: 'service' }, 'service'],
    ['assistant', { sub: 'agt', type: 'assistant', kind: 'agent', via: 'token', actor: 'agent:dev@ada', on_behalf_of: 'user:u1', credential_id: 'c1', access: ['read'] }, 'assistant'],
    ['machine', { sub: 'mac', type: 'assistant', kind: 'machine', via: 'key', actor: 'machine:ci@o1', org_id: 'o1', role: 'member', credential_id: 'c2' }, 'machine'],
  ])('%s: token_type and tokenType agree', async (_n, claims, expected) => {
    const { body } = await get(signHs256Jwt(claims as never, SECRET, 60))
    expect(body.auth.token_type).toBe(expected)
    expect(body.auth.tokenType).toBe(expected)
    expect(body.auth.user_id).toBe(claims.sub)
    expect(body.auth.userId).toBe(claims.sub)
  })

  it('absent optional fields stay absent under both spellings', async () => {
    const { body } = await get(signHs256Jwt({ sub: 'u1', type: 'human' }, SECRET, 60))
    for (const k of ['org_id', 'orgId', 'role', 'email']) expect(body.auth).not.toHaveProperty(k)
  })
})

describe('context keys', () => {
  it('request_id and realm_token are set, with requestId and realmToken beside them', async () => {
    const token = signHs256Jwt({ sub: 'u1', type: 'human' }, SECRET, 60)
    const { body } = await get(token, { 'X-Request-Id': 'req-abcdefgh-1' })
    expect(body.keys).toEqual({ request_id: 'req-abcdefgh-1', requestId: 'req-abcdefgh-1', realm_token: token, realmToken: token })
  })

  it('a minted request id is the same under both keys', async () => {
    const { body } = await get(signHs256Jwt({ sub: 'u1', type: 'human' }, SECRET, 60))
    expect(body.keys.request_id).toMatch(/^[0-9a-f-]{36}$/)
    expect(body.keys.requestId).toBe(body.keys.request_id)
  })

  it('auditOf carries the request id from request_id', async () => {
    const { body } = await get(signHs256Jwt({ sub: 'u1', type: 'human' }, SECRET, 60), { 'X-Request-Id': 'req-abcdefgh-2' })
    expect(body.audit.correlationId).toBe('req-abcdefgh-2')
    expect(body.audit.metadata.audit.request_id).toBe('req-abcdefgh-2')
  })

  it('a second requireAuth on the same request is a no-op (keyed on realm_token)', async () => {
    const a = new Hono()
    a.use('*', requireAuth)
    a.use('*', requireAuth)
    a.get('/x', (c) => c.json({ id: c.get('request_id') }))
    const res = await a.fetch(new Request('http://x/x', { headers: { Authorization: `Bearer ${signHs256Jwt({ sub: 'u', type: 'human' }, SECRET, 60)}`, 'X-Request-Id': 'req-abcdefgh-3' } }))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ id: 'req-abcdefgh-3' })
  })
})

describe('option objects', () => {
  it('mint and verifier take snake_case; the camelCase keys still work', async () => {
    const { privateKey } = await generateKeyPair('ES256', { extractable: true })
    const key = await loadSigningKey(await exportPKCS8(privateKey))
    const set = jwks(key)
    for (const opts of [
      { issuer: 'i', audience: 'a', expires_in_seconds: 60 },
      { issuer: 'i', audience: 'a', expiresInSeconds: 60 },
    ]) {
      const token = await mint(key, { sub: 's', type: 'human' }, opts)
      const claims = await verifier({ jwks: set, issuer: 'i', audience: 'a' })(token)
      expect(claims?.sub).toBe('s')
      expect((claims!.exp ?? 0) - (claims!.iat ?? 0)).toBe(60)
    }
    await expect(mint(key, { sub: 's', type: 'human' }, { issuer: 'i', audience: 'a' })).rejects.toThrow(/expires_in_seconds/)

    const legacy = signHs256Jwt({ sub: 'u', type: 'human' }, SECRET, 60)
    expect((await verifier({ legacy_hs256_secret: SECRET })(legacy))?.sub).toBe('u')
    expect((await verifier({ legacyHs256Secret: SECRET })(legacy))?.sub).toBe('u')
    expect(() => verifier({})).toThrow(/jwks_uri/)
  })

  it('serviceToken takes snake_case; the camelCase keys still work; the request body is unchanged', async () => {
    const bodies: unknown[] = []
    const f = (async (url: string, init: RequestInit) => {
      bodies.push({ url, body: JSON.parse(String(init.body)) })
      return new Response(JSON.stringify({ token: 't', expires_in: 300 }), { status: 200 })
    }) as unknown as typeof fetch
    const a = serviceToken({ auth_url: 'http://auth/api/', client_id: 'svc', client_secret: 's3', expires_in: 120, renew_before: 10, fetch: f })
    const b = serviceToken({ authUrl: 'http://auth/api', clientId: 'svc', clientSecret: 's3', expiresIn: 120, renewBefore: 10, fetch: f })
    expect(await a()).toBe('t')
    expect(await b()).toBe('t')
    expect(bodies[1]).toEqual(bodies[0])
    expect(bodies[0]).toEqual({ url: 'http://auth/api/service-token', body: { client_id: 'svc', client_secret: 's3', expires_in: 120 } })
    expect(() => serviceToken({ auth_url: 'http://auth' })).toThrow(/client_id/)
  })
})

describe('serviceAudit', () => {
  it('a service acts as itself: actor service:<name>, the whole envelope', async () => {
    const { serviceAudit, servicePrincipal, principalOf } = await import('../principal.js')
    expect(serviceAudit('iam-service')).toEqual({
      actor: 'service:iam-service',
      metadata: { audit: { kind: 'service', actor: 'service:iam-service', actor_id: 'iam-service', via: 'client' } },
    })
    expect(serviceAudit('x', { org_id: 'o1', request_id: 'r1' })).toEqual({
      actor: 'service:x',
      metadata: { audit: { kind: 'service', actor: 'service:x', actor_id: 'x', via: 'client', org_id: 'o1', request_id: 'r1' } },
      correlationId: 'r1',
    })
    // The same principal a verified service token reads as.
    expect(servicePrincipal('svc')).toEqual(principalOf({ sub: 'svc', type: 'service' }))
  })
})
