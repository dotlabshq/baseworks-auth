/**
 * `requireAuth` accepts an API token (`bwt_…`) by exchanging it at auth-service
 * (@baseworks/auth 2.2.0, workspace ADR 0004 §7): once per token, remembered
 * briefly, refusals remembered shorter, errors not at all, and the secret
 * never anywhere but the request to auth.
 */
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { Hono } from 'hono'
import { exportPKCS8, generateKeyPair } from 'jose'
import { jwks, loadSigningKey, mint } from '../identity.js'
import { signHs256Jwt } from '../jwt.js'
import { requireAuth, resetAuthExchange, resetAuthVerifier } from '../hono.js'

const SECRET = 'test-secret-32-chars-long-enough!'
const KEY = (n: number | string = 1) => `bwt_never-leak-this-secret-${n}`
const saved = { ...process.env }

type Req = { url: string; method: string; headers: Headers; body: { token?: string } }
let calls: Req[]
let respond: (req: Req) => Response | Promise<Response>
let realFetch: typeof fetch

/** What auth-service would mint for a token. */
const realm = (claims: Record<string, unknown>, seconds = 300) => signHs256Jwt({ type: 'assistant', ...claims } as never, SECRET, seconds)
const ok = (token: string, expires_in = 300) => new Response(JSON.stringify({ token, token_type: 'bearer', expires_in }), { status: 200 })
const AGENT = (extra: Record<string, unknown> = {}) => ({ sub: 'agt-1', kind: 'agent', via: 'token', actor: 'agent:dev@ada', on_behalf_of: 'user:u1', credential_id: 'tok-1', access: ['read'], ...extra })

function app() {
  const a = new Hono()
  a.use('*', requireAuth)
  a.get('/who', (c) => c.json({ auth: c.get('auth'), realmToken: c.get('realmToken'), principal: c.get('principal') }))
  return a
}
const get = (bearer: string, a = app()) => a.fetch(new Request('http://x/who', { headers: { Authorization: `Bearer ${bearer}` } }))
const who = async (res: Response) => (await res.json()) as { auth: { tokenType: string; userId: string }; realmToken: string; principal: Record<string, any> }

beforeEach(() => {
  process.env = { ...saved }
  process.env['JWT_SECRET'] = SECRET
  process.env['AUTH_URL'] = 'http://auth.test/api'
  delete process.env['AUTH_JWKS_URI']
  delete process.env['AUTH_EXCHANGE_CACHE']
  resetAuthVerifier(); resetAuthExchange()
  calls = []
  respond = () => ok(realm(AGENT()))
  realFetch = globalThis.fetch
  vi.stubGlobal('fetch', async (url: string | URL | Request, init?: RequestInit) => {
    if (String(url).startsWith('http://127.0.0.1')) return realFetch(url as never, init)
    calls.push({ url: String(url), method: init?.method ?? 'GET', headers: new Headers(init?.headers), body: init?.body ? JSON.parse(String(init.body)) : {} })
    return respond(calls.at(-1)!)
  })
})
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); process.env = { ...saved }; resetAuthVerifier(); resetAuthExchange() })

describe('exchanging', () => {
  it('asks auth-service once, at AUTH_URL/exchange-key, with the token in the body and no Authorization', async () => {
    process.env['AUTH_URL'] = 'http://auth.test/api///'
    const res = await get(KEY())
    expect(res.status).toBe(200)
    expect(calls).toHaveLength(1)
    expect(calls[0]).toMatchObject({ url: 'http://auth.test/api/exchange-key', method: 'POST', body: { token: KEY() } })
    expect(calls[0]!.headers.get('authorization')).toBeNull()
  })

  it('the request then runs on the realm token: principal, tokenType and realmToken', async () => {
    const jwt = realm(AGENT())
    respond = () => ok(jwt)
    const w = await who(await get(KEY()))
    expect(w.realmToken).toBe(jwt)
    expect(w.realmToken).not.toBe(KEY())
    expect(w.auth).toMatchObject({ userId: 'agt-1', tokenType: 'assistant' })
    expect(w.principal).toMatchObject({ kind: 'agent', id: 'agt-1', actor: 'agent:dev@ada', via: 'token', on_behalf_of: 'user:u1', credential_id: 'tok-1', access: ['read'] })
  })

  it('a person, an agent and a machine come out as themselves, none of them a session', async () => {
    const shapes: Array<[Record<string, unknown>, string, string, string]> = [
      [{ sub: 'u1', kind: 'human', via: 'token', actor: 'user:u1', credential_id: 't1', access: ['read'] }, 'user', 'human', 'token'],
      [AGENT(), 'assistant', 'agent', 'token'],
      [{ sub: 'k1', kind: 'machine', via: 'key', actor: 'machine:ci@o1', credential_id: 'k1', role: 'member', org_id: 'o1', access: ['read'] }, 'machine', 'machine', 'key'],
    ]
    for (const [claims, tokenType, kind, via] of shapes) {
      resetAuthExchange()
      respond = () => ok(realm(claims))
      const w = await who(await get(KEY(kind)))
      expect(w.auth.tokenType).toBe(tokenType)
      expect(w.principal).toMatchObject({ kind, via })
      expect(w.principal['via']).not.toBe('session')
    }
  })

  it('a bearer that is already a JWT is not exchanged, and is its own realmToken', async () => {
    const jwt = realm({ sub: 'u1', type: 'human' })
    const w = await who(await get(jwt))
    expect(calls).toEqual([])
    expect(w.realmToken).toBe(jwt)
  })

  it('only a bearer that starts with bwt_ is an API token', async () => {
    for (const b of ['bwt', 'BWT_x', 'xbwt_x', 'bwt-x']) expect((await get(b)).status, b).toBe(401)
    expect(calls).toEqual([])
  })

  it('without AUTH_URL an API token cannot be accepted: 401, and nobody is asked', async () => {
    delete process.env['AUTH_URL']
    expect((await get(KEY())).status).toBe(401)
    expect(calls).toEqual([])
    // …but a JWT still is
    expect((await get(realm({ sub: 'u1', type: 'human' }))).status).toBe(200)
  })

  it('the rest of requireAuth is unchanged: no header 401, nothing configured 500', async () => {
    expect((await app().fetch(new Request('http://x/who'))).status).toBe(401)
    delete process.env['JWT_SECRET']; delete process.env['AUTH_JWKS_URI']
    resetAuthVerifier()
    vi.spyOn(console, 'error').mockImplementation(() => {})
    expect((await get(KEY())).status).toBe(500)
    expect(calls).toEqual([])
  })

  it('what comes back must verify like any bearer: a token the verifier rejects is 401', async () => {
    const bad: Array<[string, string]> = [
      ['another secret', signHs256Jwt({ sub: 'x', type: 'assistant', kind: 'agent' } as never, 'a-different-secret-that-is-long-enough!!', 60)],
      ['expired', signHs256Jwt({ sub: 'x', type: 'assistant' } as never, SECRET, -60)],
      ['not a token', 'garbage'],
      ['no type', signHs256Jwt({ sub: 'x', kind: 'agent' } as never, SECRET, 60)],
    ]
    for (const [name, jwt] of bad) {
      resetAuthExchange()
      respond = () => ok(jwt)
      expect((await get(KEY(name))).status, name).toBe(401)
    }
  })
})

describe('once per request', () => {
  it('requireAuth registered several times on one request exchanges once, even with the memory off', async () => {
    process.env['AUTH_EXCHANGE_CACHE'] = 'off'
    const a = new Hono()
    a.use('*', requireAuth); a.use('*', requireAuth); a.use('/who', requireAuth)
    a.get('/who', (c) => c.json({ realmToken: c.get('realmToken') }))
    const res = await a.fetch(new Request('http://x/who', { headers: { Authorization: `Bearer ${KEY()}` } }))
    expect(res.status).toBe(200)
    expect(calls).toHaveLength(1)
  })

  it('a second request is its own: it is authenticated again', async () => {
    process.env['AUTH_EXCHANGE_CACHE'] = 'off'
    await get(KEY()); await get(KEY())
    expect(calls).toHaveLength(2)
  })
})

describe('remembered by the hash of the token', () => {
  it('once per token across many requests', async () => {
    for (let i = 0; i < 12; i++) expect((await get(KEY())).status).toBe(200)
    expect(calls).toHaveLength(1)
  })

  it('every token has its own entry: nothing is shared between two', async () => {
    respond = (r) => ok(realm(AGENT({ sub: r.body.token === KEY('a') ? 'agt-a' : 'agt-b' })))
    expect((await who(await get(KEY('a')))).auth.userId).toBe('agt-a')
    expect((await who(await get(KEY('b')))).auth.userId).toBe('agt-b')
    expect((await who(await get(KEY('a')))).auth.userId).toBe('agt-a')
    expect(calls).toHaveLength(2)
  })

  it('the entry is keyed on a hash: the secret is not a key anywhere we can see, and a near-miss is a different token', async () => {
    await get(KEY('x'))
    await get(KEY('x') + 'z')
    await get(KEY('x').slice(0, -1))
    expect(calls).toHaveLength(3)
  })

  it('refreshes before the realm token ends: kept until 30 seconds before', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'))
    respond = () => ok(realm(AGENT()), 300)
    await get(KEY())
    vi.setSystemTime(Date.now() + 269_000)
    await get(KEY())
    expect(calls).toHaveLength(1)
    vi.setSystemTime(Date.now() + 2_000) // 271 s: the margin is passed
    respond = () => ok(realm(AGENT({ sub: 'agt-2' })), 300)
    expect((await who(await get(KEY()))).auth.userId).toBe('agt-2')
    expect(calls).toHaveLength(2)
  })

  it('a realm token with less than the margin left is not remembered at all', async () => {
    respond = () => ok(realm(AGENT()), 20)
    await get(KEY()); await get(KEY()); await get(KEY())
    expect(calls).toHaveLength(3)
  })

  it('a refusal is remembered for 10 seconds and then asked again', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'))
    respond = () => new Response(JSON.stringify({ error: 'invalid_token' }), { status: 401 })
    for (let i = 0; i < 5; i++) expect((await get(KEY())).status).toBe(401)
    expect(calls).toHaveLength(1)
    vi.setSystemTime(Date.now() + 9_000)
    expect((await get(KEY())).status).toBe(401)
    expect(calls).toHaveLength(1)
    vi.setSystemTime(Date.now() + 2_000)
    respond = () => ok(realm(AGENT()))
    expect((await get(KEY())).status).toBe(200)
    expect(calls).toHaveLength(2)
  })

  it('a refusal for one token does not refuse another', async () => {
    respond = (r) => r.body.token === KEY('bad') ? new Response('{}', { status: 401 }) : ok(realm(AGENT()))
    expect((await get(KEY('bad'))).status).toBe(401)
    expect((await get(KEY('good'))).status).toBe(200)
  })

  it('an error is not remembered: 5xx, network, and no token in the answer are 502 auth_unavailable, and the next request asks again', async () => {
    const failures: Array<() => Response | Promise<Response>> = [
      () => new Response('{}', { status: 500 }), () => new Response('{}', { status: 503 }), () => new Response('{}', { status: 502 }),
      () => new Response('{}', { status: 403 }), () => new Response('not json', { status: 200 }), () => new Response('{}', { status: 200 }),
      () => { throw new TypeError('fetch failed') },
    ]
    vi.spyOn(console, 'error').mockImplementation(() => {})
    for (const f of failures) {
      respond = f
      const res = await get(KEY())
      expect(res.status).toBe(502)
      expect(await res.json()).toEqual({ error: 'auth_unavailable' })
    }
    expect(calls).toHaveLength(failures.length)
    respond = () => ok(realm(AGENT()))
    expect((await get(KEY())).status).toBe(200)
  })

  it('an error after a good answer does not unseat it', async () => {
    await get(KEY())
    respond = () => new Response('{}', { status: 500 })
    expect((await get(KEY())).status).toBe(200)
    expect(calls).toHaveLength(1)
  })

  it('at most 5 000 entries: past that the memory starts over', async () => {
    respond = () => ok(realm(AGENT()))
    for (let i = 0; i < 5001; i++) await get(KEY(i))
    const before = calls.length
    await get(KEY(5000))            // the newest survives the clear
    expect(calls.length).toBe(before)
    await get(KEY(0))               // the oldest does not
    expect(calls.length).toBe(before + 1)
  }, 60_000)
})

describe('concurrency', () => {
  it('requests with one token at the same moment share one exchange', async () => {
    let release!: () => void
    const gate = new Promise<void>((r) => { release = r })
    respond = async () => { await gate; return ok(realm(AGENT())) }
    const all = Promise.all(Array.from({ length: 25 }, () => get(KEY())))
    await new Promise((r) => setTimeout(r, 30))
    release()
    const results = await all
    expect(results.map((r) => r.status)).toEqual(Array(25).fill(200))
    expect(calls).toHaveLength(1)
  })

  it('different tokens at the same moment do not share', async () => {
    respond = async (r) => ok(realm(AGENT({ sub: String(r.body.token) })))
    const results = await Promise.all(['a', 'b', 'c'].map(async (k) => who(await get(KEY(k)))))
    expect(results.map((r) => r.auth.userId).sort()).toEqual([KEY('a'), KEY('b'), KEY('c')])
    expect(calls).toHaveLength(3)
  })

  it('sharing a failure shares it once, and the next request tries again', async () => {
    let release!: () => void
    const gate = new Promise<void>((r) => { release = r })
    vi.spyOn(console, 'error').mockImplementation(() => {})
    respond = async () => { await gate; return new Response('{}', { status: 500 }) }
    const all = Promise.all(Array.from({ length: 6 }, () => get(KEY())))
    await new Promise((r) => setTimeout(r, 20)); release()
    expect((await all).map((r) => r.status)).toEqual(Array(6).fill(502))
    expect(calls).toHaveLength(1)
    respond = () => ok(realm(AGENT()))
    expect((await get(KEY())).status).toBe(200)
    expect(calls).toHaveLength(2)
  })
})

describe('AUTH_EXCHANGE_CACHE=off', () => {
  beforeEach(() => { process.env['AUTH_EXCHANGE_CACHE'] = 'off' })

  it('every request exchanges: a revoked token is refused at once', async () => {
    expect((await get(KEY())).status).toBe(200)
    expect((await get(KEY())).status).toBe(200)
    expect(calls).toHaveLength(2)
    respond = () => new Response('{}', { status: 401 })
    expect((await get(KEY())).status).toBe(401)
    expect((await get(KEY())).status).toBe(401)
    expect(calls).toHaveLength(4)
  })

  it('and a refusal is not remembered either', async () => {
    respond = () => new Response('{}', { status: 401 })
    await get(KEY()); await get(KEY())
    expect(calls).toHaveLength(2)
  })

  it('requests at the very same moment still share the call', async () => {
    let release!: () => void
    const gate = new Promise<void>((r) => { release = r })
    respond = async () => { await gate; return ok(realm(AGENT())) }
    const all = Promise.all([get(KEY()), get(KEY()), get(KEY())])
    await new Promise((r) => setTimeout(r, 20)); release(); await all
    expect(calls).toHaveLength(1)
  })

  it('turning it off later does not use what was remembered before', async () => {
    delete process.env['AUTH_EXCHANGE_CACHE']
    await get(KEY())
    process.env['AUTH_EXCHANGE_CACHE'] = 'off'
    await get(KEY())
    expect(calls).toHaveLength(2)
  })
})

describe('the secret', () => {
  it('is in no log line and no response, whatever happens', async () => {
    const lines: string[] = []
    for (const m of ['log', 'warn', 'error', 'info', 'debug'] as const) vi.spyOn(console, m).mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')) })
    const texts: string[] = []
    const scenarios: Array<() => Response | Promise<Response>> = [
      () => ok(realm(AGENT())), () => new Response('{}', { status: 401 }), () => new Response('{}', { status: 500 }),
      () => new Response('nope', { status: 200 }), () => { throw new TypeError(`fetch failed, cause: ${KEY('s')}`) },
      () => ok(signHs256Jwt({ sub: 'x', type: 'assistant' } as never, 'another-secret-that-is-long-enough!!!!!', 60)),
    ]
    for (const [i, s] of scenarios.entries()) {
      resetAuthExchange()
      respond = s
      texts.push(await (await get(KEY('s'))).text())
      void i
    }
    expect(calls.length).toBe(scenarios.length)
    // the secret goes to auth in the request body and nowhere else
    for (const t of [...lines, ...texts]) expect(t).not.toContain('never-leak-this-secret')
    // …and on a success what the handler sees is the JWT only
    const w = await who(await get(KEY('t')))
    expect(JSON.stringify(w)).not.toContain('never-leak-this-secret')
  })
})

describe('with an ES256 realm', () => {
  let server: Server
  let jwksUri = ''
  let signing: Awaited<ReturnType<typeof loadSigningKey>>
  beforeAll(async () => {
    signing = await loadSigningKey(await exportPKCS8((await generateKeyPair('ES256', { extractable: true })).privateKey))
    server = createServer((_q, r) => { r.setHeader('content-type', 'application/json'); r.end(JSON.stringify(jwks(signing))) })
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
    jwksUri = `http://127.0.0.1:${(server.address() as AddressInfo).port}/jwks.json`
  })
  afterAll(() => { server.close() })

  it('exchanges to an ES256 token and verifies it against the JWKS, and an HS256 one is refused when the realm has no secret', async () => {
    delete process.env['JWT_SECRET']
    process.env['AUTH_JWKS_URI'] = jwksUri
    process.env['AUTH_ISSUER'] = 'https://auth.example.test'
    process.env['AUTH_AUDIENCE'] = 'example-realm'
    resetAuthVerifier()
    const es = await mint(signing, { sub: 'agt-1', type: 'assistant', kind: 'agent', via: 'token', actor: 'agent:dev@ada', on_behalf_of: 'user:u1' }, { issuer: 'https://auth.example.test', audience: 'example-realm', expiresInSeconds: 300 })
    respond = () => ok(es)
    const w = await who(await get(KEY()))
    expect(w.principal).toMatchObject({ kind: 'agent', actor: 'agent:dev@ada' })
    expect(w.realmToken).toBe(es)
    resetAuthExchange()
    respond = () => ok(realm(AGENT()))   // signed with a secret this realm does not trust
    expect((await get(KEY())).status).toBe(401)
    const wrongAud = await mint(signing, { sub: 'x', type: 'assistant' }, { issuer: 'https://auth.example.test', audience: 'other', expiresInSeconds: 60 })
    resetAuthExchange()
    respond = () => ok(wrongAud)
    expect((await get(KEY())).status).toBe(401)
  })
})
