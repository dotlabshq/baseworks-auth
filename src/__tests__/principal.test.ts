/**
 * Who is acting (workspace ADR 0004): the four kinds read from claims, the
 * actor string, and what an event records.
 */
import { describe, expect, it } from 'vitest'
import { Hono } from 'hono'
import { signHs256Jwt } from '../jwt.js'
import { auditOf, requireAuth, resetAuthVerifier } from '../hono.js'
import {
  actorFor, auditEnvelope, clientOf, emitAs, isSession, mayWrite, personOf, principalOf,
} from '../principal.js'

describe('the kind is read from the token', () => {
  it('a person who signed in', () => {
    const p = principalOf({ sub: 'u1', type: 'human' })
    expect(p).toEqual({ kind: 'human', id: 'u1', actor: 'user:u1', via: 'session' })
    expect(isSession(p)).toBe(true)
    expect(personOf(p)).toBe('u1')
  })

  it('a person through their API token is not a session', () => {
    const p = principalOf({ sub: 'u1', kind: 'human', via: 'token', credential_id: 'tok_9', access: ['read'], org_id: 'o1' })
    expect(p).toEqual({ kind: 'human', id: 'u1', actor: 'user:u1', via: 'token', org_id: 'o1', access: ['read'], credential_id: 'tok_9' })
    expect(isSession(p)).toBe(false)
    expect(mayWrite(p)).toBe(false)
    // A credential id alone is enough to know a token stood behind it.
    expect(principalOf({ sub: 'u1', type: 'human', credential_id: 'tok_9' }).via).toBe('token')
  })

  it('an agent works for a person and names both', () => {
    const p = principalOf({ sub: 'agt_1', kind: 'agent', via: 'oauth', actor: 'agent:dev@basri', on_behalf_of: 'user:u1', org_id: 'o1' })
    expect(p).toMatchObject({ kind: 'agent', id: 'agt_1', actor: 'agent:dev@basri', via: 'oauth', on_behalf_of: 'user:u1', org_id: 'o1' })
    expect(isSession(p)).toBe(false)
    expect(personOf(p)).toBe('u1')
    expect(mayWrite(p)).toBe(true)
  })

  it('a machine acts for its organization, with the role on its key', () => {
    const p = principalOf({ sub: 'key_7', kind: 'machine', actor: 'machine:ci@acme', org_id: 'o1', role: 'member', access: ['read', 'write'], credential_id: 'key_7' })
    expect(p).toEqual({ kind: 'machine', id: 'key_7', actor: 'machine:ci@acme', via: 'key', role: 'member', org_id: 'o1', access: ['read', 'write'], credential_id: 'key_7' })
    expect(personOf(p)).toBeUndefined()
  })

  it('a service is itself', () => {
    expect(principalOf({ sub: 'billing', type: 'service' })).toEqual({ kind: 'service', id: 'billing', actor: 'service:billing', via: 'client' })
  })
})

describe('older and odd tokens', () => {
  it('the narrowed `assistant` token is an agent for its person, never a session', () => {
    const p = principalOf({ sub: 'u1', type: 'assistant', org_id: 'o1' })
    expect(p).toMatchObject({ kind: 'agent', via: 'token', on_behalf_of: 'user:u1', actor: 'agent:assistant@u1', org_id: 'o1' })
    expect(isSession(p)).toBe(false)
  })

  it('an unknown type is a person, as it always was, and never a service', () => {
    const p = principalOf({ sub: 'u1', type: 'user' })
    expect(p).toMatchObject({ kind: 'human', via: 'session', actor: 'user:u1' })
    expect(principalOf({ sub: 'x', type: 'superuser' }).kind).toBe('human')
  })

  it('an actor claim of another kind is not believed', () => {
    // A machine's token cannot name itself a service or a user.
    expect(principalOf({ sub: 'key_7', kind: 'machine', org_id: 'o1', actor: 'service:billing' }).actor).toBe('machine:key_7@o1')
    expect(principalOf({ sub: 'u1', kind: 'human', actor: 'user:somebody-else' }).actor).toBe('user:u1')
  })

  it('a made-up name cannot carry another actor inside it', () => {
    expect(actorFor('agent', 'dev@x agent:root', 'basri')).toBe('agent:dev_x_agent_root@basri')
  })

  it('access that says nothing usable is no limit claimed, and junk is dropped', () => {
    expect(principalOf({ sub: 'u1', kind: 'human', via: 'token', access: ['admin', 'read', 'read'] }).access).toEqual(['read'])
    expect(principalOf({ sub: 'u1', kind: 'human', via: 'token', access: 'write' }).access).toBeUndefined()
  })
})

describe('what an event records', () => {
  const agent = principalOf({ sub: 'agt_1', kind: 'agent', via: 'oauth', actor: 'agent:dev@basri', on_behalf_of: 'user:u1', credential_id: 'grant_3' })

  it('the envelope says who, for whom, with what, through where', () => {
    expect(auditEnvelope(agent, { org_id: 'o1', request_id: 'req-12345678', client: { surface: 'mcp', app: 'claude' } })).toEqual({
      kind: 'agent', actor: 'agent:dev@basri', actor_id: 'agt_1', via: 'oauth',
      on_behalf_of: 'user:u1', credential_id: 'grant_3', client: 'mcp/claude', org_id: 'o1', request_id: 'req-12345678',
    })
  })

  it('the organization falls back to the one the credential is bound to', () => {
    const machine = principalOf({ sub: 'key_7', kind: 'machine', org_id: 'o1', actor: 'machine:ci@acme' })
    expect(auditEnvelope(machine).org_id).toBe('o1')
    expect(auditEnvelope(machine, { org_id: 'o2' }).org_id).toBe('o2')
  })

  it('emitAs is what foldbase appends with', () => {
    expect(emitAs(agent, { request_id: 'req-12345678' })).toEqual({
      actor: 'agent:dev@basri',
      correlationId: 'req-12345678',
      metadata: { audit: { kind: 'agent', actor: 'agent:dev@basri', actor_id: 'agt_1', via: 'oauth', on_behalf_of: 'user:u1', credential_id: 'grant_3', request_id: 'req-12345678' } },
    })
  })

  it('the client header is read, and anything else is the API', () => {
    expect(clientOf('cli/bw')).toEqual({ surface: 'cli', app: 'bw' })
    expect(clientOf('ui')).toEqual({ surface: 'ui' })
    expect(clientOf(undefined)).toEqual({ surface: 'api' })
    expect(clientOf('browser/<script>')).toEqual({ surface: 'api', app: '_script_' })
  })
})

describe('requireAuth sets it on the request', () => {
  const SECRET = 'test-secret-32-chars-long-enough!'
  const app = () => {
    process.env['JWT_SECRET'] = SECRET
    delete process.env['AUTH_JWKS_URI']
    resetAuthVerifier()
    const a = new Hono()
    a.use('*', requireAuth)
    a.get('/who', (c) => c.json({ auth: c.get('auth'), audit: auditOf(c, { org_id: 'o1' }), requestId: c.get('requestId') }))
    return a
  }
  const call = (claims: Record<string, unknown>, headers: Record<string, string> = {}) =>
    Promise.resolve(app().fetch(new Request('http://x/who', { headers: { Authorization: `Bearer ${signHs256Jwt(claims, SECRET, 60)}`, ...headers } })))
      .then((r) => r.json() as Promise<{ auth: { tokenType: string; principal: { kind: string } }; audit: { actor: string; correlationId: string; metadata: { audit: Record<string, string> } }; requestId: string }>)

  it('the older tokenType agrees with the principal', async () => {
    expect((await call({ sub: 'u1', type: 'human' })).auth).toMatchObject({ tokenType: 'user', principal: { kind: 'human' } })
    expect((await call({ sub: 'billing', type: 'service' })).auth).toMatchObject({ tokenType: 'service', principal: { kind: 'service' } })
    expect((await call({ sub: 'u1', type: 'assistant' })).auth).toMatchObject({ tokenType: 'assistant', principal: { kind: 'agent' } })
    expect((await call({ sub: 'key_7', type: 'assistant', kind: 'machine', org_id: 'o1' })).auth).toMatchObject({ tokenType: 'machine', principal: { kind: 'machine' } })
    // `kind` cannot make a person out of a service token's doors or the reverse.
    expect((await call({ sub: 'u1', type: 'human', kind: 'agent', on_behalf_of: 'user:u1' })).auth.tokenType).toBe('assistant')
  })

  it('auditOf carries the request id and the client', async () => {
    const r = await call({ sub: 'u1', type: 'human' }, { 'X-Request-Id': 'req-abcdef12', 'X-Baseworks-Client': 'cli/bw' })
    expect(r.requestId).toBe('req-abcdef12')
    expect(r.audit).toMatchObject({ actor: 'user:u1', correlationId: 'req-abcdef12', metadata: { audit: { kind: 'human', via: 'session', client: 'cli/bw', org_id: 'o1', request_id: 'req-abcdef12' } } })
  })

  it('a request id that does not look like one is replaced', async () => {
    const r = await call({ sub: 'u1', type: 'human' }, { 'X-Request-Id': 'a b' })
    expect(r.requestId).toMatch(/^[0-9a-f-]{36}$/)
  })
})
