import { describe, expect, it } from 'vitest'
import { auditEnvelope, credentialKey, emitAs, principalOf } from '../principal.js'

const role = {
  sub: 'ag_software', type: 'assistant', kind: 'agent', via: 'oauth', actor: 'agent:software@basri', on_behalf_of: 'user:u1',
  credential_id: 'g1', access: ['read'], act: { sub: 'ag_conn', actor: 'agent:claude-code@basri' }, sid: 'sess-1',
}

describe('act and sid (acting as a role agent)', () => {
  it('act and sid round-trip through principalOf and the audit envelope', () => {
    const p = principalOf(role)
    expect(p.id).toBe('ag_software')
    expect(p.actor).toBe('agent:software@basri')
    expect(p.act).toEqual({ actor: 'agent:claude-code@basri' })
    expect(p.session_id).toBe('sess-1')
    const e = emitAs(p)
    expect(e.actor).toBe('agent:software@basri')
    expect(e.metadata.audit).toMatchObject({ actor: 'agent:software@basri', credential_id: 'g1', act: 'agent:claude-code@basri', session_id: 'sess-1', on_behalf_of: 'user:u1' })
  })

  it('a principal without act or sid is exactly what it was', () => {
    const { act: _a, sid: _s, ...plain } = role
    const p = principalOf(plain)
    expect('act' in p).toBe(false)
    expect('session_id' in p).toBe(false)
    const audit = auditEnvelope(p)
    expect('act' in audit).toBe(false)
    expect('session_id' in audit).toBe(false)
  })

  it.each([
    ['not an object', 'agent:claude-code@basri'], ['an array', [{ actor: 'agent:x@y' }]], ['no actor', { sub: 'x' }],
    ['a person actor', { actor: 'user:u1' }], ['a service actor', { actor: 'service:mcp' }], ['a forged shape', { actor: 'agent:x@y z' }], ['null', null],
  ])('act that is %s is no act', (_n, act) => {
    expect(principalOf({ ...role, act }).act).toBeUndefined()
  })

  it.each([['empty', ''], ['too long', 'a'.repeat(65)], ['a space', 'a b'], ['a control character', 'a\nb'], ['non-ASCII', 'oturum-ş'], ['a number', 7]])('sid that is %s is no session', (_n, sid) => {
    expect(principalOf({ ...role, sid }).session_id).toBeUndefined()
  })

  it('sid at 64 visible characters is kept', () => {
    expect(principalOf({ ...role, sid: '~'.repeat(64) }).session_id).toBe('~'.repeat(64))
  })

  it('only an agent has act or a session: a person or a service token that carries them does not', () => {
    for (const kind of ['human', 'service', 'machine']) {
      const p = principalOf({ sub: 'x', kind, type: kind === 'human' ? 'human' : kind, act: role.act, sid: 'sess-1' })
      expect(p.act, kind).toBeUndefined()
      expect(p.session_id, kind).toBeUndefined()
    }
  })

  it('credentialKey differs per role agent and from the connection itself, and the session does not change it', () => {
    const software = principalOf(role)
    const platform = principalOf({ ...role, sub: 'ag_platform', actor: 'agent:platform@basri' })
    const connection = principalOf({ sub: 'ag_conn', type: 'assistant', kind: 'agent', via: 'oauth', actor: 'agent:claude-code@basri', on_behalf_of: 'user:u1', credential_id: 'g1', access: ['read'] })
    expect(new Set([credentialKey(software), credentialKey(platform), credentialKey(connection)]).size).toBe(3)
    // The same id reached through a different connection is another key.
    expect(credentialKey(principalOf({ ...role, act: { sub: 'z', actor: 'agent:other@basri' } }))).not.toBe(credentialKey(software))
    expect(credentialKey(principalOf({ ...role, sid: 'sess-2' }))).toBe(credentialKey(software))
  })

  it('credentialKey of a principal without act is unchanged (eight elements)', () => {
    const p = principalOf({ sub: 'u1', kind: 'human', via: 'token', credential_id: 't1', access: ['read'] })
    expect(JSON.parse(credentialKey(p))).toHaveLength(8)
  })
})

describe('auditOf', () => {
  it('writes act and session_id under metadata.audit for the request principal', async () => {
    const { auditOf } = await import('../hono.js')
    const vars: Record<string, unknown> = { principal: principalOf(role), client: { surface: 'mcp' }, request_id: 'req-12345678' }
    const e = auditOf({ get: (k: string) => vars[k] } as never, { org_id: 'o1' })
    expect(e.actor).toBe('agent:software@basri')
    expect(e.metadata.audit).toMatchObject({ act: 'agent:claude-code@basri', session_id: 'sess-1', credential_id: 'g1', org_id: 'o1', client: 'mcp' })
  })
})
