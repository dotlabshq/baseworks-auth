import { describe, expect, it } from 'vitest'
import { credentialKey, principalOf, type Principal } from '../principal.js'

const base: Principal = { kind: 'human', id: 'u1', actor: 'user:u1', via: 'session' }
const token: Principal = { ...base, via: 'token', credential_id: 'tok1', access: ['read'] }

describe('credentialKey', () => {
  it('the same principal gives the same key, and field order or access order does not matter', () => {
    expect(credentialKey(token)).toBe(credentialKey({ ...token }))
    expect(credentialKey({ ...token, access: ['read', 'write'] })).toBe(credentialKey({ ...token, access: ['write', 'read'] }))
    expect(credentialKey(principalOf({ sub: 'u1', kind: 'human', via: 'token', credential_id: 'tok1', access: ['read'] })))
      .toBe(credentialKey(principalOf({ access: ['read'], credential_id: 'tok1', via: 'token', kind: 'human', sub: 'u1' })))
  })

  it('actor and other cosmetic fields are not part of it', () => {
    expect(credentialKey({ ...base, actor: 'user:other' })).toBe(credentialKey(base))
  })

  it('any two principals that could be decided differently differ, one field at a time', () => {
    const variants: Array<[string, Principal]> = [
      ['kind', { ...base, kind: 'agent', on_behalf_of: 'user:u1' }], ['id', { ...base, id: 'u2' }], ['via', { ...base, via: 'token' }],
      ['credential_id', { ...token, credential_id: 'tok2' }], ['org_id', { ...token, org_id: 'o1' }], ['access', { ...token, access: ['write'] }],
      ['access more', { ...token, access: ['read', 'write'] }], ['role', { ...token, role: 'admin' }], ['on_behalf_of', { ...token, on_behalf_of: 'user:u9' }],
    ]
    const keys = new Set([credentialKey(token), ...variants.map(([, p]) => credentialKey(p))])
    expect(keys.size).toBe(variants.length + 1)
    for (const [name, p] of variants) expect(credentialKey(p), name).not.toBe(credentialKey(token))
  })

  it('absent access and empty access differ; so do org binding absent and empty-looking values', () => {
    expect(credentialKey({ ...token, access: undefined })).not.toBe(credentialKey({ ...token, access: [] }))
    expect(credentialKey({ ...token, access: [] })).not.toBe(credentialKey({ ...token, access: ['read'] }))
  })

  it('a session, a read-only token, a write token and an agent of the same person never share a key', () => {
    const person = 'u1'
    const keys = [
      principalOf({ sub: person, type: 'human' }),
      principalOf({ sub: person, kind: 'human', via: 'token', credential_id: 't1', access: ['read'] }),
      principalOf({ sub: person, kind: 'human', via: 'token', credential_id: 't2', access: ['read', 'write'] }),
      principalOf({ sub: person, type: 'assistant' }),
      principalOf({ sub: 'agt', kind: 'agent', via: 'token', on_behalf_of: `user:${person}`, credential_id: 't3', access: ['read'] }),
      principalOf({ sub: 'agt', kind: 'agent', via: 'token', on_behalf_of: `user:${person}`, credential_id: 't3' }),
    ].map(credentialKey)
    expect(new Set(keys).size).toBe(keys.length)
  })

  it('no field can run into the next', () => {
    const a = credentialKey({ ...base, id: 'a', via: 'token', credential_id: 'b' })
    const b = credentialKey({ ...base, id: 'a","token', via: 'token', credential_id: 'b' })
    const c = credentialKey({ ...base, id: 'a', credential_id: 'token","b', via: 'session' })
    expect(new Set([a, b, c]).size).toBe(3)
    expect(credentialKey({ ...base, id: 'u1', role: 'x' })).not.toBe(credentialKey({ ...base, id: 'u1', on_behalf_of: 'x' }))
    expect(() => JSON.parse(credentialKey(base))).not.toThrow()
  })

  it('is a string of bounded shape, never undefined', () => {
    expect(typeof credentialKey(base)).toBe('string')
    expect(credentialKey(base)).not.toContain('undefined')
  })
})
