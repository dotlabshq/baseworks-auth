/**
 * Every branch of `principal.ts` and the `requireAuth` changes in `hono.ts`
 * (workspace ADR 0004). This module decides who every request is, so the
 * behaviour is pinned down here, including the parts that are doubtful: tests
 * marked FINDING assert what the code does today and say why it matters.
 */
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { Hono } from 'hono'
import { exportPKCS8, generateKeyPair } from 'jose'
import { jwks, loadSigningKey, mint } from '../identity.js'
import { signHs256Jwt } from '../jwt.js'
import { auditOf, requireAuth, resetAuthVerifier } from '../hono.js'
import {
  actorFor, auditEnvelope, clientOf, emitAs, isSession, mayRead, mayWrite, personOf, principalOf,
  type Principal, type PrincipalKind, type Via,
} from '../principal.js'

// ─── principalOf: the kind ───────────────────────────────────────────────────

describe('principalOf: kind', () => {
  it.each([
    ['human', 'human'], ['agent', 'agent'], ['machine', 'machine'], ['service', 'service'],
  ] as const)('kind %s is read as %s', (kind, expected) => {
    expect(principalOf({ sub: 's1', kind }).kind).toBe(expected)
  })

  it.each([
    [{ type: 'human' }, 'human'],
    [{ type: 'service' }, 'service'],
    [{ type: 'assistant' }, 'agent'],
    [{ type: 'user' }, 'human'],
    [{}, 'human'],
    [{ type: '' }, 'human'],
    [{ type: 42 }, 'human'],
    [{ type: null }, 'human'],
    [{ type: ['service'] }, 'human'],
    [{ type: 'SERVICE' }, 'human'],
    [{ type: 'machine' }, 'human'], // `machine` is not an old type; only `kind` can say it
    [{ type: 'agent' }, 'human'],   // nor is `agent`: only `assistant` was
  ] as const)('old type %j is read as %s', (claims, expected) => {
    expect(principalOf({ sub: 's1', ...claims }).kind).toBe(expected)
  })

  it('kind beats type, in every direction', () => {
    expect(principalOf({ sub: 's1', kind: 'human', type: 'service' }).kind).toBe('human')
    expect(principalOf({ sub: 's1', kind: 'service', type: 'human' }).kind).toBe('service')
    expect(principalOf({ sub: 's1', kind: 'machine', type: 'assistant' }).kind).toBe('machine')
    expect(principalOf({ sub: 's1', kind: 'agent', type: 'service' }).kind).toBe('agent')
  })

  it.each(['root', 'Human', 'HUMAN', '', 7, null, ['human'], { kind: 'human' }, true])(
    'an unknown kind %j falls back to type',
    (kind) => {
      expect(principalOf({ sub: 's1', kind, type: 'service' }).kind).toBe('service')
      expect(principalOf({ sub: 's1', kind, type: 'assistant' }).kind).toBe('agent')
      expect(principalOf({ sub: 's1', kind, type: 'human' }).kind).toBe('human')
      expect(principalOf({ sub: 's1', kind }).kind).toBe('human')
    },
  )

  it('sub missing is an empty id, not a crash', () => {
    const p = principalOf({ kind: 'human' })
    expect(p.id).toBe('')
    expect(p.actor).toBe('user:')
  })

  it.each([
    [undefined, ''], [null, ''], [12, '12'], [0, '0'], [true, ''], [false, ''], ['', ''],
  ])('sub %j becomes id %j', (sub, id) => {
    expect(principalOf({ sub, kind: 'human' }).id).toBe(id)
  })

  it('a sub that is not a string or a number reads as empty', () => {
    expect(principalOf({ sub: { a: 1 }, kind: 'human' }).id).toBe('')
    expect(principalOf({ sub: ['a', 'b'], kind: 'human' }).id).toBe('')
  })

  it('principalOf never throws, whatever sub is (an object with a non-callable toString included)', () => {
    for (const sub of [{ toString: 'no' }, { toString: 1, valueOf: 2 }, Object.create(null), [Object.create(null)], Symbol.iterator, 10n]) {
      for (const kind of ['human', 'agent', 'machine', 'service']) {
        expect(() => principalOf({ sub, kind }), kind).not.toThrow()
        expect(principalOf({ sub, kind }).id).toBe('')
      }
    }
  })

  it('the principal never carries keys with undefined values', () => {
    for (const claims of [
      { sub: 'u', kind: 'human' }, { sub: 'k', kind: 'machine' }, { sub: 'a', kind: 'agent' },
      { sub: 's', kind: 'service' }, { sub: 'u', type: 'assistant' },
    ]) {
      for (const v of Object.values(principalOf(claims))) expect(v).not.toBeUndefined()
    }
  })
})

// ─── principalOf: via ────────────────────────────────────────────────────────

describe('principalOf: via', () => {
  const VIAS = ['session', 'token', 'key', 'oauth', 'client'] as const

  it.each(VIAS)('human with via %s', (via) => {
    const expected = via === 'token' || via === 'oauth' ? via : 'session'
    expect(principalOf({ sub: 'u', kind: 'human', via }).via).toBe(expected)
  })

  it.each(VIAS)('agent with via %s', (via) => {
    expect(principalOf({ sub: 'a', kind: 'agent', via }).via).toBe(via === 'oauth' ? 'oauth' : 'token')
  })

  it.each(VIAS)('machine with via %s is always key', (via) => {
    expect(principalOf({ sub: 'k', kind: 'machine', via }).via).toBe('key')
  })

  it.each(VIAS)('service with via %s is always client', (via) => {
    expect(principalOf({ sub: 's', kind: 'service', via }).via).toBe('client')
  })

  it('a human via key or client is a session only if nothing else marks it, and key/client are ignored', () => {
    expect(principalOf({ sub: 'u', kind: 'human', via: 'key' }).via).toBe('session')
    expect(principalOf({ sub: 'u', kind: 'human', via: 'client' }).via).toBe('session')
    // …but a credential id still wins over an ignored via.
    expect(principalOf({ sub: 'u', kind: 'human', via: 'key', credential_id: 'c' }).via).toBe('token')
  })

  it('a human who says session and has a credential id is a token (the marker wins)', () => {
    expect(principalOf({ sub: 'u', kind: 'human', via: 'session', credential_id: 'c' }).via).toBe('token')
  })

  it('credential_id alone makes a person a token', () => {
    expect(principalOf({ sub: 'u', type: 'human', credential_id: 'tok' }).via).toBe('token')
    expect(principalOf({ sub: 'u', credential_id: 'tok' }).via).toBe('token')
  })

  it('an empty or non-string credential_id makes no marker', () => {
    expect(principalOf({ sub: 'u', kind: 'human', credential_id: '' }).via).toBe('session')
    expect(principalOf({ sub: 'u', kind: 'human', credential_id: 5 }).via).toBe('session')
  })

  it.each(['SESSION', '', 3, null, ['token'], 'bearer'])('unreadable via %j: a person is a session', (via) => {
    expect(principalOf({ sub: 'u', kind: 'human', via }).via).toBe('session')
  })

  it('an agent that is not oauth is a token, also with no via', () => {
    expect(principalOf({ sub: 'a', kind: 'agent' }).via).toBe('token')
    expect(principalOf({ sub: 'u', type: 'assistant' }).via).toBe('token')
    expect(principalOf({ sub: 'u', type: 'assistant', via: 'oauth' }).via).toBe('oauth')
  })
})

// ─── principalOf: the actor claim ────────────────────────────────────────────

describe('principalOf: actor claim', () => {
  it('is believed with the prefix of the kind', () => {
    expect(principalOf({ sub: 'a1', kind: 'agent', actor: 'agent:dev@basri' }).actor).toBe('agent:dev@basri')
    expect(principalOf({ sub: 'k1', kind: 'machine', actor: 'machine:ci@acme' }).actor).toBe('machine:ci@acme')
    expect(principalOf({ sub: 'billing', kind: 'service', actor: 'service:billing' }).actor).toBe('service:billing')
  })

  it('is never read for a human: the actor is user:<sub>', () => {
    expect(principalOf({ sub: 'u1', kind: 'human', actor: 'user:u1' }).actor).toBe('user:u1')
    expect(principalOf({ sub: 'u1', kind: 'human', actor: 'user:other' }).actor).toBe('user:u1')
    expect(principalOf({ sub: 'u1', kind: 'human', actor: 'agent:dev@basri' }).actor).toBe('user:u1')
  })

  it.each([
    ['agent', 'service:billing', 'agent:a1@unknown'],
    ['agent', 'machine:ci@acme', 'agent:a1@unknown'],
    ['agent', 'user:u1', 'agent:a1@unknown'],
    ['machine', 'agent:dev@basri', 'machine:k1@unknown'],
    ['machine', 'user:u1', 'machine:k1@unknown'],
    ['service', 'machine:ci@acme', 'service:k1'],
    ['service', 'user:u1', 'service:k1'],
    ['service', 'agent:dev@x', 'service:k1'],
  ] as const)('a %s token with actor %j gets the derived actor', (kind, actor, expected) => {
    expect(principalOf({ sub: kind === 'agent' ? 'a1' : 'k1', kind, actor, on_behalf_of: undefined }).actor).toBe(expected)
  })

  it.each([
    ['', 'empty'], [null, 'null'], [undefined, 'undefined'], [5, 'number'], [{}, 'object'], [['agent:x@y'], 'array'],
  ])('a non-usable actor claim (%j, %s) is ignored', (actor, _label) => {
    expect(principalOf({ sub: 'a1', kind: 'agent', actor }).actor).toBe('agent:a1@unknown')
    expect(principalOf({ sub: 'k1', kind: 'machine', actor, org_id: 'o1' }).actor).toBe('machine:k1@o1')
    expect(principalOf({ sub: 'svc', kind: 'service', actor }).actor).toBe('service:svc')
  })

  it('the prefix alone is not an actor: it is rebuilt', () => {
    expect(principalOf({ sub: 'a1', kind: 'agent', actor: 'agent:' }).actor).toBe('agent:a1@unknown')
    expect(principalOf({ sub: 'a1', kind: 'agent', actor: 'agent:@basri' }).actor).toBe('agent:a1@unknown')
    expect(principalOf({ sub: 'a1', kind: 'agent', actor: 'agent:dev@' }).actor).toBe('agent:a1@unknown')
  })

  it('the prefix is case sensitive and must be at the start', () => {
    expect(principalOf({ sub: 'a1', kind: 'agent', actor: 'Agent:dev@basri', on_behalf_of: 'user:u1' }).actor).toBe('agent:a1@u1')
    expect(principalOf({ sub: 'a1', kind: 'agent', actor: ' agent:dev@basri', on_behalf_of: 'user:u1' }).actor).toBe('agent:a1@u1')
    expect(principalOf({ sub: 'a1', kind: 'agent', actor: 'x agent:dev@basri', on_behalf_of: 'user:u1' }).actor).toBe('agent:a1@u1')
  })

  it.each([
    'agent:x@y service:z', 'agent:x@y\nuser:root', 'agent:x y@z', 'agent:x@y@z', 'agent:x@y/z', 'agent:x:y@z', 'agent:ü@z', 'agent:x@y ', 'agent: x@y',
  ])('an agent actor claim that is not exactly one actor (%j) is rebuilt', (actor) => {
    expect(principalOf({ sub: 'a1', kind: 'agent', actor, on_behalf_of: 'user:u1' }).actor).toBe('agent:a1@u1')
  })
  it('the same for machine and service claims', () => {
    expect(principalOf({ sub: 'k1', kind: 'machine', org_id: 'o1', actor: 'machine:ci@acme user:root' }).actor).toBe('machine:k1@o1')
    expect(principalOf({ sub: 'billing', kind: 'service', actor: 'service:billing\nuser:root' }).actor).toBe('service:billing')
    expect(principalOf({ sub: 'billing', kind: 'service', actor: 'service:a@b' }).actor).toBe('service:a@b')
  })

  it('a human or service `sub` goes into the actor sanitised; the id keeps the raw string', () => {
    const h = principalOf({ sub: 'u1 agent:x@y', kind: 'human' })
    expect(h.actor).toBe('user:u1_agent_x_y')
    expect(h.id).toBe('u1 agent:x@y')
    const sv = principalOf({ sub: 'billing user:root', kind: 'service' })
    expect(sv.actor).toBe('service:billing_user_root')
    expect(sv.id).toBe('billing user:root')
    expect(actorFor('human', 'a b')).toBe('user:a_b')
    expect(actorFor('service', 'a b')).toBe('service:a_b')
    expect(principalOf({ sub: '01a191d6-ab.c_d', kind: 'human' }).actor).toBe('user:01a191d6-ab.c_d')
  })

  it('a derived agent or machine actor is sanitised even when sub is hostile', () => {
    expect(principalOf({ sub: 'x y@z', kind: 'agent', on_behalf_of: 'user:ow' }).actor).toBe('agent:x_y_z@ow')
    expect(principalOf({ sub: 'k y', kind: 'machine', org_id: 'o 1' }).actor).toBe('machine:k_y@o_1')
  })
})

// ─── principalOf: on_behalf_of and the legacy assistant ──────────────────────

describe('principalOf: on_behalf_of', () => {
  it('an agent takes it from the claim', () => {
    const p = principalOf({ sub: 'agt', kind: 'agent', on_behalf_of: 'user:u9' })
    expect(p.on_behalf_of).toBe('user:u9')
    expect(personOf(p)).toBe('u9')
  })

  it('a legacy assistant defaults to user:<sub>', () => {
    const p = principalOf({ sub: 'u1', type: 'assistant' })
    expect(p.on_behalf_of).toBe('user:u1')
    expect(p.actor).toBe('agent:assistant@u1')
    expect(p.id).toBe('u1')
  })

  it('a legacy assistant with an on_behalf_of claim keeps the claim', () => {
    const p = principalOf({ sub: 'u1', type: 'assistant', on_behalf_of: 'user:u2' })
    expect(p.on_behalf_of).toBe('user:u2')
    expect(p.actor).toBe('agent:assistant@u2')
  })

  it('an agent that says kind and nobody behind it has nobody: no on_behalf_of, no person', () => {
    const p = principalOf({ sub: 'agt', kind: 'agent' })
    expect('on_behalf_of' in p).toBe(false)
    expect(personOf(p)).toBeUndefined()
    expect(p.actor).toBe('agent:agt@unknown')
  })

  it.each(['', 3, null, 'org:o1', 'u1', 'user:', 'user:a b', 'user:a@b', 'user:u1 user:u2', 'user:u1\n', 'User:u1', ['user:u1']])(
    'an on_behalf_of that is %j leaves a kind-agent token with nobody behind it',
    (v) => {
      const p = principalOf({ sub: 'agt', kind: 'agent', on_behalf_of: v })
      expect('on_behalf_of' in p).toBe(false)
      expect(personOf(p)).toBeUndefined()
    },
  )
  it('a valid on_behalf_of is kept', () => {
    expect(principalOf({ sub: 'agt', kind: 'agent', on_behalf_of: 'user:01a1.b_c-d' }).on_behalf_of).toBe('user:01a1.b_c-d')
  })
  it('a legacy assistant with an invalid claim or an odd sub: the default only when it is a clean id', () => {
    expect(principalOf({ sub: 'u1', type: 'assistant', on_behalf_of: 'garbage' }).on_behalf_of).toBe('user:u1')
    expect('on_behalf_of' in principalOf({ sub: 'u 1', type: 'assistant' })).toBe(false)
    expect('on_behalf_of' in principalOf({ type: 'assistant' })).toBe(false)
  })

  it.each(['human', 'machine', 'service'] as const)('is never present for %s, even when the claim is', (kind) => {
    const p = principalOf({ sub: 'x', kind, on_behalf_of: 'user:u1', org_id: 'o1' })
    expect('on_behalf_of' in p).toBe(false)
  })

  it('is not present for old human, service types either', () => {
    expect('on_behalf_of' in principalOf({ sub: 'u', type: 'human', on_behalf_of: 'user:z' })).toBe(false)
    expect('on_behalf_of' in principalOf({ sub: 's', type: 'service', on_behalf_of: 'user:z' })).toBe(false)
  })
})

// ─── principalOf: org_id, access, role, credential_id ────────────────────────

describe('principalOf: org_id, access, role, credential_id', () => {
  const claims = { org_id: 'o1', access: ['read', 'write'], role: 'admin', credential_id: 'c1' }

  it('human: org_id, access, credential_id; never role', () => {
    const p = principalOf({ sub: 'u', kind: 'human', via: 'token', ...claims })
    expect(p).toMatchObject({ org_id: 'o1', access: ['read', 'write'], credential_id: 'c1' })
    expect('role' in p).toBe(false)
  })

  it('agent: org_id, access, credential_id; never role', () => {
    const p = principalOf({ sub: 'a', kind: 'agent', ...claims })
    expect(p).toMatchObject({ org_id: 'o1', access: ['read', 'write'], credential_id: 'c1' })
    expect('role' in p).toBe(false)
  })

  it('machine: all four', () => {
    expect(principalOf({ sub: 'k', kind: 'machine', ...claims })).toMatchObject({ org_id: 'o1', access: ['read', 'write'], credential_id: 'c1', role: 'admin' })
  })

  it('service: none of the narrowing', () => {
    const p = principalOf({ sub: 's', kind: 'service', ...claims })
    expect(p).toEqual({ kind: 'service', id: 's', actor: 'service:s', via: 'client' })
  })

  it('absent claims are absent keys', () => {
    for (const kind of ['human', 'agent', 'machine'] as const) {
      const p = principalOf({ sub: 'x', kind })
      expect('org_id' in p).toBe(false)
      expect('access' in p).toBe(false)
      expect('credential_id' in p).toBe(false)
      expect('role' in p).toBe(false)
    }
  })

  it.each([['', 'empty'], [5, 'number'], [null, 'null'], [{}, 'object'], [['o'], 'array']])('org_id %j (%s) is dropped', (org_id, _label) => {
    expect('org_id' in principalOf({ sub: 'u', kind: 'human', org_id })).toBe(false)
  })

  it('role must be a non-empty string', () => {
    expect('role' in principalOf({ sub: 'k', kind: 'machine', role: '' })).toBe(false)
    expect('role' in principalOf({ sub: 'k', kind: 'machine', role: 9 })).toBe(false)
    expect(principalOf({ sub: 'k', kind: 'machine', role: 'viewer' }).role).toBe('viewer')
  })

  describe('access', () => {
    const access = (v: unknown) => principalOf({ sub: 'u', kind: 'human', via: 'token', access: v }).access
    it('dedupes and keeps order of first appearance', () => {
      expect(access(['write', 'read', 'write', 'read'])).toEqual(['write', 'read'])
    })
    it('drops junk values', () => {
      expect(access(['admin', 'read', 3, null, 'READ', undefined, {}])).toEqual(['read'])
    })
    it.each([['read'], ['write'], [{ 0: 'read' }], [null], [3], [true], ['']])('a claim that is not an array (%j) is a limit to nothing', (v) => {
      expect(access(v)).toEqual([])
    })
    it('an absent claim is no limit', () => {
      expect(access(undefined)).toBeUndefined()
      expect('access' in principalOf({ sub: 'u', kind: 'human', via: 'token' })).toBe(false)
    })
    it('an empty array is a limit to nothing', () => {
      expect(access([])).toEqual([])
    })
    it('an array of only junk is a limit to nothing', () => {
      expect(access(['admin', 'root'])).toEqual([])
    })
    it('applies to agents and machines too, and never to a service', () => {
      expect(principalOf({ sub: 'a', kind: 'agent', access: [] }).access).toEqual([])
      expect(principalOf({ sub: 'k', kind: 'machine', access: 'x' }).access).toEqual([])
      expect('access' in principalOf({ sub: 's', kind: 'service', access: [] })).toBe(false)
    })
    it('a single value', () => {
      expect(access(['write'])).toEqual(['write'])
    })
  })
})

// ─── actorFor, personOf, isSession, mayWrite ─────────────────────────────────

describe('actorFor', () => {
  it('each kind', () => {
    expect(actorFor('human', 'u1')).toBe('user:u1')
    expect(actorFor('service', 'billing')).toBe('service:billing')
    expect(actorFor('agent', 'dev', 'basri')).toBe('agent:dev@basri')
    expect(actorFor('machine', 'ci', 'acme')).toBe('machine:ci@acme')
  })
  it('owner missing is unknown, for agent and machine only', () => {
    expect(actorFor('agent', 'dev')).toBe('agent:dev@unknown')
    expect(actorFor('machine', 'ci')).toBe('machine:ci@unknown')
    expect(actorFor('human', 'u1', 'ignored')).toBe('user:u1')
    expect(actorFor('service', 's', 'ignored')).toBe('service:s')
  })
  it('sanitises name and owner of an agent or machine', () => {
    expect(actorFor('agent', 'a b', 'o@p')).toBe('agent:a_b@o_p')
    expect(actorFor('machine', 'ü/ş', 'x y')).toBe('machine:___@x_y')
    expect(actorFor('machine', 'ci', '')).toBe('machine:ci@')
  })
  it('keeps dots, dashes and underscores', () => {
    expect(actorFor('agent', 'a.b-c_d', 'e.f')).toBe('agent:a.b-c_d@e.f')
  })
})

describe('personOf', () => {
  const base = { actor: 'x', via: 'session' as Via }
  it('a human is itself', () => expect(personOf({ ...base, kind: 'human', id: 'u1' })).toBe('u1'))
  it('an agent is who it works for, without the prefix', () => {
    expect(personOf({ ...base, kind: 'agent', id: 'a', on_behalf_of: 'user:u2' })).toBe('u2')
  })
  it('an agent with no on_behalf_of has no person', () => {
    expect(personOf({ ...base, kind: 'agent', id: 'a' })).toBeUndefined()
  })
  it('only the leading user: is stripped', () => {
    expect(personOf({ ...base, kind: 'agent', id: 'a', on_behalf_of: 'user:user:u2' })).toBe('user:u2')
  })
  it('a machine and a service have no person', () => {
    expect(personOf({ ...base, kind: 'machine', id: 'k' })).toBeUndefined()
    expect(personOf({ ...base, kind: 'service', id: 's' })).toBeUndefined()
  })
})

describe('isSession and mayWrite', () => {
  const KINDS: PrincipalKind[] = ['human', 'agent', 'machine', 'service']
  const VIAS: Via[] = ['session', 'token', 'key', 'oauth', 'client']

  it('isSession is true for exactly one kind × via pair', () => {
    const trues: string[] = []
    for (const kind of KINDS) for (const via of VIAS) {
      const p: Principal = { kind, id: 'x', actor: 'x', via }
      if (isSession(p)) trues.push(`${kind}/${via}`)
    }
    expect(trues).toEqual(['human/session'])
  })

  it('mayWrite: no access means no limit, read does not write, write does', () => {
    const p = (access?: Array<'read' | 'write'>): Principal => ({ kind: 'human', id: 'u', actor: 'user:u', via: 'token', ...(access ? { access } : {}) })
    expect(mayWrite(p())).toBe(true)
    expect(mayWrite(p(['read']))).toBe(false)
    expect(mayWrite(p(['write']))).toBe(true)
    expect(mayWrite(p(['read', 'write']))).toBe(true)
  })

  it('fails closed: an unusable access claim is neither readable nor writable; only an absent one is unlimited', () => {
    const p = (access?: unknown) => principalOf({ sub: 'u', kind: 'human', via: 'token', ...(access === undefined ? {} : { access }) })
    for (const bad of [['admin'], [], 'write', null, 0]) {
      expect(mayWrite(p(bad)), JSON.stringify(bad)).toBe(false)
      expect(mayRead(p(bad)), JSON.stringify(bad)).toBe(false)
    }
    expect(mayWrite(p())).toBe(true)
    expect(mayRead(p())).toBe(true)
    expect(mayWrite(p(['read']))).toBe(false)
    expect(mayRead(p(['read']))).toBe(true)
    expect(mayRead(p(['write']))).toBe(false)
    expect(mayWrite(p(['write']))).toBe(true)
    expect(mayRead(p(['read', 'write']))).toBe(true)
  })
})

// ─── clientOf ────────────────────────────────────────────────────────────────

describe('clientOf', () => {
  it.each([
    ['ui', { surface: 'ui' }],
    ['cli', { surface: 'cli' }],
    ['mcp', { surface: 'mcp' }],
    ['api', { surface: 'api' }],
    ['cli/bw', { surface: 'cli', app: 'bw' }],
    ['mcp/claude', { surface: 'mcp', app: 'claude' }],
    ['ui/doubletap', { surface: 'ui', app: 'doubletap' }],
    ['api/curl', { surface: 'api', app: 'curl' }],
    ['  cli/bw  ', { surface: 'cli', app: 'bw' }],
    [undefined, { surface: 'api' }],
    ['', { surface: 'api' }],
    ['   ', { surface: 'api' }],
    ['/', { surface: 'api' }],
    ['/x', { surface: 'api', app: 'x' }],
    ['cli/', { surface: 'cli' }],
    ['robot', { surface: 'api' }],
    ['robot/x', { surface: 'api', app: 'x' }],
    ['CLI/bw', { surface: 'api', app: 'bw' }],
  ] as const)('%j', (header, expected) => {
    expect(clientOf(header)).toEqual(expected)
  })

  it('many slashes: only the second part is the app, the rest is dropped', () => {
    expect(clientOf('cli/a/b/c')).toEqual({ surface: 'cli', app: 'a' })
    expect(clientOf('///')).toEqual({ surface: 'api' })
  })

  it('sanitises the app', () => {
    expect(clientOf('cli/a b')).toEqual({ surface: 'cli', app: 'a_b' })
    expect(clientOf('cli/<script>alert(1)</script>').app).toBe('_script_alert_1__')
    expect(clientOf('cli/a;b\nc')).toEqual({ surface: 'cli', app: 'a_b_c' })
  })

  it('unicode becomes underscores, one per UTF-16 unit', () => {
    expect(clientOf('cli/şç').app).toBe('__')
    expect(clientOf('cli/日本').app).toBe('__')
    // An emoji is two UTF-16 units: two underscores.
    expect(clientOf('cli/😀').app).toBe('__')
  })

  it('an app of only unsafe characters is still an app (underscores)', () => {
    expect(clientOf('cli/!!!')).toEqual({ surface: 'cli', app: '___' })
  })

  it('caps the app at 60 characters', () => {
    expect(clientOf(`cli/${'a'.repeat(60)}`).app).toHaveLength(60)
    expect(clientOf(`cli/${'a'.repeat(61)}`).app).toHaveLength(60)
    expect(clientOf(`cli/${'a'.repeat(5000)}`).app).toHaveLength(60)
  })

  it('whitespace inside the header is not trimmed away', () => {
    expect(clientOf('cli /bw')).toEqual({ surface: 'api', app: 'bw' })
  })
})

// ─── auditEnvelope and emitAs ────────────────────────────────────────────────

describe('auditEnvelope and emitAs', () => {
  const minimal: Principal = { kind: 'human', id: 'u1', actor: 'user:u1', via: 'session' }
  const full: Principal = {
    kind: 'agent', id: 'agt', actor: 'agent:dev@basri', via: 'oauth', on_behalf_of: 'user:u1',
    org_id: 'pcred', credential_id: 'cred_1', access: ['read'],
  }

  const noUndefined = (o: object) => {
    for (const [k, v] of Object.entries(o)) {
      expect(v, `key ${k}`).not.toBeUndefined()
      if (v && typeof v === 'object') noUndefined(v)
    }
  }

  it('minimal principal, no context: only the five always-present fields', () => {
    expect(auditEnvelope(minimal)).toEqual({ kind: 'human', actor: 'user:u1', actor_id: 'u1', via: 'session' })
    expect(Object.keys(auditEnvelope(minimal))).toEqual(['kind', 'actor', 'actor_id', 'via'])
  })

  it('every optional field present', () => {
    expect(auditEnvelope(full, { org_id: 'o2', request_id: 'req-12345678', client: { surface: 'mcp', app: 'claude' } })).toEqual({
      kind: 'agent', actor: 'agent:dev@basri', actor_id: 'agt', via: 'oauth',
      on_behalf_of: 'user:u1', credential_id: 'cred_1', client: 'mcp/claude', org_id: 'o2', request_id: 'req-12345678',
    })
  })

  it('each optional field alone', () => {
    expect(auditEnvelope(minimal, { request_id: 'r' })).toEqual({ ...auditEnvelope(minimal), request_id: 'r' })
    expect(auditEnvelope(minimal, { org_id: 'o' })).toEqual({ ...auditEnvelope(minimal), org_id: 'o' })
    expect(auditEnvelope(minimal, { client: { surface: 'ui' } })).toEqual({ ...auditEnvelope(minimal), client: 'ui' })
    expect(auditEnvelope(minimal, { client: { surface: 'cli', app: 'bw' } }).client).toBe('cli/bw')
    expect(auditEnvelope({ ...minimal, credential_id: 'c' }).credential_id).toBe('c')
    expect(auditEnvelope({ ...minimal, kind: 'agent', on_behalf_of: 'user:z' }).on_behalf_of).toBe('user:z')
  })

  it('does not copy access, role or org-less fields into the envelope', () => {
    const e = auditEnvelope({ ...full, role: 'admin' })
    expect('access' in e).toBe(false)
    expect('role' in e).toBe(false)
  })

  it('an empty request id is absent; an empty org id falls back to the credential\'s org', () => {
    expect('request_id' in auditEnvelope(minimal, { request_id: '' })).toBe(false)
    expect(auditEnvelope(full, { org_id: '' }).org_id).toBe('pcred')
    expect('org_id' in auditEnvelope(minimal, { org_id: '' })).toBe(false)
  })

  it('org fallback order: context, then credential, then none', () => {
    expect(auditEnvelope(full, { org_id: 'ctx' }).org_id).toBe('ctx')
    expect(auditEnvelope(full).org_id).toBe('pcred')
    expect(auditEnvelope(full, {}).org_id).toBe('pcred')
    expect('org_id' in auditEnvelope(minimal)).toBe(false)
  })

  it('no undefined values anywhere, for a range of inputs', () => {
    const ps = [minimal, full, { ...minimal, kind: 'service' as const, via: 'client' as const }]
    const ctxs = [undefined, {}, { org_id: undefined }, { client: undefined, request_id: undefined }, { client: { surface: 'api' as const } }]
    for (const p of ps) for (const ctx of ctxs) {
      noUndefined(auditEnvelope(p, ctx))
      noUndefined(emitAs(p, ctx))
    }
  })

  it('emitAs: actor, metadata.audit, correlationId only with a request id', () => {
    const a = emitAs(full)
    expect(a).toEqual({ actor: 'agent:dev@basri', metadata: { audit: auditEnvelope(full) } })
    expect('correlationId' in a).toBe(false)
    const b = emitAs(full, { request_id: 'req-12345678', org_id: 'o' })
    expect(b.correlationId).toBe('req-12345678')
    expect(b.metadata.audit.request_id).toBe('req-12345678')
    expect(b.actor).toBe(full.actor)
  })

  it('actor_id is the id and not the actor', () => {
    expect(auditEnvelope(full).actor_id).toBe('agt')
  })

  it('all values are strings', () => {
    for (const v of Object.values(auditEnvelope(full, { org_id: 'o', request_id: 'r', client: { surface: 'cli', app: 'x' } }))) {
      expect(typeof v).toBe('string')
    }
  })
})

// ─── requireAuth ─────────────────────────────────────────────────────────────

const SECRET = 'test-secret-32-chars-long-enough!'
const ENV_KEYS = ['JWT_SECRET', 'AUTH_JWKS_URI', 'AUTH_ISSUER', 'AUTH_AUDIENCE'] as const
const savedEnv: Record<string, string | undefined> = {}

function useEnv(env: Partial<Record<(typeof ENV_KEYS)[number], string>>) {
  for (const k of ENV_KEYS) delete process.env[k]
  for (const [k, v] of Object.entries(env)) process.env[k] = v
  resetAuthVerifier()
}

function makeApp() {
  const a = new Hono()
  a.use('*', requireAuth)
  a.get('/who', (c) => c.json({
    auth: c.get('auth'),
    principal: c.get('principal'),
    sameObject: c.get('auth').principal === c.get('principal'),
    requestId: c.get('requestId'),
    client: c.get('client'),
    audit: auditOf(c, { org_id: 'o1' }),
  }))
  return a
}

type Who = {
  auth: { userId: string; orgId?: string; role?: string; email?: string; tokenType: string; principal: Record<string, unknown> }
  principal: Record<string, unknown>
  sameObject: boolean
  requestId: string
  client: { surface: string; app?: string }
  audit: { actor: string; correlationId?: string; metadata: { audit: Record<string, string> } }
}

async function get(token: string | null, headers: Record<string, string> = {}, scheme = 'Bearer') {
  const h: Record<string, string> = { ...headers }
  if (token !== null) h['Authorization'] = `${scheme} ${token}`
  return makeApp().fetch(new Request('http://x/who', { headers: h }))
}

beforeAll(() => { for (const k of ENV_KEYS) savedEnv[k] = process.env[k] })
afterAll(() => {
  for (const k of ENV_KEYS) { if (savedEnv[k] === undefined) delete process.env[k]; else process.env[k] = savedEnv[k] }
  resetAuthVerifier()
})

describe('requireAuth with HS256 (JWT_SECRET)', () => {
  const who = async (claims: Record<string, unknown>, headers: Record<string, string> = {}) => {
    useEnv({ JWT_SECRET: SECRET })
    const r = await get(signHs256Jwt(claims, SECRET, 60), headers)
    expect(r.status).toBe(200)
    return (await r.json()) as Who
  }

  it('sets auth, principal, requestId and client', async () => {
    const w = await who({ sub: 'u1', type: 'human', email: 'a@b.c', org_id: 'o9', role: 'admin' }, { 'X-Baseworks-Client': 'cli/bw' })
    expect(w.auth).toMatchObject({ userId: 'u1', orgId: 'o9', role: 'admin', email: 'a@b.c', tokenType: 'user' })
    expect(w.principal).toMatchObject({ kind: 'human', id: 'u1', actor: 'user:u1', via: 'session', org_id: 'o9' })
    expect(w.sameObject).toBe(true)
    expect(w.requestId).toMatch(/^[0-9a-f-]{36}$/)
    expect(w.client).toEqual({ surface: 'cli', app: 'bw' })
  })

  it('client defaults to api', async () => {
    expect((await who({ sub: 'u1', type: 'human' })).client).toEqual({ surface: 'api' })
  })

  it.each([
    [{ sub: 'u1', type: 'human' }, 'user', 'human'],
    [{ sub: 'u1', type: 'human', kind: 'human', via: 'token', credential_id: 'c' }, 'user', 'human'],
    [{ sub: 'u1', type: 'user' }, 'user', 'human'],
    [{ sub: 'billing', type: 'service' }, 'service', 'service'],
    [{ sub: 'billing', kind: 'service', type: 'service' }, 'service', 'service'],
    [{ sub: 'u1', type: 'assistant' }, 'assistant', 'agent'],
    [{ sub: 'a1', type: 'assistant', kind: 'agent', on_behalf_of: 'user:u1' }, 'assistant', 'agent'],
    [{ sub: 'k1', type: 'service', kind: 'machine', org_id: 'o1' }, 'machine', 'machine'],
    [{ sub: 'k1', type: 'service', kind: 'machine', org_id: 'o1' }, 'machine', 'machine'],
    [{ sub: 'u1', type: 'service', kind: 'human' }, 'user', 'human'],
  ])('tokenType for %j is %s (kind %s)', async (claims, tokenType, kind) => {
    const w = await who(claims)
    expect(w.auth.tokenType).toBe(tokenType)
    expect(w.principal['kind']).toBe(kind)
  })

  it('only a service-kind token gets tokenType service', async () => {
    for (const claims of [
      { sub: 'x', type: 'human' }, { sub: 'x', type: 'assistant' }, { sub: 'x', type: 'human', kind: 'agent' }, { sub: 'x', type: 'human', kind: 'machine' }, { sub: 'x', type: 'banana' },
    ]) {
      expect((await who(claims)).auth.tokenType).not.toBe('service')
    }
  })

  // The verifier requires exp, sub and type: a token with `kind` alone is
  // rejected. Whoever mints tokens (iam, auth-service) must keep writing `type`.
  it('a token with no sub, or with kind but no type, is rejected by the verifier (401)', async () => {
    useEnv({ JWT_SECRET: SECRET })
    expect((await get(signHs256Jwt({ type: 'human' }, SECRET, 60))).status).toBe(401)
    expect((await get(signHs256Jwt({ sub: 'u1', kind: 'human' }, SECRET, 60))).status).toBe(401)
    expect((await get(signHs256Jwt({ sub: 'k1', kind: 'machine', org_id: 'o1' }, SECRET, 60))).status).toBe(401)
  })

  it('a request id is kept only when it matches', async () => {
    const ok = ['abcdefgh', 'req-abcdef12', 'A.b_c-d.e', 'a'.repeat(128), '12345678']
    for (const id of ok) expect((await who({ sub: 'u1', type: 'human' }, { 'X-Request-Id': id })).requestId).toBe(id)
    const bad = ['short', '1234567', 'a'.repeat(129), 'has space1', 'semi;colon1', 'newéline1', 'ünicode123', 'a/b/c/d/e/f']
    for (const id of bad) {
      let r: Who | undefined
      try { r = await who({ sub: 'u1', type: 'human' }, { 'X-Request-Id': id }) } catch { continue } // the runtime may refuse the header itself
      expect(r.requestId).not.toBe(id)
      expect(r.requestId).toMatch(/^[0-9a-f-]{36}$/)
    }
  })

  it('a new request id is minted per request when none is sent', async () => {
    const a = (await who({ sub: 'u1', type: 'human' })).requestId
    const b = (await who({ sub: 'u1', type: 'human' })).requestId
    expect(a).not.toBe(b)
  })

  it('auditOf: correlationId and envelope from the request', async () => {
    const w = await who({ sub: 'a1', type: 'assistant', kind: 'agent', actor: 'agent:dev@basri', on_behalf_of: 'user:u1', credential_id: 'c9' }, { 'X-Request-Id': 'req-abcdef12', 'X-Baseworks-Client': 'mcp/claude' })
    expect(w.audit).toEqual({
      actor: 'agent:dev@basri',
      correlationId: 'req-abcdef12',
      metadata: { audit: { kind: 'agent', actor: 'agent:dev@basri', actor_id: 'a1', via: 'token', on_behalf_of: 'user:u1', credential_id: 'c9', client: 'mcp/claude', org_id: 'o1', request_id: 'req-abcdef12' } },
    })
  })

  it('401 without a header, with another scheme, with an empty bearer, with junk', async () => {
    useEnv({ JWT_SECRET: SECRET })
    expect((await get(null)).status).toBe(401)
    expect((await get(signHs256Jwt({ sub: 'u' }, SECRET), {}, 'Basic')).status).toBe(401)
    expect((await get(signHs256Jwt({ sub: 'u' }, SECRET), {}, 'bearer')).status).toBe(401) // case sensitive
    expect((await get('')).status).toBe(401)
    expect((await get('not-a-jwt')).status).toBe(401)
    expect((await get('a.b.c')).status).toBe(401)
    const body = await (await get(null)).json()
    expect(body).toEqual({ error: 'Unauthorized' })
  })

  it('401 for an expired token', async () => {
    useEnv({ JWT_SECRET: SECRET })
    expect((await get(signHs256Jwt({ sub: 'u1', type: 'human' }, SECRET, -10))).status).toBe(401)
    expect((await get(signHs256Jwt({ sub: 'u1', type: 'human' }, SECRET, 60))).status).toBe(200)
  })

  it('401 for a wrong signature', async () => {
    useEnv({ JWT_SECRET: SECRET })
    expect((await get(signHs256Jwt({ sub: 'u1', type: 'human' }, 'another-secret-that-is-long-enough!!', 60))).status).toBe(401)
    const t = signHs256Jwt({ sub: 'u1', type: 'human' }, SECRET, 60)
    expect((await get(t.slice(0, -2) + (t.endsWith('AA') ? 'BB' : 'AA'))).status).toBe(401)
  })

  it('401 for a tampered payload (kind swapped to service, signature kept)', async () => {
    useEnv({ JWT_SECRET: SECRET })
    const [h, p, s] = signHs256Jwt({ sub: 'u1', type: 'human' }, SECRET, 60).split('.') as [string, string, string]
    const claims = JSON.parse(Buffer.from(p, 'base64url').toString()) as Record<string, unknown>
    const forged = Buffer.from(JSON.stringify({ ...claims, kind: 'service' })).toString('base64url')
    expect((await get(`${h}.${forged}.${s}`)).status).toBe(401)
  })

  it('401 for alg none', async () => {
    useEnv({ JWT_SECRET: SECRET })
    const h = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')
    const p = Buffer.from(JSON.stringify({ sub: 'u1', kind: 'service', exp: Math.floor(Date.now() / 1000) + 60 })).toString('base64url')
    expect((await get(`${h}.${p}.`)).status).toBe(401)
    expect((await get(`${h}.${p}`)).status).toBe(401)
  })

  it('does not set the principal on a rejected request (the handler is not reached)', async () => {
    useEnv({ JWT_SECRET: SECRET })
    const r = await get('nope')
    expect(r.status).toBe(401)
    expect(await r.text()).not.toContain('principal')
  })
})

describe('requireAuth with nothing configured', () => {
  afterEach(() => vi.restoreAllMocks())

  it('500 when no verifier is configured, whatever the token', async () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    useEnv({})
    const r = await get(signHs256Jwt({ sub: 'u1', type: 'human' }, SECRET, 60))
    expect(r.status).toBe(500)
    expect(await r.json()).toEqual({ error: 'auth is not configured' })
    expect(spy).toHaveBeenCalled()
  })

  it('a missing header is still 401, not 500, before anything is checked', async () => {
    useEnv({})
    expect((await get(null)).status).toBe(401)
  })

  it('the configuration error is cached until reset', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    useEnv({})
    expect((await get('x')).status).toBe(500)
    process.env['JWT_SECRET'] = SECRET // not reset: the cached error remains
    expect((await get(signHs256Jwt({ sub: 'u1', type: 'human' }, SECRET, 60))).status).toBe(500)
    resetAuthVerifier()
    expect((await get(signHs256Jwt({ sub: 'u1', type: 'human' }, SECRET, 60))).status).toBe(200)
  })
})

describe('requireAuth with ES256 (JWKS)', () => {
  const ISS = 'https://auth.example.test'
  const AUD = 'example-realm'
  let server: Server
  let jwksUri = ''
  let signing: Awaited<ReturnType<typeof loadSigningKey>>
  let stranger: Awaited<ReturnType<typeof loadSigningKey>>

  const key = async () => loadSigningKey(await exportPKCS8((await generateKeyPair('ES256', { extractable: true })).privateKey))

  beforeAll(async () => {
    signing = await key()
    stranger = await key()
    server = createServer((_req, res) => {
      res.setHeader('content-type', 'application/json')
      res.end(JSON.stringify(jwks(signing)))
    })
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
    jwksUri = `http://127.0.0.1:${(server.address() as AddressInfo).port}/jwks.json`
  })
  afterAll(() => { server.close() })

  const tok = (claims: Parameters<typeof mint>[1], o: Partial<Parameters<typeof mint>[2]> = {}, k = signing) =>
    mint(k, claims, { issuer: ISS, audience: AUD, expiresInSeconds: 60, ...o })

  const who = async (claims: Parameters<typeof mint>[1], headers: Record<string, string> = {}) => {
    useEnv({ AUTH_JWKS_URI: jwksUri, AUTH_ISSUER: ISS, AUTH_AUDIENCE: AUD })
    const r = await get(await tok(claims), headers)
    expect(r.status).toBe(200)
    return (await r.json()) as Who
  }

  it('sets auth, principal, requestId and client', async () => {
    const w = await who({ sub: 'u1', type: 'human', email: 'e@x.y' }, { 'X-Baseworks-Client': 'ui', 'X-Request-Id': 'req-12345678' })
    expect(w.auth).toMatchObject({ userId: 'u1', email: 'e@x.y', tokenType: 'user' })
    expect(w.principal).toMatchObject({ kind: 'human', via: 'session' })
    expect(w.sameObject).toBe(true)
    expect(w.requestId).toBe('req-12345678')
    expect(w.client).toEqual({ surface: 'ui' })
  })

  it.each([
    [{ sub: 'u1', type: 'human' as const }, 'user', 'human'],
    [{ sub: 'billing', type: 'service' as const }, 'service', 'service'],
    [{ sub: 'u1', type: 'assistant' as const }, 'assistant', 'agent'],
    [{ sub: 'a1', type: 'assistant' as const, kind: 'agent' as const, on_behalf_of: 'user:u1', via: 'oauth' as const }, 'assistant', 'agent'],
    [{ sub: 'k1', type: 'service' as const, kind: 'machine' as const, org_id: 'o1', role: 'member', access: ['read' as const] }, 'machine', 'machine'],
  ])('tokenType for %j is %s', async (claims, tokenType, kind) => {
    const w = await who(claims)
    expect(w.auth.tokenType).toBe(tokenType)
    expect(w.principal['kind']).toBe(kind)
  })

  it('carries the narrowing claims through the verifier', async () => {
    const w = await who({ sub: 'k1', type: 'service', kind: 'machine', org_id: 'o1', role: 'viewer', access: ['read'], credential_id: 'key1', actor: 'machine:ci@acme' })
    expect(w.principal).toEqual({ kind: 'machine', id: 'k1', actor: 'machine:ci@acme', via: 'key', role: 'viewer', org_id: 'o1', access: ['read'], credential_id: 'key1' })
  })

  it('401 for a token signed by another key', async () => {
    useEnv({ AUTH_JWKS_URI: jwksUri, AUTH_ISSUER: ISS, AUTH_AUDIENCE: AUD })
    expect((await get(await tok({ sub: 'u1', type: 'human' }, {}, stranger))).status).toBe(401)
  })

  it('401 for an expired token', async () => {
    useEnv({ AUTH_JWKS_URI: jwksUri, AUTH_ISSUER: ISS, AUTH_AUDIENCE: AUD })
    expect((await get(await tok({ sub: 'u1', type: 'human' }, { expiresInSeconds: -5 }))).status).toBe(401)
  })

  it('401 for the wrong issuer or audience', async () => {
    useEnv({ AUTH_JWKS_URI: jwksUri, AUTH_ISSUER: ISS, AUTH_AUDIENCE: AUD })
    expect((await get(await tok({ sub: 'u1', type: 'human' }, { issuer: 'https://evil.test' }))).status).toBe(401)
    expect((await get(await tok({ sub: 'u1', type: 'human' }, { audience: 'other' }))).status).toBe(401)
  })

  it('401 for a missing header', async () => {
    useEnv({ AUTH_JWKS_URI: jwksUri })
    expect((await get(null)).status).toBe(401)
  })

  it('JWKS and legacy secret together: both are accepted', async () => {
    useEnv({ AUTH_JWKS_URI: jwksUri, AUTH_ISSUER: ISS, AUTH_AUDIENCE: AUD, JWT_SECRET: SECRET })
    expect((await get(await tok({ sub: 'u1', type: 'human' }))).status).toBe(200)
    // A legacy HS256 token has no iss/aud: with an issuer configured it is
    // still accepted while the secret is set (the documented migration door).
    const legacy = await get(signHs256Jwt({ sub: 'u1', type: 'human' }, SECRET, 60))
    expect(legacy.status).toBe(200)
  })

  it('JWKS only: an HS256 token is not accepted', async () => {
    useEnv({ AUTH_JWKS_URI: jwksUri })
    expect((await get(signHs256Jwt({ sub: 'u1', type: 'human' }, SECRET, 60))).status).toBe(401)
  })
})

// ─── property-style ──────────────────────────────────────────────────────────

describe('principalOf, a few hundred random claim objects', () => {
  // A small seeded generator (mulberry32): the run is the same every time.
  function rng(seed: number) {
    let a = seed
    return () => {
      a = (a + 0x6d2b79f5) | 0
      let t = Math.imul(a ^ (a >>> 15), 1 | a)
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296
    }
  }
  const rand = rng(20261112)
  const pick = <T,>(xs: readonly T[]): T => xs[Math.floor(rand() * xs.length)] as T

  const junk: unknown[] = [undefined, null, '', ' ', 0, 1, -1, true, false, {}, [], ['read'], ['x'], 'service', 'human', 'agent', 'machine', 'user', 'assistant',
    'agent:a@b', 'user:u', 'service:s', 'machine:m@o', 'a b', 'ünï', '😀', 'x'.repeat(200), [[]], NaN, Infinity]
  const keys = ['sub', 'kind', 'type', 'via', 'actor', 'on_behalf_of', 'org_id', 'access', 'role', 'credential_id', 'email', 'extra']
  const kinds = ['human', 'agent', 'machine', 'service']
  const types = ['human', 'service', 'assistant', 'user', 'x']
  const vias = ['session', 'token', 'key', 'oauth', 'client']

  function claims(): Record<string, unknown> {
    const c: Record<string, unknown> = {}
    for (const k of keys) {
      const r = rand()
      if (r < 0.35) continue
      if (k === 'kind' && r < 0.7) c[k] = pick(kinds)
      else if (k === 'type' && r < 0.7) c[k] = pick(types)
      else if (k === 'via' && r < 0.7) c[k] = pick(vias)
      else if (k === 'access' && r < 0.7) c[k] = [pick(['read', 'write', 'admin']), pick(['read', 'write', 3])]
      else if (k === 'sub' && r < 0.8) c[k] = 'sub' + Math.floor(rand() * 5)
      else c[k] = pick(junk)
    }
    return c
  }

  it('never throws; no service without saying so; isSession only for a person with no marker', () => {
    for (let i = 0; i < 600; i++) {
      const c = claims()
      let p!: Principal
      expect(() => { p = principalOf(c) }, JSON.stringify(c)).not.toThrow()

      // Every result is well-formed.
      expect(['human', 'agent', 'machine', 'service']).toContain(p.kind)
      expect(['session', 'token', 'key', 'oauth', 'client']).toContain(p.via)
      expect(typeof p.id).toBe('string')
      expect(typeof p.actor).toBe('string')
      for (const v of Object.values(p)) expect(v).not.toBeUndefined()
      expect(() => auditEnvelope(p)).not.toThrow()
      expect(() => personOf(p)).not.toThrow()
      expect(typeof mayWrite(p)).toBe('boolean')

      // `service` only when the token said so.
      if (p.kind === 'service') expect(c['kind'] === 'service' || c['type'] === 'service', JSON.stringify(c)).toBe(true)
      // `machine` and `agent` only through `kind`, or `assistant` type for agent.
      if (p.kind === 'machine') expect(c['kind']).toBe('machine')
      if (p.kind === 'agent') expect(c['kind'] === 'agent' || c['type'] === 'assistant').toBe(true)

      // isSession: the token said human (or nothing usable) and carried no marker.
      if (isSession(p)) {
        expect(p.kind).toBe('human')
        expect(c['kind'] === 'human' || !['agent', 'machine', 'service'].includes(c['kind'] as string)).toBe(true)
        expect(c['type'] === 'assistant' && c['kind'] !== 'human').toBe(false)
        expect(c['via'] === 'token' || c['via'] === 'oauth').toBe(false)
        expect(typeof c['credential_id'] === 'string' && (c['credential_id'] as string).length > 0).toBe(false)
        expect(p.credential_id).toBeUndefined()
      }
      // The converse: any marker makes a person not-a-session.
      if (p.kind === 'human' && (c['via'] === 'token' || c['via'] === 'oauth' || (typeof c['credential_id'] === 'string' && c['credential_id'] !== ''))) {
        expect(isSession(p)).toBe(false)
      }
      // A person's actor is always user:<id>, whatever the claim said.
      if (p.kind === 'human') expect(p.actor).toBe(`user:${p.id.replace(/[^A-Za-z0-9._-]/g, '_')}`)
      // Whatever the claims were, an actor is one actor: no spaces, one prefix.
      expect(p.actor, JSON.stringify(c)).toMatch(/^(user|agent|machine|service):[A-Za-z0-9._-]*(@[A-Za-z0-9._-]+)?$/)
      // access: only an absent claim is no limit (never for a service).
      if (p.kind !== 'service') expect('access' in p).toBe(c['access'] !== undefined)
      if (p.access && p.access.length === 0) { expect(mayWrite(p)).toBe(false); expect(mayRead(p)).toBe(false) }
      // The actor always starts with the prefix of the kind.
      const prefix = { human: 'user:', agent: 'agent:', machine: 'machine:', service: 'service:' }[p.kind]
      expect(p.actor.startsWith(prefix)).toBe(true)
      // An agent always has someone it works for; no one else does.
      if (p.kind !== 'agent') expect('on_behalf_of' in p).toBe(false)
      else if (p.on_behalf_of) expect(p.on_behalf_of).toMatch(/^user:[A-Za-z0-9._-]+$/)
      else expect(personOf(p)).toBeUndefined()
      // `role` only for a machine.
      if (p.kind !== 'machine') expect('role' in p).toBe(false)
      // A service is never narrowed.
      if (p.kind === 'service') expect(Object.keys(p).sort()).toEqual(['actor', 'id', 'kind', 'via'])
    }
  })
})
