/**
 * Who is acting, said the same way in every service (workspace ADR 0004).
 *
 * A verified realm token names one of four kinds of principal:
 *
 *   human     a person with an account
 *   agent     an AI agent working for a person; never more than that person
 *   machine   an organization's own automation (an organization key)
 *   service   a service of the realm, acting as itself
 *
 * `principalOf(claims)` reads that from a token's claims, `emitAs(principal)`
 * turns it into what an event records. A service writes neither by hand, so
 * every event answers "who did it, for whom, with what" in the same fields.
 *
 * Nothing here talks to the network or trusts anything but verified claims.
 */

export type PrincipalKind = 'human' | 'agent' | 'machine' | 'service'

/**
 * How the identity was proved.
 *
 *   session   a person signed in (browser, `bw login`)
 *   token     a person's API token, or a token narrowed from a session
 *   key       an organization key
 *   oauth     a client the person consented to (MCP)
 *   client    a realm service's own credentials
 */
export type Via = 'session' | 'token' | 'key' | 'oauth' | 'client'

export type Access = 'read' | 'write'

export interface Principal {
  kind: PrincipalKind
  /** The id that does not change: user, agent, key or service. */
  id: string
  /** How a record names it: `user:<id>`, `agent:dev@basri`, `machine:ci@acme`, `service:billing`. */
  actor: string
  via: Via
  /** For an agent: `user:<id>` of the person it works for. */
  on_behalf_of?: string
  /** The organization the credential is bound to. A restriction, never a grant. */
  org_id?: string
  /** What the credential is limited to. Absent: no limit beyond what the principal may do. */
  access?: Access[]
  /** For a machine: the role its key acts with. */
  role?: string
  /** The API token or key behind this token: its id, never the secret. */
  credential_id?: string
}

const KINDS: readonly PrincipalKind[] = ['human', 'agent', 'machine', 'service']
const VIAS: readonly Via[] = ['session', 'token', 'key', 'oauth', 'client']

const text = (v: unknown): string | undefined => (typeof v === 'string' && v.length > 0 ? v : undefined)

/**
 * Only an absent claim means "no limit". A claim that is there but says
 * nothing usable (empty, junk, not an array) is a limit to nothing: `[]`.
 */
function accessOf(v: unknown): Access[] | undefined {
  if (v === undefined) return undefined
  if (!Array.isArray(v)) return []
  return [...new Set(v.filter((a): a is Access => a === 'read' || a === 'write'))]
}

/** What follows the kind in an actor string must not be able to forge another one. */
const safe = (s: string): string => s.replace(/[^A-Za-z0-9._-]/g, '_')

/** The actor string for a principal whose token did not carry one. */
export function actorFor(kind: PrincipalKind, id: string, owner?: string): string {
  switch (kind) {
    case 'human': return `user:${safe(id)}`
    case 'service': return `service:${safe(id)}`
    case 'agent': return `agent:${safe(id)}@${safe(owner ?? 'unknown')}`
    case 'machine': return `machine:${safe(id)}@${safe(owner ?? 'unknown')}`
  }
}

const ACTOR_RE = /^(agent|machine|service):[A-Za-z0-9._-]+(@[A-Za-z0-9._-]+)?$/
const BEHALF_RE = /^user:[A-Za-z0-9._-]+$/

/**
 * An actor claim is believed only if it is exactly one actor of the kind the
 * token says. Anything else is rebuilt from the token. A person's actor is
 * never read from a claim.
 */
function actorClaim(claims: Record<string, unknown>, kind: PrincipalKind): string | undefined {
  const actor = text(claims['actor'])
  return actor && kind !== 'human' && ACTOR_RE.test(actor) && actor.startsWith(`${kind}:`) ? actor : undefined
}

/**
 * Read the principal from verified claims.
 *
 * Tokens minted since ADR 0004 say `kind` and `via`. Older ones say only
 * `type`, and are read as what they were:
 *
 *   type: human      a person, signed in
 *   type: service    a service
 *   type: assistant  a token narrowed from a person's: an agent for that
 *                    person, and so never a session
 *
 * A type that is none of these is read as a person, as `requireAuth` always
 * has: the realm signed it, some issuers still write `user`, and reading it
 * as anything else would lock those people out. It is never read as a
 * service.
 */
export function principalOf(claims: Record<string, unknown>): Principal {
  // Never throws: a subject that is not a string or a number reads as empty.
  const rawSub = claims['sub']
  const sub = typeof rawSub === 'string' ? rawSub : typeof rawSub === 'number' ? String(rawSub) : ''
  const named = KINDS.find((k) => k === claims['kind'])
  const type = claims['type']
  const kind: PrincipalKind =
    named ?? (type === 'service' ? 'service' : type === 'assistant' ? 'agent' : 'human')

  const givenVia = VIAS.find((v) => v === claims['via'])
  const org_id = text(claims['org_id'])
  const access = accessOf(claims['access'])
  const credential_id = text(claims['credential_id'])
  const narrowing = {
    ...(org_id ? { org_id } : {}),
    ...(access ? { access } : {}),
    ...(credential_id ? { credential_id } : {}),
  }

  if (kind === 'service') {
    return { kind, id: sub, actor: actorClaim(claims, kind) ?? actorFor(kind, sub), via: 'client' }
  }
  if (kind === 'human') {
    // A person's token is a session only when it says so, or says nothing in
    // the old format. A credential id means an API token stood behind it.
    const via: Via = givenVia === 'token' || givenVia === 'oauth' ? givenVia : credential_id ? 'token' : 'session'
    return { kind, id: sub, actor: actorFor('human', sub), via, ...narrowing }
  }
  if (kind === 'machine') {
    const role = text(claims['role'])
    return {
      kind, id: sub,
      actor: actorClaim(claims, kind) ?? actorFor(kind, sub, org_id),
      via: 'key',
      ...(role ? { role } : {}),
      ...narrowing,
    }
  }
  // An agent. It acts for somebody, or it acts for nobody and can do nothing:
  // `on_behalf_of` is kept only in the shape `user:<id>`. The old `assistant`
  // token (no `kind`) has no agent record: its subject is the person, so the
  // person is who it acts for when it says nothing better.
  const claimed = text(claims['on_behalf_of'])
  const given = claimed && BEHALF_RE.test(claimed) ? claimed : undefined
  const legacy = named ? undefined : BEHALF_RE.test(`user:${sub}`) ? `user:${sub}` : undefined
  const on_behalf_of = given ?? legacy
  return {
    kind: 'agent', id: sub,
    actor: actorClaim(claims, 'agent') ?? actorFor('agent', named ? sub : 'assistant', on_behalf_of?.replace(/^user:/, '')),
    via: givenVia === 'oauth' ? 'oauth' : 'token',
    ...(on_behalf_of ? { on_behalf_of } : {}),
    ...narrowing,
  }
}

/** The person whose standing decides what this principal may do: itself, or who it works for. */
export function personOf(p: Principal): string | undefined {
  if (p.kind === 'human') return p.id
  if (p.kind === 'agent') return p.on_behalf_of?.replace(/^user:/, '')
  return undefined
}

/** True only for a person who signed in. An agent, a token, a key and a service are not. */
export function isSession(p: Principal): boolean {
  return p.kind === 'human' && p.via === 'session'
}

/** May this credential write? Absent `access` means it is not limited; an empty one means nothing. */
export function mayWrite(p: Principal): boolean {
  return !p.access || p.access.includes('write')
}

/** May this credential read? Absent `access` means it is not limited. */
export function mayRead(p: Principal): boolean {
  return !p.access || p.access.includes('read')
}

/** Where a request came through. `app` is the product or tool, when it said. */
export interface ClientInfo {
  surface: 'ui' | 'api' | 'cli' | 'mcp'
  app?: string
}

/** `X-Baseworks-Client: cli/bw`, `mcp/claude`, `ui`. Unset or unreadable: `api`. */
export function clientOf(header: string | undefined): ClientInfo {
  const [surface, app] = (header ?? '').trim().split('/', 2)
  const known = surface === 'ui' || surface === 'cli' || surface === 'mcp' || surface === 'api' ? surface : 'api'
  const name = app ? safe(app).slice(0, 60) : ''
  return { surface: known, ...(name ? { app: name } : {}) }
}

/** What every event says about who caused it. All strings, so it reads the same in any store. */
export interface AuditEnvelope {
  kind: PrincipalKind
  actor: string
  actor_id: string
  via: Via
  on_behalf_of?: string
  credential_id?: string
  client?: string
  org_id?: string
  request_id?: string
}

export interface AuditContext {
  client?: ClientInfo
  /** The organization the request is for; falls back to the one the credential is bound to. */
  org_id?: string
  request_id?: string
}

export function auditEnvelope(p: Principal, ctx: AuditContext = {}): AuditEnvelope {
  const org_id = ctx.org_id || p.org_id
  const client = ctx.client ? (ctx.client.app ? `${ctx.client.surface}/${ctx.client.app}` : ctx.client.surface) : undefined
  return {
    kind: p.kind,
    actor: p.actor,
    actor_id: p.id,
    via: p.via,
    ...(p.on_behalf_of ? { on_behalf_of: p.on_behalf_of } : {}),
    ...(p.credential_id ? { credential_id: p.credential_id } : {}),
    ...(client ? { client } : {}),
    ...(org_id ? { org_id } : {}),
    ...(ctx.request_id ? { request_id: ctx.request_id } : {}),
  }
}

/**
 * The options an event is appended with: who did it, under `metadata.audit`,
 * and the request it belongs to as the correlation id. Shaped for foldbase's
 * `emit(..., opts)`:
 *
 *     await customers.emit(id, 0, 'CustomerCreated', payload, emitAs(principal, { org_id, request_id }))
 */
export function emitAs(p: Principal, ctx: AuditContext = {}): {
  actor: string
  metadata: { audit: AuditEnvelope }
  correlationId?: string
} {
  return {
    actor: p.actor,
    metadata: { audit: auditEnvelope(p, ctx) },
    ...(ctx.request_id ? { correlationId: ctx.request_id } : {}),
  }
}
