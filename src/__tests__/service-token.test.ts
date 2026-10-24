import { describe, expect, it } from 'vitest'
import { serviceToken, ServiceTokenError } from '../service-token.js'

/** A stand-in for auth-service `/service-token`: counts calls, numbers tokens. */
function authService(opts: { secret?: string; expiresIn?: number } = {}) {
  const calls: unknown[] = []
  const fetch = async (url: string | URL | Request, init?: RequestInit) => {
    expect(String(url)).toBe('http://auth.test/service-token')
    const body = JSON.parse(String(init?.body)) as { client_id: string; client_secret: string }
    calls.push(body)
    if (body.client_secret !== (opts.secret ?? 's3cret')) return Response.json({ error: 'invalid_client' }, { status: 401 })
    return Response.json({ token: `tok-${calls.length}`, token_type: 'bearer', expires_in: opts.expiresIn ?? 3600 })
  }
  return { fetch: fetch as typeof globalThis.fetch, calls }
}

describe('serviceToken', () => {
  it('asks once with the client credentials and keeps the token', async () => {
    const auth = authService()
    const token = serviceToken({ authUrl: 'http://auth.test/', clientId: 'flect-api', clientSecret: 's3cret', fetch: auth.fetch })
    expect(await token()).toBe('tok-1')
    expect(await token()).toBe('tok-1')
    expect(auth.calls).toEqual([{ client_id: 'flect-api', client_secret: 's3cret' }])
  })

  it('renews shortly before expiry, not after', async () => {
    let t = 0
    const auth = authService({ expiresIn: 600 })
    const token = serviceToken({ authUrl: 'http://auth.test', clientId: 'flect-api', clientSecret: 's3cret', fetch: auth.fetch, now: () => t })
    expect(await token()).toBe('tok-1')
    t = 539_000 // 61 s left
    expect(await token()).toBe('tok-1')
    t = 541_000 // 59 s left: inside the renewal window
    expect(await token()).toBe('tok-2')
  })

  it('callers waiting at the same time share one request', async () => {
    const auth = authService()
    const token = serviceToken({ authUrl: 'http://auth.test', clientId: 'flect-api', clientSecret: 's3cret', fetch: auth.fetch })
    const all = await Promise.all([token(), token(), token()])
    expect(all).toEqual(['tok-1', 'tok-1', 'tok-1'])
    expect(auth.calls).toHaveLength(1)
  })

  it('a refused secret is an error that names the client, never the secret', async () => {
    const auth = authService({ secret: 'other' })
    const token = serviceToken({ authUrl: 'http://auth.test', clientId: 'flect-api', clientSecret: 's3cret', fetch: auth.fetch })
    const err = await token().catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ServiceTokenError)
    expect((err as ServiceTokenError).status).toBe(401)
    expect((err as Error).message).toContain('flect-api')
    expect((err as Error).message).not.toContain('s3cret')
    // A failure is not cached: the next call asks again.
    await token().catch(() => {})
    expect(auth.calls).toHaveLength(2)
  })
})
