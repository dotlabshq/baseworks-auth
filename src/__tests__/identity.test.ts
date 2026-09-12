import { describe, expect, it } from 'vitest'
import { exportPKCS8, exportSPKI, generateKeyPair } from 'jose'
import { jwks, loadPublicKey, loadSigningKey, mint, verifier } from '../identity.js'

const ISS = 'https://auth.example.test'
const AUD = 'example-realm'

async function freshKey() {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true })
  return { pkcs8: await exportPKCS8(privateKey), spki: await exportSPKI(publicKey) }
}

describe('identity tokens', () => {
  it('mints and verifies a token against the published JWKS', async () => {
    const { pkcs8 } = await freshKey()
    const key = await loadSigningKey(pkcs8)
    const token = await mint(key, { sub: 'usr_1', type: 'human' }, {
      issuer: ISS, audience: AUD, expiresInSeconds: 60,
    })

    const verify = verifier({ jwks: jwks(key), issuer: ISS, audience: AUD })
    const claims = await verify(token)

    expect(claims?.sub).toBe('usr_1')
    expect(claims?.type).toBe('human')
    expect(claims?.iss).toBe(ISS)
    expect(claims?.aud).toBe(AUD)
    expect(claims?.jti).toBeTruthy()
  })

  it('never publishes the private half', async () => {
    const { pkcs8 } = await freshKey()
    const key = await loadSigningKey(pkcs8)
    const published = JSON.stringify(jwks(key))

    expect(published).not.toContain('"d"')
    expect(key.publicJwk.kid).toBeTruthy()
    expect(key.publicJwk.alg).toBe('ES256')
  })

  it('rejects a token signed by another realm', async () => {
    const mine = await loadSigningKey((await freshKey()).pkcs8)
    const theirs = await loadSigningKey((await freshKey()).pkcs8)

    const token = await mint(theirs, { sub: 'usr_1', type: 'human' }, {
      issuer: ISS, audience: AUD, expiresInSeconds: 60,
    })

    expect(await verifier({ jwks: jwks(mine), issuer: ISS, audience: AUD })(token)).toBeNull()
  })

  it('rejects a wrong audience and a wrong issuer', async () => {
    const key = await loadSigningKey((await freshKey()).pkcs8)
    const token = await mint(key, { sub: 'usr_1', type: 'human' }, {
      issuer: ISS, audience: 'other-realm', expiresInSeconds: 60,
    })

    expect(await verifier({ jwks: jwks(key), issuer: ISS, audience: AUD })(token)).toBeNull()
    expect(await verifier({ jwks: jwks(key), issuer: 'https://elsewhere.test', audience: 'other-realm' })(token)).toBeNull()
  })

  it('rejects an expired token', async () => {
    const key = await loadSigningKey((await freshKey()).pkcs8)
    const token = await mint(key, { sub: 'usr_1', type: 'human' }, {
      issuer: ISS, audience: AUD, expiresInSeconds: -1,
    })
    expect(await verifier({ jwks: jwks(key), issuer: ISS, audience: AUD })(token)).toBeNull()
  })

  it('keeps a retired key verifiable while it is still published', async () => {
    const old = await loadSigningKey((await freshKey()).pkcs8)
    const oldSpki = (await freshKey()).spki // ayri bir anahtar: yayinlanmamis olan
    const current = await loadSigningKey((await freshKey()).pkcs8)

    const tokenFromOld = await mint(old, { sub: 'usr_1', type: 'human' }, {
      issuer: ISS, audience: AUD, expiresInSeconds: 60,
    })

    const withOld = verifier({ jwks: jwks(current, [old.publicJwk]), issuer: ISS, audience: AUD })
    expect((await withOld(tokenFromOld))?.sub).toBe('usr_1')

    // Yayindan dusunce ayni token artik gecmez.
    const withoutOld = verifier({ jwks: jwks(current), issuer: ISS, audience: AUD })
    expect(await withoutOld(tokenFromOld)).toBeNull()

    // Emeklilikte yalniz public anahtar elde olur; PEM'den de yuklenebilmeli.
    expect((await loadPublicKey(oldSpki)).kid).toBeTruthy()
  })

  it('accepts base64-wrapped PEM, because env vars eat newlines', async () => {
    const { pkcs8 } = await freshKey()
    const key = await loadSigningKey(Buffer.from(pkcs8).toString('base64'))
    const token = await mint(key, { sub: 'usr_1', type: 'human' }, {
      issuer: ISS, audience: AUD, expiresInSeconds: 60,
    })
    expect((await verifier({ jwks: jwks(key), issuer: ISS, audience: AUD })(token))?.sub).toBe('usr_1')
  })
})

describe('HS256 migration mode', () => {
  const secret = 'test-secret-32-chars-long-enough!'

  it('accepts both an ES256 token and a legacy HS256 one', async () => {
    const { signHs256Jwt } = await import('../jwt.js')
    const key = await loadSigningKey((await freshKey()).pkcs8)
    const verify = verifier({ jwks: jwks(key), issuer: ISS, audience: AUD, legacyHs256Secret: secret })

    const modern = await mint(key, { sub: 'usr_1', type: 'human' }, {
      issuer: ISS, audience: AUD, expiresInSeconds: 60,
    })
    const legacy = signHs256Jwt({ sub: 'usr_2', type: 'human' }, secret, 60)

    expect((await verify(modern))?.sub).toBe('usr_1')
    expect((await verify(legacy))?.sub).toBe('usr_2')
  })

  it('rejects a legacy token once the secret is withdrawn', async () => {
    const { signHs256Jwt } = await import('../jwt.js')
    const key = await loadSigningKey((await freshKey()).pkcs8)
    const legacy = signHs256Jwt({ sub: 'usr_2', type: 'human' }, secret, 60)

    expect(await verifier({ jwks: jwks(key), issuer: ISS, audience: AUD })(legacy)).toBeNull()
  })
})

describe('hono middleware', () => {
  const secret = 'test-secret-32-chars-long-enough!'

  async function run(env: Record<string, string | undefined>, token?: string) {
    const { requireAuth, resetAuthVerifier } = await import('../hono.js')
    for (const [k, v] of Object.entries(env)) {
      if (v === undefined) delete process.env[k]
      else process.env[k] = v
    }
    resetAuthVerifier()

    const { Hono } = await import('hono')
    const app = new Hono()
    app.use('*', requireAuth)
    app.get('/', (c) => c.json(c.get('auth')))
    return app.request('/', token ? { headers: { Authorization: `Bearer ${token}` } } : {})
  }

  it('answers 500, not 401, when nothing is configured', async () => {
    const res = await run({ AUTH_JWKS_URI: undefined, JWT_SECRET: undefined }, 'whatever')
    expect(res.status).toBe(500)
  })

  it('rejects a missing header', async () => {
    expect((await run({ JWT_SECRET: secret })).status).toBe(401)
  })

  it('accepts a legacy HS256 token and classifies the token type', async () => {
    const { signHs256Jwt } = await import('../jwt.js')
    const res = await run(
      { AUTH_JWKS_URI: undefined, JWT_SECRET: secret },
      signHs256Jwt({ sub: 'usr_1', type: 'service' }, secret, 60),
    )
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ userId: 'usr_1', tokenType: 'service' })
  })

  it('treats an unknown token type as a plain user token', async () => {
    const { signHs256Jwt } = await import('../jwt.js')
    const res = await run(
      { AUTH_JWKS_URI: undefined, JWT_SECRET: secret },
      signHs256Jwt({ sub: 'usr_1', type: 'something-new' }, secret, 60),
    )
    expect(await res.json()).toMatchObject({ tokenType: 'user' })
  })

  it('rejects a token signed with a different secret', async () => {
    const { signHs256Jwt } = await import('../jwt.js')
    const res = await run(
      { AUTH_JWKS_URI: undefined, JWT_SECRET: secret },
      signHs256Jwt({ sub: 'usr_1', type: 'human' }, 'a-completely-different-secret!!', 60),
    )
    expect(res.status).toBe(401)
  })
})

describe('remote JWKS — the production path', () => {
  it('fetches the key set over HTTP and verifies a token against it', async () => {
    const { createServer } = await import('node:http')
    const { exportPKCS8, generateKeyPair } = await import('jose')

    const { privateKey } = await generateKeyPair('ES256', { extractable: true })
    const key = await loadSigningKey(await exportPKCS8(privateKey))

    let served = 0
    const server = createServer((_req, res) => {
      served += 1
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify(jwks(key)))
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const { port } = server.address() as { port: number }

    try {
      const verify = verifier({
        jwksUri: `http://127.0.0.1:${port}/.well-known/jwks.json`,
        issuer: ISS,
        audience: AUD,
      })

      const token = await mint(key, { sub: 'usr_1', type: 'human' }, {
        issuer: ISS, audience: AUD, expiresInSeconds: 60,
      })

      expect((await verify(token))?.sub).toBe('usr_1')
      // Second call must come from cache: a fetch per request would put the
      // auth service on the critical path of every request in the realm.
      expect((await verify(token))?.sub).toBe('usr_1')
      expect(served).toBe(1)
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()))
    }
  })

  it('returns null instead of throwing when the key set is unreachable', async () => {
    const key = await loadSigningKey((await freshKey()).pkcs8)
    const token = await mint(key, { sub: 'usr_1', type: 'human' }, {
      issuer: ISS, audience: AUD, expiresInSeconds: 60,
    })

    let seen: unknown
    // Port 1 is reserved and never listening.
    const verify = verifier({
      jwksUri: 'http://127.0.0.1:1/jwks.json',
      issuer: ISS,
      audience: AUD,
      onError: (err) => { seen = err },
    })

    expect(await verify(token)).toBeNull()
    expect(seen).toBeTruthy()
  })
})
