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
