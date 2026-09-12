/**
 * Realm identity tokens: minting, publication and verification.
 *
 * One realm has one issuer — its auth-service — and one signing key pair. Every
 * other service in the realm (org, iam, billing, pay, and each product API)
 * verifies with the PUBLIC key it fetches from `/.well-known/jwks.json`, and
 * therefore cannot mint anything.
 *
 * That asymmetry is the whole point. With a shared HMAC secret, every service
 * holding it can also *issue* tokens — including one that claims to be another
 * user. This is not theoretical: a product API was found minting
 * `{ sub: <some other user>, type: 'user' }` to write a membership on that
 * user's behalf. Under ES256 that is impossible by construction: the private
 * key never leaves auth-service.
 *
 * Claims: `iss`, `aud`, `sub`, `iat`, `exp`, `jti`, `type`. Org and role are
 * deliberately absent — membership changes while a token lives, so a token that
 * carries a role goes stale and lies. Consumers ask the org service instead.
 *
 * HS256 stays available during migration; see `verifier()` below.
 */

import {
  SignJWT,
  jwtVerify,
  exportJWK,
  importPKCS8,
  importSPKI,
  calculateJwkThumbprint,
  createLocalJWKSet,
  createRemoteJWKSet,
  type JSONWebKeySet,
  type JWK,
} from 'jose'

export const IDENTITY_ALG = 'ES256'

/** `human` signs in; `service` is a service acting as itself; `assistant` is a narrowed token. */
export type IdentityType = 'human' | 'service' | 'assistant'

export interface IdentityClaims {
  sub: string
  type: IdentityType
  iss?: string
  aud?: string
  exp?: number
  iat?: number
  jti?: string
  /** Narrowed tokens carry the org they are scoped to; identity tokens do not. */
  org_id?: string
  scope?: string
  [key: string]: unknown
}

export interface SigningKey {
  privateKey: CryptoKey
  /** Published in the JWKS and in every token header, so verifiers pick the right key. */
  kid: string
  publicJwk: JWK
}

// ─── Key material ────────────────────────────────────────────────────────────

/**
 * Accept a PEM as-is, or base64 of a PEM.
 *
 * Environment variables and PEM disagree about newlines: a key pasted into a
 * shell, a Kubernetes Secret or a CI variable loses them often enough that
 * requiring raw PEM guarantees confusing failures. Base64 survives every one of
 * those paths, so both forms are accepted.
 */
function toPem(raw: string, label: 'PRIVATE' | 'PUBLIC'): string {
  const value = raw.trim()
  if (value.includes('-----BEGIN')) return value.replace(/\\n/g, '\n')
  const decoded = Buffer.from(value, 'base64').toString('utf8')
  if (decoded.includes('-----BEGIN')) return decoded.trim()
  throw new Error(`not a ${label} key: expected PEM, or base64 of PEM`)
}

async function jwkOf(key: CryptoKey, kid?: string): Promise<JWK> {
  const jwk = await exportJWK(key)
  jwk.alg = IDENTITY_ALG
  jwk.use = 'sig'
  // A thumbprint (RFC 7638) is derived from the key itself, so the same key
  // always gets the same id and two different keys can never collide. Deriving
  // beats configuring: one less value to keep in step across services.
  jwk.kid = kid ?? (await calculateJwkThumbprint(jwk))
  return jwk
}

/** Load the signing key pair from a PKCS#8 private key. */
export async function loadSigningKey(privateKeyPem: string, kid?: string): Promise<SigningKey> {
  const pem = toPem(privateKeyPem, 'PRIVATE')
  const privateKey = await importPKCS8(pem, IDENTITY_ALG, { extractable: true })
  const publicJwk = await jwkOf(privateKey, kid)
  // The private half must never reach the JWKS; exportJWK on a private key
  // returns `d`, and publishing it would hand the realm away.
  delete publicJwk.d
  return { privateKey, kid: publicJwk.kid as string, publicJwk }
}

/** Load a public key (SPKI PEM) for publication only — a retired key during rotation. */
export async function loadPublicKey(publicKeyPem: string, kid?: string): Promise<JWK> {
  const key = await importSPKI(toPem(publicKeyPem, 'PUBLIC'), IDENTITY_ALG, { extractable: true })
  return jwkOf(key, kid)
}

/**
 * The document served at `/.well-known/jwks.json`.
 *
 * Rotation works by publishing both keys for longer than a token lives: add the
 * new key, sign with it, keep the old one listed until every token signed by it
 * has expired, then drop it.
 */
export function jwks(signing: SigningKey, retired: JWK[] = []): JSONWebKeySet {
  return { keys: [signing.publicJwk, ...retired] }
}

// ─── Minting ─────────────────────────────────────────────────────────────────

export interface MintOptions {
  issuer: string
  audience: string
  expiresInSeconds: number
}

export async function mint(
  key: SigningKey,
  claims: IdentityClaims,
  opts: MintOptions,
): Promise<string> {
  const { sub, type, ...rest } = claims
  return new SignJWT({ type, ...rest })
    .setProtectedHeader({ alg: IDENTITY_ALG, kid: key.kid })
    .setSubject(sub)
    .setIssuer(opts.issuer)
    .setAudience(opts.audience)
    .setIssuedAt()
    // A unique id per token is what makes a future revocation list possible;
    // without it a leaked token cannot be named, only waited out.
    .setJti(crypto.randomUUID())
    .setExpirationTime(`${opts.expiresInSeconds}s`)
    .sign(key.privateKey)
}

// ─── Verification ────────────────────────────────────────────────────────────

export interface VerifierOptions {
  /** Where to fetch the realm's public keys. jose caches and refetches on an unknown `kid`. */
  jwksUri?: string
  /** A fixed key set instead of a URL — for tests, or a service that ships with the realm. */
  jwks?: JSONWebKeySet
  issuer?: string
  audience?: string
  /**
   * Accept HS256 tokens signed with this shared secret, in addition to ES256.
   *
   * Migration only. While it is set, any holder of the secret can still mint
   * tokens for this realm — including tokens impersonating a user — so it must
   * be removed once every issuer has moved to ES256.
   */
  legacyHs256Secret?: string
}

export interface Verifier {
  (token: string): Promise<IdentityClaims | null>
}

/**
 * Build a verifier for the realm.
 *
 * Returns `null` rather than throwing on every rejection: a caller answering an
 * HTTP request wants one 401 path, not a taxonomy of crypto errors. Reasons
 * worth acting on (an unreachable JWKS, say) surface through `onError`.
 */
export function verifier(opts: VerifierOptions & { onError?: (err: unknown) => void }): Verifier {
  if (!opts.jwksUri && !opts.jwks && !opts.legacyHs256Secret) {
    throw new Error('verifier needs jwksUri, jwks, or legacyHs256Secret')
  }

  const keys = opts.jwks
    ? createLocalJWKSet(opts.jwks)
    : opts.jwksUri
      ? createRemoteJWKSet(new URL(opts.jwksUri))
      : undefined

  const legacy = opts.legacyHs256Secret
    ? new TextEncoder().encode(opts.legacyHs256Secret)
    : undefined

  const expectations = {
    ...(opts.issuer ? { issuer: opts.issuer } : {}),
    ...(opts.audience ? { audience: opts.audience } : {}),
  }

  return async (token: string): Promise<IdentityClaims | null> => {
    if (keys) {
      try {
        const { payload } = await jwtVerify(token, keys, {
          ...expectations,
          algorithms: [IDENTITY_ALG],
        })
        return payload as unknown as IdentityClaims
      } catch (err) {
        // Fall through to the legacy secret when one is configured: during
        // migration both kinds of token are in circulation at once.
        if (!legacy) {
          opts.onError?.(err)
          return null
        }
      }
    }

    if (!legacy) return null
    try {
      // Legacy tokens predate iss/aud, so those are not required of them.
      const { payload } = await jwtVerify(token, legacy, { algorithms: ['HS256'] })
      return payload as unknown as IdentityClaims
    } catch (err) {
      opts.onError?.(err)
      return null
    }
  }
}
