import { createHmac, timingSafeEqual } from 'crypto'
import { base64urlDecodeString } from '@baseworks/core'

/** Decode a JWT payload without signature verification. Returns null on malformed input. */
export function parseJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const part = token.split('.')[1]
    if (!part) return null
    return JSON.parse(base64urlDecodeString(part)) as Record<string, unknown>
  } catch {
    return null
  }
}

export interface JwtClaims {
  sub?:    string
  exp?:    number
  iat?:    number
  org_id?: string
  role?:   string
  email?:  string
  type?:   string
  [key: string]: unknown
}

/** Sign an HS256 JWT. Runtime: Node.js only. */
export function signHs256Jwt(claims: JwtClaims, secret: string, expiresInSeconds = 86400): string {
  const header  = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
  const now     = Math.floor(Date.now() / 1000)
  const payload = Buffer.from(JSON.stringify({ iat: now, exp: now + expiresInSeconds, ...claims })).toString('base64url')
  const sig     = createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url')
  return `${header}.${payload}.${sig}`
}

/**
 * Verify an HS256 JWT using Node.js crypto.
 * Returns decoded claims on success, null on any failure.
 * Runtime: Node.js only (uses `crypto` module).
 */
export function verifyHs256Jwt(token: string, secret: string): JwtClaims | null {
  const parts = token.split('.')
  if (parts.length !== 3) return null

  const [header, payload, sig] = parts as [string, string, string]
  const expected = createHmac('sha256', secret)
    .update(`${header}.${payload}`)
    .digest('base64url')

  const sigBuf = Buffer.from(sig, 'base64url')
  const expBuf = Buffer.from(expected, 'base64url')
  if (sigBuf.length !== expBuf.length) return null
  if (!timingSafeEqual(sigBuf, expBuf)) return null

  try {
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString()) as JwtClaims
    if (claims.exp && claims.exp < Math.floor(Date.now() / 1000)) return null
    return claims
  } catch {
    return null
  }
}
