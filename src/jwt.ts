import { createHmac, timingSafeEqual } from 'crypto'

export interface JwtClaims {
  sub?:    string
  exp?:    number
  iat?:    number
  org_id?: string
  role?:   string
  type?:   string
  [key: string]: unknown
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
