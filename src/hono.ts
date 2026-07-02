import type { Context, Next } from 'hono'
import { verifyHs256Jwt } from './jwt.js'

export interface ServiceAuthUser {
  userId:    string
  orgId?:    string
  role?:     string
  tokenType: 'user' | 'service'
}

declare module 'hono' {
  interface ContextVariableMap {
    auth: ServiceAuthUser
  }
}

/**
 * Hono middleware — verifies HS256 JWT from Authorization: Bearer header.
 * Reads JWT_SECRET from process.env.
 * Sets c.var.auth on success.
 */
export async function requireAuth(c: Context, next: Next) {
  const header = c.req.header('Authorization')
  if (!header?.startsWith('Bearer ')) return c.json({ error: 'Unauthorized' }, 401)

  const token  = header.slice(7)
  const secret = process.env['JWT_SECRET']
  if (!secret) return c.json({ error: 'JWT_SECRET not configured' }, 500)

  const claims = verifyHs256Jwt(token, secret)
  if (!claims) return c.json({ error: 'Unauthorized' }, 401)

  c.set('auth', {
    userId:    String(claims['sub'] ?? ''),
    orgId:     claims['org_id'] as string | undefined,
    role:      claims['role'] as string | undefined,
    tokenType: claims['type'] === 'service' ? 'service' : 'user',
  })
  return next()
}
