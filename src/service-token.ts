/**
 * A service's own identity token, from auth-service `POST /service-token`.
 *
 * Under the old shared HS256 secret a service signed its own tokens. Under
 * ES256 only auth-service signs, so a service that calls another one as
 * itself (iam, org-service) asks for a token with its client credentials and
 * presents that. This keeps one, renews it before it runs out, and never asks
 * twice at once.
 *
 *   const token = serviceToken({
 *     auth_url: env.AUTH_URL,              // auth-service's API, see below
 *     client_id: 'flect-api',
 *     client_secret: env.AUTH_CLIENT_SECRET, // from Vault, never in the job file
 *   })
 *   await fetch(iamUrl, { headers: { Authorization: `Bearer ${await token()}` } })
 *
 * `auth_url` is where auth-service's API is reached, and `/service-token` is
 * appended to it. Through a gateway that is `https://<host>/v1/auth`. Calling
 * auth-service directly, inside a cluster or on a laptop, it is the service's
 * own API mount: `http://auth:3000/api` from auth-service 2.0 on, where the
 * API moved under `/api` and the root serves pages (1.x: the bare origin).
 *
 * The secret is the service's, issued by the realm through
 * `AUTH_SERVICE_CLIENTS`. A token minted from it says `sub: <client id>,
 * type: service` and nothing else: it cannot name a user.
 */

export interface ServiceTokenOptions {
  /** auth-service origin, e.g. http://auth-service.service.consul:3000. */
  auth_url?: string
  client_id?: string
  client_secret?: string
  /** Lifetime to ask for, in seconds. auth-service caps it (3600). */
  expires_in?: number
  /** Renew this many seconds before expiry. Default 60. */
  renew_before?: number
  /** @deprecated Read `auth_url`. Accepted until the last service has moved. */
  authUrl?: string
  /** @deprecated Read `client_id`. Accepted until the last service has moved. */
  clientId?: string
  /** @deprecated Read `client_secret`. Accepted until the last service has moved. */
  clientSecret?: string
  /** @deprecated Read `expires_in`. Accepted until the last service has moved. */
  expiresIn?: number
  /** @deprecated Read `renew_before`. Accepted until the last service has moved. */
  renewBefore?: number
  fetch?: typeof fetch
  now?: () => number
}

/** Returns the current token, fetching or renewing it when needed. */
export type ServiceTokenSource = () => Promise<string>

export class ServiceTokenError extends Error {
  constructor(readonly status: number, message: string) {
    super(message)
    this.name = 'ServiceTokenError'
  }
}

export function serviceToken(opts: ServiceTokenOptions): ServiceTokenSource {
  const doFetch = opts.fetch ?? fetch
  const now = opts.now ?? Date.now
  const authUrl = opts.auth_url ?? opts.authUrl
  const clientId = opts.client_id ?? opts.clientId
  const clientSecret = opts.client_secret ?? opts.clientSecret
  const expiresIn = opts.expires_in ?? opts.expiresIn
  if (!authUrl || !clientId || !clientSecret) throw new Error('serviceToken needs auth_url, client_id and client_secret')
  const renewBeforeMs = (opts.renew_before ?? opts.renewBefore ?? 60) * 1000
  const url = `${authUrl.replace(/\/+$/, '')}/service-token`

  let current: { token: string; renewAt: number } | undefined
  let pending: Promise<string> | undefined

  async function fetchOne(): Promise<string> {
    const res = await doFetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: clientId,
        client_secret: clientSecret,
        ...(expiresIn ? { expires_in: expiresIn } : {}),
      }),
    })
    if (!res.ok) {
      // The body is auth-service's error code; it never echoes the secret.
      const body = (await res.json().catch(() => ({}))) as { error?: string }
      throw new ServiceTokenError(res.status, `service token for ${clientId}: ${body.error ?? res.statusText}`)
    }
    const { token, expires_in } = (await res.json()) as { token: string; expires_in: number }
    current = { token, renewAt: now() + Math.max(0, expires_in * 1000 - renewBeforeMs) }
    return token
  }

  return async () => {
    if (current && now() < current.renewAt) return current.token
    // Everyone waiting for a renewal shares the one request.
    pending ??= fetchOne().finally(() => {
      pending = undefined
    })
    return pending
  }
}
