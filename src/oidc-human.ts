/**
 * Shared OIDC → HumanContext resolver.
 *
 * Handles: JWT detection, issuer check, signature verification.
 * DB lookup / user creation is delegated to `findOrCreate` — kept app-specific.
 *
 * Usage:
 *   const resolve = createOidcHumanResolver({
 *     issuer:       env.OIDC_ISSUER,
 *     audience:     env.OIDC_AUDIENCE,
 *     findOrCreate: async (identity) => { /* DB upsert *\/ },
 *   })
 *   const ctx = await resolve(bearerToken)
 */

import { decodeJwt }        from 'jose';
import { verifyOidcToken }  from './oidc.js';
import type { OidcIdentity } from './oidc.js';

export type { OidcIdentity };

export interface OidcHumanResolverConfig<T> {
  /** OIDC issuer URL — e.g. https://nesskey.com */
  issuer: string;
  /** Optional audience restriction */
  audience?: string;
  /**
   * Called after successful OIDC verification.
   * Return the app's HumanContext or null to reject.
   * Responsible for DB lookup / upsert.
   * rawToken is passed so implementations can call userinfo if needed.
   */
  findOrCreate: (identity: OidcIdentity, rawToken: string) => Promise<T | null>;
}

/**
 * Returns a resolver function `(token: string) => Promise<T | null>`.
 * Call it with a raw Bearer token (JWT form). Returns null if:
 *   - token is not a JWT
 *   - issuer doesn't match
 *   - signature invalid / expired
 *   - findOrCreate returns null
 */
export function createOidcHumanResolver<T>(
  config: OidcHumanResolverConfig<T>,
): (token: string) => Promise<T | null> {
  const issuer = config.issuer.replace(/\/+$/, '');

  return async (token: string): Promise<T | null> => {
    // Fast-fail: decode without verify to check issuer
    let iss: string | undefined;
    try { iss = (decodeJwt(token) as { iss?: string }).iss; } catch { return null; }
    if (!iss || !iss.startsWith(issuer)) return null;

    const identity = await verifyOidcToken(token, { issuer, audience: config.audience });
    if (!identity) return null;

    return config.findOrCreate(identity, token);
  };
}
