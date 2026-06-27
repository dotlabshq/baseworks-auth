import { createRemoteJWKSet, jwtVerify } from 'jose';

export interface OidcVerifyConfig {
  issuer:    string;
  audience?: string;
}

export interface OidcClaims {
  sub:                 string;
  email?:              string;
  preferred_username?: string;
  name?:               string;
  picture?:            string;
  exp?:                number;
  iss?:                string;
  aud?:                string | string[];
}

// Matches OidcIdentity in @baseworks/account — intentionally compatible.
export interface OidcIdentity {
  subject:  string;
  issuer:   string;   // normalised, no trailing slash
  email:    string;
  name:     string;
  picture?: string;
}

function withoutTrailingSlash(v: string): string {
  return v.replace(/\/+$/, '');
}

/**
 * Verify an OIDC JWT and return the normalised identity.
 * Uses JWKS from `{issuer}/oauth/v2/keys` (Zitadel-compatible endpoint).
 * Returns null on any verification failure — never throws to the caller.
 */
export async function verifyOidcToken(
  token:  string,
  config: OidcVerifyConfig,
): Promise<OidcIdentity | null> {
  const issuer = withoutTrailingSlash(config.issuer);
  const jwks   = createRemoteJWKSet(new URL(`${issuer}/oauth/v2/keys`));
  const opts   = config.audience ? { issuer, audience: config.audience } : { issuer };

  const result = await jwtVerify(token, jwks, opts).catch(() => null);
  if (!result) return null;

  const payload = result.payload as OidcClaims;
  const subject = String(payload.sub ?? '');
  if (!subject) return null;

  const email   = String(payload.email ?? payload.preferred_username ?? `${subject}@unknown`);
  const name    = String(payload.name  ?? payload.preferred_username ?? email);
  const picture = payload.picture ? String(payload.picture) : undefined;

  return { subject, issuer, email, name, picture };
}
