import { createRemoteJWKSet, jwtVerify } from 'jose';

export interface ZitadelConfig {
  issuer:    string;
  audience?: string;
}

export interface ZitadelClaims {
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
export interface ZitadelIdentity {
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
 * Verify a Zitadel JWT and return the identity.
 * Returns null on any verification failure — never throws to the caller.
 */
export async function verifyZitadelToken(
  token: string,
  config: ZitadelConfig,
): Promise<ZitadelIdentity | null> {
  const issuer = withoutTrailingSlash(config.issuer);
  const jwks   = createRemoteJWKSet(new URL(`${issuer}/oauth/v2/keys`));
  const opts   = config.audience ? { issuer, audience: config.audience } : { issuer };

  const result = await jwtVerify(token, jwks, opts).catch(() => null);
  if (!result) return null;

  const payload = result.payload as ZitadelClaims;
  const subject = String(payload.sub ?? '');
  if (!subject) return null;

  const email   = String(payload.email ?? payload.preferred_username ?? `${subject}@zitadel.local`);
  const name    = String(payload.name  ?? payload.preferred_username ?? email);
  const picture = payload.picture ? String(payload.picture) : undefined;

  return { subject, issuer, email, name, picture };
}
