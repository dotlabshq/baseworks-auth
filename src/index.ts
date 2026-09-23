// OIDC verification (provider-agnostic)
export { verifyOidcToken } from './oidc';
export type { OidcVerifyConfig, OidcIdentity, OidcClaims } from './oidc';

// Shared OIDC → HumanContext resolver (DB-agnostic)
export { createOidcHumanResolver } from './oidc-human';
export type { OidcHumanResolverConfig } from './oidc-human';

// PKCE + authorization URL builder
export { generatePkce, buildOidcAuthUrl } from './pkce';
export type { PkceChallenge, OidcAuthUrlConfig } from './pkce';

// CLI polling flow
export { startCliAuth, pollCliAuth } from './cli-auth';
export type { CliAuthStart, CliAuthResult, PollOptions } from './cli-auth';

// Token utilities
export { hashToken, looksLikeJwt, stripBearer } from './token';

// HS256 JWT sign + verify (Node.js)
export { signHs256Jwt, verifyHs256Jwt } from './jwt';
export type { JwtClaims } from './jwt';

// Browser sessions are not here. Signing a person in, and keeping them signed
// in, is auth-service's job: this package is what a consumer shares, not a
// second place to run a login.
