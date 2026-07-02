/**
 * PKCE (Proof Key for Code Exchange) utilities — RFC 7636.
 * Runtime-agnostic: Workers, Node 20+, browser (Web Crypto API).
 */
import { base64urlEncode } from '@baseworks/core'

export interface PkceChallenge {
  verifier:  string;
  challenge: string;
  method:    'S256';
}

export interface OidcAuthUrlConfig {
  /** OIDC issuer base URL, e.g. "https://nesskey.com" */
  issuer:       string;
  clientId:     string;
  redirectUri:  string;
  /** Defaults to ["openid", "email", "profile"] */
  scopes?:      string[];
  state?:       string;
  challenge:    string;
  /**
   * OIDC prompt parameter.
   * - "select_account" → show account chooser even if session exists (recommended for web apps)
   * - "login"          → force re-authentication every time
   * - "none"           → silent auth, error if no session
   */
  prompt?:      'select_account' | 'login' | 'none' | 'consent';
}

/** Generate a PKCE code_verifier + S256 code_challenge pair. */
export async function generatePkce(): Promise<PkceChallenge> {
  const verifier  = base64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
  const digest    = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  const challenge = base64urlEncode(new Uint8Array(digest));
  return { verifier, challenge, method: 'S256' };
}

/**
 * Build an OIDC authorization URL with PKCE.
 * Compatible with any OIDC provider (Zitadel, Auth0, Keycloak, etc.).
 */
export function buildOidcAuthUrl(config: OidcAuthUrlConfig): string {
  const issuer = config.issuer.replace(/\/+$/, '');
  const scopes = (config.scopes ?? ['openid', 'email', 'profile']).join(' ');

  const params = new URLSearchParams({
    client_id:             config.clientId,
    redirect_uri:          config.redirectUri,
    response_type:         'code',
    scope:                 scopes,
    code_challenge:        config.challenge,
    code_challenge_method: 'S256',
  });

  if (config.state)  params.set('state',  config.state);
  if (config.prompt) params.set('prompt', config.prompt);

  return `${issuer}/oauth/v2/authorize?${params.toString()}`;
}
