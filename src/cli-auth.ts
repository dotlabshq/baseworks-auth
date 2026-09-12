/**
 * CLI authentication helpers — PKCE polling flow.
 * Used by any CLI tool that authenticates via an orbseal-compatible API.
 *
 * Flow:
 *   1. startCliAuth()  → get state + URL to show user
 *   2. pollCliAuth()   → long-poll until user completes browser auth
 */

export interface CliAuthStart {
  state:     string;
  url:       string;
  expiresIn: number;   // seconds
}

export interface CliAuthResult {
  token: string;
}

export interface PollOptions {
  /** ms between polls (default: 2000) */
  intervalMs?: number;
  /**
   * ms before giving up (default: 600_000 = 10 min).
   *
   * Prefer passing `start.expiresIn * 1000` so the CLI stops at the same moment
   * the server drops the state; a shorter timeout reports a client-side
   * giving-up while the link is in fact still good.
   */
  timeoutMs?:  number;
}

/**
 * Call the API to initiate CLI login.
 * Returns the state handle and the URL the user should open.
 */
export async function startCliAuth(apiBase: string): Promise<CliAuthStart> {
  const url = `${apiBase.replace(/\/+$/, '')}/v1/auth/start`;
  const res = await fetch(url);

  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`Auth start failed (${res.status}): ${text}`);
  }

  const data = await res.json() as {
    state?:      string;
    url?:        string;
    expires_in?: number;
  };

  if (!data.state || !data.url) {
    throw new Error('Invalid response from auth/start');
  }

  return {
    state:     data.state,
    url:       data.url,
    expiresIn: data.expires_in ?? 600,
  };
}

/**
 * Poll the API until the user completes browser auth.
 * Resolves with the token when done, rejects on timeout or error.
 */
export async function pollCliAuth(
  apiBase: string,
  state:   string,
  opts:    PollOptions = {},
): Promise<CliAuthResult> {
  const intervalMs = opts.intervalMs ?? 2_000;
  const timeoutMs  = opts.timeoutMs  ?? 600_000;
  const base       = apiBase.replace(/\/+$/, '');
  const deadline   = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    await sleep(intervalMs);

    const res = await fetch(`${base}/v1/auth/poll/${state}`);

    if (!res.ok) {
      throw new Error(`Poll failed (${res.status})`);
    }

    const data = await res.json() as {
      status?: string;
      token?:  string;
    };

    if (data.status === 'done' && data.token) {
      return { token: data.token };
    }

    // The server answers 'expired' both for a state whose TTL ran out and for
    // one it never had; from here the two are the same thing — nobody approved
    // in time.
    if (data.status === 'expired') {
      throw new Error('the sign-in was not approved in time — run login again');
    }

    // status === "pending" → continue polling
  }

  throw new Error('no approval received in time — run login again');
}

// ─── helpers ────────────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
