/**
 * Importable `login` / `logout` / `auth status` commands for any CLI that
 * authenticates through an auth-service (OIDC/PKCE device flow). Mirrors the
 * `@baseworks/org/cli` and `@baseworks/iam/cli` pattern — the commands live in
 * auth's own package; the app composes them:
 *
 *   import { addAuthCommands } from '@baseworks/auth/cli'
 *   addAuthCommands(program, { authBase, cliName: 'dtab', onToken, onLogout })
 *
 * The device flow is auth-service's `/v1/auth/start` + `/v1/auth/poll/:state`
 * (see `@baseworks/auth/cli-auth`). auth mints an identity JWT (`{ sub, type }`,
 * HS256) that org-service and iam-service verify with the shared realm secret —
 * so ONE login token works across the whole plane. Org context is not in the
 * token; the app resolves it via org-service (`use` / `ls`).
 *
 * Storage stays with the app: this module never touches the filesystem. Pass
 * `onToken` / `onLogout` to persist, and `getToken` to enable `auth status`.
 */
import { spawn } from 'node:child_process'
import { Command } from 'commander'
import { clr, kv, success, warn, fatal } from '@baseworks/cli/display'
import { fmtRelative } from '@baseworks/cli/fmt'
import { parseJwtPayload } from './jwt.js'
import { startCliAuth, pollCliAuth } from './cli-auth.js'

export interface AuthCliDeps {
  /** Origin of the auth mount, e.g. `http://127.0.0.1:3003` (no `/v1/auth`). */
  authBase: string | (() => string)
  cliName?: string
  /** Persist the identity token (app decides where). */
  onToken: (token: string) => void | Promise<void>
  /** Clear persisted credentials/context. */
  onLogout?: () => void | Promise<void>
  /** Open the browser automatically (default true). */
  openBrowser?: boolean
  /**
   * Read the saved identity token. Providing it registers `<cli> auth status`,
   * and lets `logout` warn when a token is still reachable afterwards — an
   * environment variable that outranks the config file, typically.
   */
  getToken?: () => string | undefined
  /** Where the token came from, for display: a config path, or an env var name. */
  tokenOrigin?: () => string | undefined
  /** Extra rows for `auth status`, e.g. the API base URL the app will call. */
  statusRows?: () => [string, string][]
  /** One-line hint printed after a successful login. */
  nextSteps?: string
}

function resolveBase(b: AuthCliDeps['authBase']): string {
  return (typeof b === 'function' ? b() : b).replace(/\/+$/, '')
}

function openInBrowser(url: string): void {
  const cmd = process.platform === 'darwin' ? 'open'
    : process.platform === 'win32' ? 'cmd'
    : 'xdg-open'
  const args = process.platform === 'win32' ? ['/c', 'start', '', url] : [url]
  try { spawn(cmd, args, { stdio: 'ignore', detached: true }).unref() } catch { /* print fallback below */ }
}

interface IdentityClaims {
  sub?: string
  exp?: number
  iss?: string
  type?: string
}

/**
 * Read the token's claims WITHOUT verifying the signature — display only.
 * Verification is the server's job; a CLI holds no key and needs none.
 */
function claimsOf(token: string): IdentityClaims {
  return (parseJwtPayload(token) ?? {}) as IdentityClaims
}

function expiryLine(claims: IdentityClaims): string {
  if (!claims.exp) return 'unknown'
  const at = new Date(claims.exp * 1000).toISOString().replace('T', ' ').slice(0, 16)
  return `${at} UTC (${fmtRelative(claims.exp)})`
}

/** `<cli> auth` and `<cli> auth status` — what the saved token says, no network. */
export function buildAuthCommand(deps: AuthCliDeps): Command {
  const cli = deps.cliName ?? 'cli'

  const status = (): void => {
    const token = deps.getToken?.()
    if (!token) fatal(`not signed in — run \`${cli} login\``)

    const claims = claimsOf(token)
    const rows: [string, string][] = [...(deps.statusRows?.() ?? [])]
    rows.push(['user', claims.sub ?? 'unknown'])
    rows.push(['token type', claims.type ?? 'unknown'])
    // `iss` is absent from tokens minted before the realm started claiming one;
    // an empty row would be noise, so show it only when it is there.
    if (claims.iss) rows.push(['issuer', claims.iss])
    rows.push(['expires', expiryLine(claims)])
    const origin = deps.tokenOrigin?.()
    if (origin) rows.push(['token from', origin])
    kv(rows)

    if (claims.exp && claims.exp * 1000 <= Date.now()) {
      console.log('')
      fatal(`the token has expired — run \`${cli} login\``)
    }
    console.log('')
  }

  const cmd = new Command('auth')
    .description('Show the current sign-in (alias: auth status)')
    .action(status)

  cmd.addCommand(new Command('status').description('Show the current sign-in').action(status))
  return cmd
}

export function addAuthCommands(program: Command, deps: AuthCliDeps): void {
  const cli = deps.cliName ?? 'cli'

  program.addCommand(
    new Command('login')
      .description('Log in via browser (OIDC/PKCE)')
      .option('--no-open', 'Do not open the browser automatically')
      .action(async (opts: { open?: boolean }) => {
        const base = resolveBase(deps.authBase)
        const start = await startCliAuth(base).catch((e: Error) => fatal(`Could not reach auth service at ${base}: ${e.message}`))

        console.log(`\n  ${clr.dim}Opening your browser to sign in…${clr.reset}`)
        console.log(`  ${clr.dim}If it does not open, visit:${clr.reset}\n  ${clr.cyan}${start.url}${clr.reset}\n`)
        if (deps.openBrowser !== false && opts.open !== false) openInBrowser(start.url)

        // Without this the command sits silent for minutes and looks hung.
        const minutes = Math.max(1, Math.round(start.expiresIn / 60))
        console.log(`  ${clr.dim}Waiting for approval — the link is valid for ${minutes}m…${clr.reset}`)

        // Stop exactly when the server drops the state, not before: a shorter
        // client timeout would report failure while the link still works.
        const { token } = await pollCliAuth(base, start.state, { timeoutMs: start.expiresIn * 1000 })
          .catch((e: Error) => fatal(e.message))
        await deps.onToken(token)

        const claims = claimsOf(token)
        success('Logged in.')
        const rows: [string, string][] = []
        if (claims.sub) rows.push(['user', claims.sub])
        if (claims.exp) rows.push(['expires', expiryLine(claims)])
        if (rows.length) kv(rows)
        console.log(`  ${clr.dim}Next: ${deps.nextSteps ?? `${cli} use  ·  ${cli} orgs`}${clr.reset}\n`)
      }),
  )

  program.addCommand(
    new Command('logout')
      .description('Clear saved credentials and active context')
      .action(async () => {
        if (deps.onLogout) await deps.onLogout()
        else warn('No logout handler configured.')
        success('Logged out.')

        // A token in the environment outranks the config file, so clearing the
        // file alone can leave the user still signed in without knowing it.
        const leftover = deps.getToken?.()
        if (leftover) {
          const origin = deps.tokenOrigin?.()
          warn(`A token is still in effect${origin ? ` (${origin})` : ''} and takes precedence.`)
        }
        console.log(
          `  ${clr.dim}The token stays valid on the server until it expires; there is no server-side revocation.${clr.reset}\n`,
        )
      }),
  )

  // `auth status` only makes sense when the app can hand back what it stored.
  if (deps.getToken) program.addCommand(buildAuthCommand(deps))
}
