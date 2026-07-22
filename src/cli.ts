/**
 * Importable `login` / `logout` commands for any CLI that authenticates through
 * an auth-service (OIDC/PKCE device flow). Mirrors the `@baseworks/org/cli` and
 * `@baseworks/iam/cli` pattern — the commands live in auth's own package; the
 * app composes them:
 *
 *   import { addAuthCommands } from '@baseworks/auth/cli'
 *   addAuthCommands(program, { authBase, cliName: 'dtab', onToken, onLogout })
 *
 * The device flow is auth-service's `/v1/auth/start` + `/v1/auth/poll/:state`
 * (see `@baseworks/auth/cli-auth`). auth mints an identity JWT (`{ sub, type }`,
 * HS256) that org-service and iam-service verify with the shared realm secret —
 * so ONE login token works across the whole plane. Org context is not in the
 * token; the app resolves it via org-service (`use` / `ls`).
 */
import { spawn } from 'node:child_process'
import { Command } from 'commander'
import { clr, kv, success, warn, fatal } from '@baseworks/cli/display'
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

/** Decode a JWT payload without verifying (display only). */
function jwtSub(token: string): string | undefined {
  try {
    const seg = token.split('.')[1]
    if (!seg) return undefined
    const json = Buffer.from(seg.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')
    return (JSON.parse(json) as { sub?: string }).sub
  } catch { return undefined }
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

        const { token } = await pollCliAuth(base, start.state).catch((e: Error) => fatal(e.message))
        await deps.onToken(token)

        const sub = jwtSub(token)
        success('Logged in.')
        if (sub) kv([['user id', sub]])
        console.log(`  ${clr.dim}Next: ${cli} use  ·  ${cli} orgs${clr.reset}\n`)
      }),
  )

  program.addCommand(
    new Command('logout')
      .description('Clear saved credentials and active context')
      .action(async () => {
        if (deps.onLogout) await deps.onLogout()
        else warn('No logout handler configured.')
        success('Logged out.')
      }),
  )
}
