import { defineConfig } from 'tsup'

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    oidc: 'src/oidc.ts',
    'oidc-human': 'src/oidc-human.ts',
    pkce: 'src/pkce.ts',
    'cli-auth': 'src/cli-auth.ts',
    cli: 'src/cli.ts',
    token: 'src/token.ts',
    jwt: 'src/jwt.ts',
    identity: 'src/identity.ts',
    hono: 'src/hono.ts',
  },
  format: ['esm'],
  dts: true,
  clean: true,
  external: ['@baseworks/core', '@baseworks/cli', 'hono', 'commander'],
})
