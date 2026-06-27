import { defineConfig } from 'tsup'

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    oidc: 'src/oidc.ts',
    'oidc-human': 'src/oidc-human.ts',
    pkce: 'src/pkce.ts',
    'cli-auth': 'src/cli-auth.ts',
    token: 'src/token.ts',
    session: 'src/session.ts',
    'url-helpers': 'src/url-helpers.ts',
    edge: 'src/edge.ts',
    zitadel: 'src/zitadel.ts',
  },
  format: ['esm'],
  dts: true,
  clean: true,
  external: ['@baseworks/core', 'next'],
})
