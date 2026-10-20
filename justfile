build:
    pnpm run build

patch: build
    pnpm version patch --no-git-tag-version

minor: build
    pnpm version minor --no-git-tag-version

publish: build
    pnpm publish --access public

release-patch:
    just patch
    just publish

release-minor:
    just minor
    just publish
