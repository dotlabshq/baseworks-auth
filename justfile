build:
    npm run build

patch: build
    npm version patch --no-git-tag-version

minor: build
    npm version minor --no-git-tag-version

publish: build
    npm publish --access public

release-patch:
    just patch
    just publish

release-minor:
    just minor
    just publish
