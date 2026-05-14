---
title: "JavaScript — npm, pnpm, Yarn"
description: "Lockfile mechanics, transitive coercion, integrity for the three Node.js package managers."
weight: 10
---

## npm (`package-lock.json`)

```bash
# Direct upgrade
npm install lodash@^4.17.21

# Coerce a transitive that you don't declare directly (npm 8.3+)
# package.json:
#   "overrides": { "lodash": "^4.17.21" }
npm install

# Dedupe and re-lock
npm dedupe
```

Integrity is `sha512` per entry in `package-lock.json`. Verify with `npm ci` — fails if any installed package's hash doesn't match the lockfile. Gotcha: an `overrides` entry can break peer-dep contracts that other transitives rely on; run your test suite after applying. Native bindings (`node-gyp`) cache aggressively — `npm rebuild` after upgrade.

## pnpm (`pnpm-lock.yaml`)

```bash
pnpm update lodash

# Coerce a transitive — package.json:
#   "pnpm": {
#     "overrides": { "lodash": "^4.17.21" },
#     "peerDependencyRules": { "allowedVersions": { "react": "18" } }
#   }
pnpm install
```

`pnpm` uses a content-addressable store; integrity is per-blob and per-entry in the lockfile. Coercion is more granular than npm — you can scope an override under a specific top-level package using `pnpm.overrides`'s `pkg>nested` syntax. Gotcha: `pnpm` peer-dep enforcement is stricter than npm; `peerDependencyRules` is where you grant exceptions rather than turning off the check globally.

## Yarn Classic / Berry (`yarn.lock`)

```bash
yarn upgrade lodash@^4.17.21

# Coerce a transitive — package.json:
#   "resolutions": { "lodash": "^4.17.21" }
#   (or "lodash@^3": "^4.17.21" for path-targeted)
yarn install
```

Yarn's `resolutions` field accepts glob-style paths (`some-pkg/**/lodash`) for surgical coercion. Yarn Berry's PnP mode (no `node_modules`) makes the lockfile authoritative; Classic falls back to `node_modules`. Gotcha: `resolutions` is enforced silently — if a resolved version is incompatible with a peer's declared range, you only find out at runtime.

## Reachability

- Bundler analysis: `esbuild --bundle --metafile=meta.json src/index.ts` produces a JSON metafile listing every imported symbol. Drive the lookup from `x_affectedRoutines` so the grep targets come from the advisory, not your memory:
  ```bash
  vulnetix vdb vuln <CVE> --output json \
    | jq -r '.[0].containers.adp[0].x_affectedRoutines[]
             | select(.kind=="function") | .name' \
    | xargs -I{} jq -r --arg fn {} \
        '.inputs | to_entries[] | select(.value.imports[]?.path | contains($fn)) | .key' \
        meta.json
  ```
- `npm ls <pkg> --all` walks the dep tree to show every path that pulls in the pkg.
- `madge --image graph.svg src/` visualises the import graph of your own code.
- Runtime: c8 / nyc coverage during integration tests. If the file that imports the vulnerable lib never gets covered, the static reach is dead in practice.
