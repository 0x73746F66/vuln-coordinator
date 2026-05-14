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

## Developer gotchas — written for people who live in the code

You write JavaScript every day; you read `package.json` once a sprint. These are the surprises that catch developers — not security engineers — when triaging an SCA finding.

- **`package.json` and `package-lock.json` disagree, and the scanner is reading the lockfile.** You bumped `"lodash": "^4.17.21"` in `package.json`, opened the MR, the scanner is still flagging 4.17.20. Cause: the lockfile is still pinning the old version because nobody ran `npm install` after the bump. Symptom: `npm ls lodash` shows the old version even though the manifest says new. Fix: run `npm install` (or `npm install lodash@latest`), commit the regenerated lockfile.

- **The scanner flags a `devDependency` and you don't ship it.** `eslint`, `webpack`, `jest`, `typescript` are all dev-time tools. A CVE in any of them is unlikely to be in production. The honest VEX is `not_affected` with `component_not_present` *if* you can prove the dep doesn't end up in your bundle/image — but `npm install` (no flags) installs both `dependencies` and `devDependencies`, so it shows up in `node_modules`, so naïve image scans flag it. Real fix: `npm ci --omit=dev` in your production stage, or scan the runtime image not the build image.

- **You upgraded the dep but the bundled fat-file in `dist/` still has the old code.** Webpack/Rollup/esbuild bundles ship a snapshot of `node_modules` at build time. If your CI publishes `dist/bundle.js` and you bumped the dep but didn't rebuild, the bundle still contains the vulnerable code. Symptom: scanners flagging an artefact that doesn't match your manifest. Fix: rebuild, re-test, re-publish. Add a `npm run build` step to your release pipeline if it's missing.

- **`peerDependencies` aren't installed by default in npm 7+; they *are* validated.** You declared `react` as a peer dep; the consumer is on React 17; you wrote your code for React 18 hooks. npm doesn't install `react` for you — it warns. The consumer's installed `react@17` is what runs. A CVE in React surfaces against the consumer's lockfile, not yours.

- **The `engines` field is documentation, not enforcement.** `"engines": { "node": ">=18" }` doesn't stop someone running your code on Node 16; it logs a warning. If the vuln only exists in older Node, your `engines` doesn't protect you — package the runtime version (Docker base image, asdf/nvm pin in CI, etc.).

- **`postinstall` scripts run code from any installed package.** When the scanner flags a `MAL-` entry on a dep you just added, the malicious code may have already executed on the dev who first installed it. Mitigate with `npm ci --ignore-scripts` in CI, and `npm config set ignore-scripts true` on dev machines. Audit `node_modules/<pkg>/package.json`'s `scripts.{postinstall,preinstall,install}` after a fresh install.

- **Two copies of the same package, different versions.** `npm` hoists what it can; what it can't, it nests. `npm ls <pkg>` shows the tree — multiple copies are normal. A coercion (`overrides`) collapses them. Without one, you might have `lodash@4.17.20` and `lodash@4.17.21` both installed, with different modules importing different versions. Scanners may flag both rows.

- **`type: "module"` flips the resolution algorithm.** `require()` and `import` see different things. ESM-only packages may not be reachable from your CJS code at all (a static check that confirms `vulnerable_code_not_present`); CJS-only packages won't import into your ESM file without `--experimental-require-module`. Reachability depends on which side of the boundary your code is on.

- **`workspaces` hoist your dependencies up.** In a monorepo, `packages/api/node_modules/lodash` may not exist — the dep is hoisted to the root `node_modules`. A scan against `packages/api/` alone won't see it. Scan the root.

- **`npm audit` fixes versions that `npm install` won't actually pick.** `npm audit fix` rewrites the lockfile to the fixed version; the next `npm install` without the lockfile may pick a different version because your `package.json` range allows it. Lockfile-first workflow: `npm ci` (not `npm install`) in CI.

- **The `funding` URL has nothing to do with security.** When `npm install` prints "X packages are looking for funding", that's not a vulnerability notice. The actual security notice is `npm audit`'s summary.

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
