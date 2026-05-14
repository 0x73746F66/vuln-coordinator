---
title: "SCA — dependency vulnerabilities"
description: "Triaging SCA findings: every package manager, lockfile mechanics, transitive coercion, reachability analysis per language."
weight: 10
---

SCA is where most vulnerability work starts and where most of it ends. A scanner finds a vulnerable component in your dependency graph; you decide whether the vulnerable code is reachable in your build, then either upgrade, mitigate at runtime, or write a `not_affected` VEX statement with a sharp justification. The hard part isn't the decision — it's the mechanics: which lockfile to edit, how to coerce a transitive that you don't declare directly, how to actually check reachability in the language at hand.

This page covers all of that.

## What SCA finds in Vulnetix output

SCA findings appear in `.vulnetix/sbom.cdx.json`. Two structures matter for triage:

**`components[]`** — the resolved component graph. Each entry carries:

- `bom-ref` — the local identifier used to reference this component from `dependencies[]` and `vulnerabilities[]`.
- `purl` — the canonical package URL: `pkg:<ecosystem>/<namespace>/<name>@<version>`. This is the only field you need to reference the same component in a CycloneDX VEX.
- `version`, `name`, `type` (`library`, `framework`, `application`).
- `hashes[]` — integrity hashes from the registry. Match against the lockfile to detect tampering.
- `licenses[]` — SPDX identifiers when resolvable.

```bash
# Every component as {purl, version, type}
jq '.components[] | {purl, version, type}' .vulnetix/sbom.cdx.json

# One component by name
jq '.components[] | select(.name == "log4j-core")' .vulnetix/sbom.cdx.json

# All npm components only
jq '.components[] | select(.purl | startswith("pkg:npm/")) | .purl' \
   .vulnetix/sbom.cdx.json

# Components missing licence metadata
jq '.components[] | select(.licenses == null or (.licenses | length == 0)) | .purl' \
   .vulnetix/sbom.cdx.json
```

**`dependencies[]`** — the resolved graph as a list of `{ref, dependsOn[]}` records. Walk this backwards from a transitive finding to the top-level dep that pulled it in. The walk is the single most useful triage step in SCA.

```bash
# Forward walk: what does X depend on?
jq --arg ref "log4j-core@2.14.1" \
   '.dependencies[] | select(.ref == $ref) | .dependsOn' \
   .vulnetix/sbom.cdx.json

# Backward walk: who depends on X? — the canonical triage query
jq --arg target "log4j-core@2.14.1" \
   '.dependencies[] | select(.dependsOn | index($target)) | .ref' \
   .vulnetix/sbom.cdx.json

# Full transitive parentage of X (walk back until you hit a root)
jq --arg target "log4j-core@2.14.1" '
  def parents($t):
    [.dependencies[] | select(.dependsOn | index($t)) | .ref]
    | unique
    | if length == 0 then $t
      else . + (.[] | parents(.) | if type == "array" then . else [.] end)
      end ;
  parents($target)
' .vulnetix/sbom.cdx.json
```

When vulnerabilities are embedded inline, they appear under `vulnerabilities[]`:

- `id` — the CVE, GHSA, or vendor advisory ID.
- `source` — where the metadata came from.
- `ratings[]` — severity, optionally with CVSS vector.
- `affects[].ref` — the affected component's `bom-ref` (resolves to a PURL).
- `analysis` — Vulnetix's own assessment when one is available; if present, it's a starting point, not the final word.

```bash
# Every vuln with severity + affected PURLs
jq '.vulnerabilities[] | {
      id,
      severity: .ratings[0].severity,
      affects: [.affects[].ref]
    }' .vulnetix/sbom.cdx.json

# Critical only
jq '.vulnerabilities[] | select(.ratings[]?.severity == "critical") | .id' \
   .vulnetix/sbom.cdx.json

# Group by severity for a triage queue
jq '[.vulnerabilities[]
     | {id, severity: .ratings[0].severity}]
    | group_by(.severity)
    | map({severity: .[0].severity, count: length, ids: [.[].id]})' \
   .vulnetix/sbom.cdx.json

# Vulns Vulnetix already has an analysis on
jq '.vulnerabilities[]
    | select(.analysis != null)
    | {id, state: .analysis.state, justification: .analysis.justification}' \
   .vulnetix/sbom.cdx.json
```

### Gating signals to read first

Vulnetix's CI flags double as triage signals. If the scan failed because of one of these, the finding belongs at the top of your queue:

- `--severity high|critical` — standard severity gate.
- `--block-malware` — the package is on a known-malicious list. Treat as an incident, not a CVE: see the [xz-utils worked example](#worked-example-cve-2024-3094-xz-utils-backdoor).
- `--block-eol` — the runtime or a dependency is past end-of-life. No patches will be issued.
- `--block-unpinned` — a direct dependency uses a version range. Pin it before the next upgrade catches you out.
- `--exploits poc|active|weaponized` — the vuln has known exploit code at this maturity. KEV-listed CVEs typically hit `weaponized`.
- `--version-lag N` — your dep is N or more releases behind. Catches stale deps before they become vulnerable.
- `--cooldown N` — the dep was published within N days. Defends against typosquats and account-takeover supply-chain attacks.

## From finding to root cause

The universal six-step path, each step with the exact `jq` or CLI to run.

```bash
# Step 1 — read the PURL for one finding (start with the first critical)
jq -r '.vulnerabilities[]
       | select(.ratings[]?.severity == "critical")
       | .affects[0].ref' .vulnetix/sbom.cdx.json | head -1
# e.g. "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"

# Step 2 — backward-walk the dep graph to find the declared top-level
PURL="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
jq --arg p "$PURL" '
  .components[] as $c
  | select($c.purl == $p)
  | .["bom-ref"]
' .vulnetix/sbom.cdx.json
# Then feed that bom-ref to the backward-walk query in the previous section.

# Step 3 — full advisory (CVSS, EPSS, KEV)
vulnetix vdb vuln CVE-2021-44228

# Step 4 — patches and workarounds per registry, with exploit maturity
vulnetix vdb fixes CVE-2021-44228

# Step 5 — context-aware fix recommendation
vulnetix vdb remediation plan \
  --purl "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" \
  --current-version 2.14.1 \
  --include-guidance \
  --include-verification-steps

# Step 6 — reachability check (see the per-language section below),
# then produce the VEX statement.
```

If a code-level fix isn't immediately possible — patch is pending, transitive coercion has compatibility risk, the dep is part of a frozen vendor binary — the Vulnetix CLI itself can supply the mitigating rules so you don't have to author them from scratch:

```bash
# Snort / Suricata signatures attached to the CVE
vulnetix vdb traffic-filters CVE-2021-44228
vulnetix vdb snort-rules get CVE-2021-44228 --format rules > log4shell.rules

# Nuclei templates to verify an exploit is reachable from outside the WAF
vulnetix vdb nuclei get CVE-2021-44228 --format yaml > log4shell.yaml
nuclei -t log4shell.yaml -u https://staging.example.com

# IOC pivots — IPs, ASNs, ATT&CK techniques observed exploiting the CVE
vulnetix vdb iocs CVE-2021-44228
vulnetix vdb iocs list --cve-id CVE-2021-44228 --format stix > log4shell.stix.json
```

Deploy the rule, run the Nuclei template against staging to confirm the WAF blocks the attack vector, then write the CycloneDX VEX with `analysis.response: ["workaround_available"]` and reference the rule ID in `analysis.detail`.

Decision criteria for step 6: if the vulnerable function in the dep isn't reachable from your code, `not_affected` is honest and durable. If it is, upgrade or mitigate, then `resolved` / `exploitable + workaround_available`.

## Lockfile mechanics during patching — by package manager

For every supported package manager: where the lockfile lives, how to upgrade a single dep, how to coerce a transitive, how to verify integrity, and where the gotchas hide.

### npm (`package-lock.json`)

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

### pnpm (`pnpm-lock.yaml`)

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

### Yarn Classic / Berry (`yarn.lock`)

```bash
yarn upgrade lodash@^4.17.21

# Coerce a transitive — package.json:
#   "resolutions": { "lodash": "^4.17.21" }
#   (or "lodash@^3": "^4.17.21" for path-targeted)
yarn install
```

Yarn's `resolutions` field accepts glob-style paths (`some-pkg/**/lodash`) for surgical coercion. Yarn Berry's PnP mode (no `node_modules`) makes the lockfile authoritative; Classic falls back to `node_modules`. Gotcha: `resolutions` is enforced silently — if a resolved version is incompatible with a peer's declared range, you only find out at runtime.

### pip + `requirements.txt`

```bash
# Compile from a high-level requirements.in
pip-compile --generate-hashes requirements.in

# Coerce a transitive: pin it explicitly in requirements.in
# Then recompile
pip-compile --generate-hashes requirements.in

# Install with hash verification
pip install --require-hashes -r requirements.txt
```

`pip-compile` (from `pip-tools`) produces a fully-pinned `requirements.txt` from a constraint-style `requirements.in`. Transitive coercion means adding a constraint line for the transitive in `requirements.in` and recompiling. `--require-hashes` mandates `--hash=sha256:...` per entry — without it, the lockfile has no integrity check. Gotcha: native wheels (e.g., NumPy on Apple Silicon) have platform-specific hashes; use a `constraints.txt` separately if cross-platform.

### Pipenv (`Pipfile.lock`)

```bash
pipenv update requests

# Coerce a transitive — add to [packages] in Pipfile:
#   urllib3 = ">=2.0.7"
pipenv lock
pipenv sync     # install only what's in the lock
```

`[packages]` is production; `[dev-packages]` is dev-only — production VEX statements should ignore dev-package findings unless they ship. Integrity is per-entry `sha256`. Gotcha: `pipenv update` (no args) re-locks the entire graph; pass the package name explicitly to bump just one.

### Poetry (`poetry.lock`)

```bash
poetry update urllib3

# Coerce a transitive — pyproject.toml [tool.poetry.dependencies]:
#   urllib3 = ">=2.0.7"
poetry lock --no-update    # re-lock without bumping others
poetry install --sync
```

Poetry's constraint syntax distinguishes `^1.2.3` (next major), `~1.2.3` (next minor), `>=1.2.3` (open upper). For coercion, declare the transitive as a direct dep in `[tool.poetry.dependencies]` with the required floor. Gotcha: Poetry's resolver is exhaustive — `poetry lock` can take minutes on large graphs. Use `--no-update` when you only want to add a constraint.

### uv (`uv.lock`)

```bash
uv lock --upgrade-package requests

# Coerce a transitive: pin in pyproject.toml dependencies
uv lock

# CI: never re-resolve
uv sync --frozen
```

`uv` is the fastest of the Python lockers; `uv.lock` is TOML, human-readable, hash-locked. The frozen install in CI is the single biggest lever for build reproducibility. Gotcha: `uv` is comparatively new — the ecosystem is still catching up on tooling around it.

### Go modules (`go.mod` + `go.sum`)

```bash
go get foo.dev/bar@v1.2.3

# Coerce a transitive — go.mod:
#   require foo.dev/bar v1.2.3
#   replace foo.dev/bar => foo.dev/bar v1.2.3
go mod tidy
```

`replace` directives are the official mechanism for coerced transitives — they override what's recorded in dependent modules' `go.mod` files. `go.sum` carries `h1:` checksums verified at module-cache time; `GOSUMDB=sum.golang.org` validates against the checksum database. Vendor mode (`go mod vendor`) bakes the deps into `vendor/`; the build uses `-mod=vendor`. Gotcha: `replace` is build-local — it doesn't propagate to consumers of your module, so library authors should publish a fixed release rather than rely on `replace`.

### Cargo (`Cargo.lock`)

```bash
cargo update -p reqwest

# Coerce a transitive — Cargo.toml:
#   [patch.crates-io]
#   reqwest = { version = "0.12" }
cargo update
```

`[patch.crates-io]` redirects every reference to a crate version, regardless of where in the graph it sits. For source-level patches (a fork or a local path), `[patch]` accepts `path = ...` or `git = ...`. Integrity is per-entry SHA-256. Gotcha: `Cargo.lock` is committed for binaries but conventionally not for libraries — for an SCA fix in a library crate, the right output is a release bump rather than a lockfile change.

### Maven (`pom.xml`)

```xml
<!-- Coerce a transitive: declare it in dependencyManagement -->
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.17.1</version>
    </dependency>
  </dependencies>
</dependencyManagement>
```

```bash
mvn dependency:tree -Dincludes=org.apache.logging.log4j:log4j-core
mvn versions:display-dependency-updates
```

Maven has no native lockfile, but the `<dependencyManagement>` section in your root POM acts as one for versions. A BOM import (`<scope>import</scope>`) brings in a vetted set of versions from a vendor (Spring Boot's BOM is the common case). The `maven-enforcer-plugin` with `dependencyConvergence` makes inconsistent transitives fail the build. Gotcha: a `<dependencyManagement>` pin only applies if the artifact is actually pulled in by a transitive — declare it as a direct `<dependency>` with the right scope if it isn't.

### Gradle (`gradle.lockfile`)

```kotlin
// build.gradle.kts
dependencyLocking {
    lockAllConfigurations()
}
dependencies {
    constraints {
        implementation("org.apache.logging.log4j:log4j-core:2.17.1") {
            because("CVE-2021-44228 mitigation")
        }
    }
    implementation(enforcedPlatform("org.springframework.boot:spring-boot-dependencies:3.2.0"))
}
```

```bash
./gradlew dependencies --write-locks
```

`dependencies.constraints` is the coercion mechanism — it forces a transitive to a specific version, with a `because` reason that appears in build reports. `enforcedPlatform()` imports a Maven BOM and overrides any other resolved version. `gradle.lockfile` records the resolved version per configuration. Gotcha: locking is per-configuration; multi-project builds need locking enabled in each subproject.

### Bundler / RubyGems (`Gemfile.lock`)

```ruby
# Gemfile
gem "rails", "~> 7.1.0"
gem "nokogiri", ">= 1.16.5"   # explicit pin to coerce transitive
```

```bash
bundle update nokogiri
bundle install --frozen
```

Bundler doesn't expose a separate transitive-coercion mechanism — to coerce a transitive, declare it explicitly in the `Gemfile`. The `BUNDLED WITH` line at the bottom of `Gemfile.lock` pins the Bundler version; mismatches across the team cause subtle resolution drift. Gotcha: `bundle update` without args re-resolves everything; always pass the gem name.

### NuGet (`packages.lock.json`, `Directory.Packages.props`)

```xml
<!-- Directory.Packages.props — Central Package Management -->
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>
```

```xml
<!-- *.csproj -->
<PackageReference Include="Newtonsoft.Json" />
```

```bash
dotnet restore --locked-mode
```

Central Package Management (CPM) lets a single `Directory.Packages.props` pin every transitive across a solution; a `<PackageVersion>` there coerces a transitive even if no project declares it directly. `<RestoreLockedMode>true</RestoreLockedMode>` in a `.csproj` mandates `--locked-mode` behaviour. Gotcha: pre-CPM solutions have versions scattered across each `.csproj` — migrating is a one-time effort but it dramatically simplifies upgrades.

### Composer (`composer.lock`)

```bash
composer update guzzlehttp/guzzle

# Coerce a transitive: declare it directly in composer.json's require
composer update --lock
```

Composer's `composer.lock` carries per-package SHA-1 of the dist archive. To coerce a transitive, add it to `require` (production) or `require-dev` with the required version constraint — Composer resolves the constraint against the entire graph. Conflict declarations (`conflict` key in `composer.json`) make Composer refuse to install a specific (vulnerable) version range. Gotcha: Composer's autoloader caches aggressively; `composer dump-autoload -o` after an upgrade if you see stale class resolutions.

### SwiftPM (`Package.resolved`)

```swift
// Package.swift
.package(url: "https://github.com/apple/swift-nio.git", exact: "2.65.0"),

// Or for a version range:
.package(url: "...", .upToNextMajor(from: "2.0.0")),
```

```bash
swift package update
swift package resolve   # write Package.resolved without building
```

`exact()` is the strictest constraint; `upToNextMajor` and `upToNextMinor` give caret-style ranges. `Package.resolved` records the resolved git SHA per dep. Transitive coercion isn't a first-class feature — declare the package directly with `exact()`. Gotcha: SwiftPM's resolver is slow on large graphs; consider committing `Package.resolved` to avoid re-resolving in CI.

### CocoaPods (`Podfile.lock`)

```ruby
# Podfile
pod 'Alamofire', '5.9.1'
pod 'Starscream', '~> 4.0'   # coerce transitive by declaring directly
```

```bash
pod update Alamofire
pod install --deployment   # frozen install
```

CocoaPods' lockfile records the resolved version per pod. Coercion follows the Bundler pattern — declare the transitive directly in the Podfile. Gotcha: `pod install` vs `pod update` semantics — `install` honours the lockfile, `update` re-resolves.

### Carthage (`Cartfile.resolved`)

```bash
carthage update Alamofire --use-xcframeworks
```

Carthage is simpler than SwiftPM/CocoaPods — fewer features, less drift. Resolution is direct; coercion is by editing the `Cartfile`. Gotcha: Carthage builds frameworks from source; an upgrade can break ABI compatibility with downstream consumers if the platform version is bumped.

### Dart pub (`pubspec.lock`)

```yaml
# pubspec.yaml
dependencies:
  http: ^1.1.0

dependency_overrides:
  http: 1.2.0   # coerce a transitive
```

```bash
dart pub upgrade http
dart pub get
```

`dependency_overrides` is the explicit transitive coercion mechanism — it sits at the project level and applies regardless of where in the graph the dep is requested. Gotcha: overrides only take effect in the project where they're declared; published packages can't use them.

### Mix (Elixir) (`mix.lock`)

```elixir
# mix.exs
defp deps do
  [
    {:phoenix, "~> 1.7.0"},
    {:plug, "~> 1.15", override: true}   # coerce transitive
  ]
end
```

```bash
mix deps.update plug
mix deps.get --check-locked
```

`override: true` is the coercion flag — without it, Mix refuses to resolve a dep that conflicts with a transitive's declared range. The lockfile carries the git SHA + the SHA-256 of the package tarball. Gotcha: Hex package signatures are verifiable but disabled by default; enable with `HEX_OFFLINE=1` and pre-fetched packages for fully offline CI.

### Rebar3 (Erlang) (`rebar.lock`)

```erlang
%% rebar.config
{deps, [
    {jiffy, "1.1.1"}
]}.
{overrides, [{override, jiffy, [{deps, [...]}]}]}.
```

```bash
rebar3 upgrade jiffy
```

`{overrides, ...}` in `rebar.config` is the coercion mechanism — it operates at the rebar3 level rather than as a per-dep override.

### Cabal / Stack (Haskell) (`cabal.project.freeze` / `stack.yaml.lock`)

```yaml
# stack.yaml
resolver: lts-22.0
extra-deps:
  - aeson-2.2.1.0      # coerce transitive by including in extra-deps
```

For Cabal: `cabal.project.freeze` is produced by `cabal freeze` and contains `constraints:` for every resolved version. To coerce a transitive, add a constraint line to `cabal.project` and re-freeze.

Gotcha: Haskell's ecosystem prefers Stackage-curated resolvers — `lts-XX.YY` snapshots — over open resolution. Transitive coercion via `extra-deps` (Stack) or `constraints` (Cabal) is the escape hatch.

### opam (OCaml)

```bash
opam install package=1.2.3
opam lock -f my-project.opam.lock
```

`opam lock` is a plugin that writes a `*.opam.lock` file with pinned versions and source URLs. Coercion is by adding `package {= "1.2.3"}` to the `depends:` field of the `*.opam` file.

### Nix flakes (`flake.lock`)

```bash
nix flake lock --update-input nixpkgs
nix flake lock --update-input my-dep --override-input my-dep github:my/fork
```

`flake.lock` pins each input's git revision and `narHash`. The `--override-input` flag is the coercion mechanism — it redirects an input to a different source, useful for testing a patched upstream. Gotcha: `follows` resolution can cause an input you pinned to be silently overridden by a parent's `follows` declaration; trace with `nix flake metadata --json | jq`.

### Conan (C/C++) (`conan.lock`)

```bash
conan install . --lockfile=conan.lock --lockfile-out=conan.lock --lockfile-overrides='{"openssl/*": "openssl/3.2.1"}'
```

Conan's lockfile is JSON, records resolved versions plus build options. `--lockfile-overrides` coerces a transitive at install time. Coercion can also be done by declaring the transitive in `[requires]` of `conanfile.py` with `override=True`.

### vcpkg (C/C++) (`vcpkg.json`, `vcpkg-configuration.json`)

```json
{
  "name": "my-project",
  "version": "1.0.0",
  "dependencies": ["fmt", "openssl"],
  "overrides": [
    { "name": "openssl", "version": "3.2.1" }
  ]
}
```

The `overrides[]` array in `vcpkg.json` pins exact versions across the entire graph. `vcpkg-configuration.json` selects a baseline (a git SHA of the vcpkg registry) so that resolution is reproducible.

## Transitive coercion — quick-reference table

| Manager | Mechanism |
|---|---|
| npm | `overrides` in `package.json` |
| pnpm | `pnpm.overrides` + `peerDependencyRules` in `package.json` |
| Yarn | `resolutions` in `package.json` (supports glob paths) |
| pip-tools | Pin in `requirements.in`, recompile |
| Pipenv | Add to `[packages]` in `Pipfile` |
| Poetry | Declare in `[tool.poetry.dependencies]` |
| uv | Declare in `pyproject.toml` `[project.dependencies]` |
| Go modules | `replace` directive in `go.mod` |
| Cargo | `[patch.crates-io]` in `Cargo.toml` |
| Maven | `<dependencyManagement>` in root `pom.xml` |
| Gradle | `dependencies.constraints` + `enforcedPlatform()` |
| Bundler | Explicit `gem` declaration in `Gemfile` |
| NuGet | `<PackageVersion>` in `Directory.Packages.props` (CPM) |
| Composer | Add to `require` in `composer.json` |
| SwiftPM | Declare package directly with `exact()` |
| CocoaPods | Declare `pod` directly in `Podfile` |
| Dart pub | `dependency_overrides` in `pubspec.yaml` |
| Mix | `override: true` on the dep tuple in `mix.exs` |
| Rebar3 | `{overrides, ...}` in `rebar.config` |
| Cabal | `constraints:` in `cabal.project` |
| Stack | Add to `extra-deps` in `stack.yaml` |
| opam | `package {= "x.y.z"}` in the `*.opam` `depends:` field |
| Nix flakes | `--override-input` or `follows` in `flake.nix` |
| Conan | `override=True` in `[requires]` or `--lockfile-overrides` |
| vcpkg | `overrides[]` in `vcpkg.json` |

## Reachability analysis — by language

The question is always the same: *is the vulnerable function in the dependency actually called from any code path that runs in production?* If not, OpenVEX `not_affected` with `vulnerable_code_not_in_execute_path` is the honest answer and saves you from a noisy upgrade.

The practical rule: combine a **static check** (does our code import the vulnerable symbol?) with a **dynamic check** (does the code that imports it actually run under coverage?). If both come back negative, you have evidence for the VEX.

### JavaScript / TypeScript

- Static: `npm ls <pkg> --all` walks the dep tree to show every path that pulls in the pkg. `madge --image graph.svg src/` visualises the import graph of your own code.
- Bundler analysis: `esbuild --bundle --metafile=meta.json src/index.ts` produces a JSON metafile listing every imported symbol; `grep` for the vulnerable function name confirms reach.
- Runtime: c8 / nyc coverage during integration tests. If the file that imports the vulnerable lib never gets covered, the static reach is dead in practice.

### Python

- Static: `pip show <pkg>` shows direct/transitive relationships. `pydeps <module>` renders the import graph. `python -c "import sys; print('vuln_fn' in dir(__import__('pkg')))"` confirms the symbol exists.
- Reachability: `coverage.py` with `--branch` during a representative test run. A module imported but never run is `vulnerable_code_not_in_execute_path`.

### Java

- Static: `mvn dependency:tree -Dincludes=group:artifact` shows the path. `jdeps --multi-release 17 --print-module-deps target/myapp.jar` reports class-level reachability. For full static analysis: SootUp or WALA produce a call graph; query for the vulnerable method's class+signature.
- Runtime: JaCoCo coverage on integration tests. If the class containing the vuln isn't covered, document it.

### Go

- Static: `go mod why <module>` produces the import chain from your main module to a target. `go list -deps -json ./... | jq` walks every transitive. `go tool callgraph -algo=cha` from `golang.org/x/tools/cmd/callgraph` produces a static call graph.
- Runtime: `go test -coverprofile=cover.out ./... && go tool cover -html=cover.out`.

### Rust

- Static: `cargo tree -p <crate> -e features --invert` shows what depends on the crate. `cargo-callgraph` or `cargo-modules` for symbol-level analysis.
- Runtime: `cargo tarpaulin` for coverage, or `cargo llvm-cov` on nightly.

### Ruby

- Static: `bundle viz` produces a Graphviz of the gem graph. `bundle show --paths` lists every gem's source. For call analysis: `ruby-static-analyzer` or runtime tracing with `TracePoint`.
- Runtime: SimpleCov.

### C# / .NET

- Static: `dotnet list package --include-transitive` enumerates the graph. Roslyn analyzers (`Microsoft.CodeAnalysis`) can query for method calls; `dotnet build /p:RunAnalyzers=true`.
- Runtime: dotCover or `coverlet` integrated with `dotnet test`.

### PHP

- Static: `composer show -t <pkg>` produces a tree. `phpcallgraph` for method-level reachability.
- Runtime: Xdebug code coverage.

### C / C++

- Static: linker map (`gcc -Wl,--print-map`), then `nm`, `readelf`, or `objdump` for symbol enumeration. `cflow` for source-level call graphs.
- Runtime: Valgrind callgrind (`valgrind --tool=callgrind`) under a representative load.

### Swift

- Static: `swift package show-dependencies --format json | jq` for the resolved graph. The Xcode call graph instrument shows runtime call edges.
- Runtime: `xcodebuild -enableCodeCoverage YES`.

### Dart

- Static: `dart pub deps` lists the graph. `dart analyze` for symbol-level analysis.
- Runtime: `dart test --coverage`.

### Elixir

- Static: `mix xref graph --format dot` for cross-module call graph. `mix xref callers <module>.<function>/<arity>` answers reachability directly.
- Runtime: `mix coveralls`.

### What constitutes evidence

A clean negative on both static (function not imported or imported but only in dead branches) and dynamic (file containing the call site has no test or production coverage) is enough to write a CycloneDX VEX with:

```json
"analysis": {
  "state": "not_affected",
  "justification": "code_not_reachable",
  "detail": "Static analysis with <tool> shows <vulnerable.function> is imported via <path> but not called. Runtime coverage under <test suite> confirms the importing module is never executed in production code paths. Verified <date>."
}
```

The bar is *evidence*, not certainty — auditors and future-you both want to see the methodology, not just the conclusion.

## Worked example: CVE-2021-44228 (Log4Shell)

The shape of the relevant slice of `.vulnetix/sbom.cdx.json`:

```json
{
  "components": [
    { "bom-ref": "log4j-core@2.14.1", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "version": "2.14.1" }
  ],
  "dependencies": [
    { "ref": "myapp@1.0.0", "dependsOn": ["spring-boot-starter-web@2.5.6"] },
    { "ref": "spring-boot-starter-web@2.5.6", "dependsOn": ["spring-boot-starter-logging@2.5.6"] },
    { "ref": "spring-boot-starter-logging@2.5.6", "dependsOn": ["log4j-core@2.14.1"] }
  ],
  "vulnerabilities": [
    { "id": "CVE-2021-44228", "affects": [{ "ref": "log4j-core@2.14.1" }] }
  ]
}
```

Extract the chain from the real artefact:

```bash
# Confirm the finding is present
jq '.vulnerabilities[] | select(.id == "CVE-2021-44228")' .vulnetix/sbom.cdx.json

# Trace the chain up to the root
jq --arg target "log4j-core@2.14.1" '
  def ancestors($t):
    .dependencies[]
    | select(.dependsOn | index($t))
    | .ref ;
  [ancestors($target)]
' .vulnetix/sbom.cdx.json
# → ["spring-boot-starter-logging@2.5.6"]

# Run again with the parent to keep walking
jq --arg target "spring-boot-starter-logging@2.5.6" '
  [.dependencies[] | select(.dependsOn | index($target)) | .ref]
' .vulnetix/sbom.cdx.json
# → ["spring-boot-starter-web@2.5.6"]
# → eventually reaches "myapp@1.0.0" (your top-level)
```

Two coercion paths:

{{< tabs >}}
{{< tab name="bump Spring Boot" >}}
```xml
<parent>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-parent</artifactId>
  <version>2.7.18</version>
</parent>
```
This bumps the Spring Boot BOM which in turn upgrades log4j-core to a safe version.
{{< /tab >}}
{{< tab name="pin log4j-core directly" >}}
```xml
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.17.1</version>
    </dependency>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-api</artifactId>
      <version>2.17.1</version>
    </dependency>
  </dependencies>
</dependencyManagement>
```
This pins log4j-core even when Spring Boot's BOM resolves an older version. Use when you can't bump Spring Boot for compatibility reasons.
{{< /tab >}}
{{< /tabs >}}

Now build the reachability check. The right starting point is what Vulnetix itself knows about the vuln — pull the structured intel and find the affected class/function name to grep for.

```bash
# Fetch the full advisory enrichment
vulnetix vdb vuln CVE-2021-44228 --output json > /tmp/cve.json

# Severity + KEV + EPSS in one shot (the "is this urgent?" view)
jq '.[0].containers.adp[0] | {
      exploitation: .x_exploitationMaturity.level,
      epss: .x_exploitationMaturity.factors.epss,
      kev_listed: .x_kev.knownRansomwareCampaignUse,
      ssvc: .x_ssvc.decision,
      attack_surface: .x_attackSurface.reasoning,
      cwes: .x_kev.cwes
    }' /tmp/cve.json
# →  {
#      "exploitation": "ACTIVE",
#      "epss": 0.94,
#      "kev_listed": "Known",
#      "ssvc": "Act",
#      "attack_surface": "Remotely exploitable; Low complexity; No privileges; No user interaction",
#      "cwes": ["CWE-20", "CWE-400", "CWE-502"]
#    }

# Pull the patch PR — the source of truth for which class/method changed
vulnetix vdb fixes CVE-2021-44228 --output json > /tmp/fixes.json

# Source-code patches (the URLs whose diffs name the affected class)
jq '.fixes.sourceCode[] | select(.type == "pr") | .url' /tmp/fixes.json | sort -u
# →  "https://github.com/apache/logging-log4j2/pull/608"
#    "https://github.com/github/advisory-database/pull/5501"

# CWE-keyed remediation guidance
jq '.cweRemediations[]' /tmp/fixes.json
# →  "Mitigate CWE-917: Review and apply appropriate controls"

# KEV-required action (CISA's official wording — useful for tickets / compliance)
jq -r '.kevRequiredAction' /tmp/fixes.json
```

Read the linked patch PR (`apache/logging-log4j2#608`); it names `org.apache.logging.log4j.core.lookup.JndiLookup` as the class to gate behind a `formatMsgNoLookups=true` flag. That class name is what you grep your codebase for:

```bash
# Static: is JndiLookup actually reachable from your built artefact?
jdeps --multi-release 17 --print-module-deps target/myapp.jar 2>&1 \
  | grep -i 'log4j.core.lookup'

# Source-level: do you log anything from request data without scrubbing?
git grep -nE 'logger\.(info|warn|error|debug|trace)\([^)]*(request|req\.|input|userAgent|param)' \
  src/main/java/

# Find any log4j2.properties / log4j2.xml that set formatMsgNoLookups
git grep -nE 'formatMsgNoLookups|log4j2.formatMsgNoLookups' .

# Did the build's log4j-core actually load? (CycloneDX dependencies graph)
jq '.dependencies[] | select(.dependsOn | index("log4j-core@2.14.1"))' .vulnetix/sbom.cdx.json
```

If the app uses Logback (Spring Boot's default) and log4j-core is only on the classpath as a transitive — `JndiLookup` never instantiated, no `lookup()` call site reachable from request input — `vulnerable_code_not_in_execute_path` is honest. The grep evidence + the jdeps output is what goes in the `analysis.detail` of the VEX.

{{< outcome type="cyclonedx" >}}
```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2021-44228",
      "affects": [
        { "ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1",
          "versions": [
            { "version": "2.14.1", "status": "affected" },
            { "version": "2.17.1", "status": "unaffected" }
          ] }
      ],
      "analysis": {
        "state": "resolved",
        "detail": "Pinned log4j-core to 2.17.1 in pom.xml's <dependencyManagement>. mvn dependency:tree confirms no transitive still resolves a vulnerable version. Spring Boot stays on 2.5.6 for compatibility. See MR !128."
      }
    }
  ]
}
```
{{< /outcome >}}

## Worked example: CVE-2022-23541 (jsonwebtoken)

Vulnetix flags `pkg:npm/jsonwebtoken@8.5.1`. Confirm and trace from the SBOM:

```bash
jq '.vulnerabilities[] | select(.id == "CVE-2022-23541")' .vulnetix/sbom.cdx.json

# Every direct parent of jsonwebtoken@8.5.1
jq --arg target "jsonwebtoken@8.5.1" \
   '[.dependencies[] | select(.dependsOn | index($target)) | .ref]' \
   .vulnetix/sbom.cdx.json
```

`npm ls jsonwebtoken` confirms the same paths in human-readable form:

```
yourapp@1.0.0
├─┬ express-jwt@7.0.0
│ └── jsonwebtoken@8.5.1
├─┬ next-auth@4.10.0
│ └── jsonwebtoken@8.5.1
└─┬ jose-helper@2.1.0
  └── jsonwebtoken@8.5.1
```

Three top-level libraries all transit jsonwebtoken. Coerce once:

{{< tabs >}}
{{< tab name="npm" >}}
```json
{
  "overrides": {
    "jsonwebtoken": "^9.0.2"
  }
}
```
{{< /tab >}}
{{< tab name="yarn" >}}
```json
{
  "resolutions": {
    "jsonwebtoken": "^9.0.2"
  }
}
```
{{< /tab >}}
{{< tab name="pnpm" >}}
```json
{
  "pnpm": {
    "overrides": {
      "jsonwebtoken": "^9.0.2"
    }
  }
}
```
{{< /tab >}}
{{< /tabs >}}

Reachability: search the source for `jwt.verify` and `jwt.decode` call sites; check whether any use a JWT that originated from an attacker-controllable channel. If only used for first-party-issued service tokens with HS256 + a known issuer, the algorithm-confusion vector is contained.

{{< outcome type="cyclonedx" >}}
```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2022-23541",
      "affects": [
        { "ref": "pkg:npm/jsonwebtoken@9.0.2",
          "versions": [
            { "version": "8.5.1", "status": "affected" },
            { "version": "9.0.2", "status": "unaffected" }
          ] }
      ],
      "analysis": {
        "state": "resolved",
        "detail": "Coerced jsonwebtoken to 9.0.2 via package.json overrides. All three transit paths (express-jwt, next-auth, jose-helper) now resolve 9.0.2. Verified with npm ls jsonwebtoken. See MR !302."
      }
    }
  ]
}
```
{{< /outcome >}}

## Worked example: CVE-2024-3094 (xz-utils backdoor)

This is qualitatively different. The package isn't vulnerable in the CVE sense — it was deliberately backdoored. Vulnetix fires through `--block-malware`, not just `--severity`:

```bash
vulnetix scan --block-malware
# Exit 1: pkg:generic/xz-utils@5.6.0 — malware indicator
```

The action sequence is incident response, not a normal upgrade:

1. **Downgrade immediately** to a known-clean version (`5.4.6` is the pre-backdoor branch).
2. **Audit any build host or developer machine** that pulled the affected version. If the affected version was installed, treat the host as potentially compromised — rotate SSH keys, audit auth logs, check for unexpected processes.
3. **Audit any binary built on an affected host** — the backdoor was sshd-targeted but in principle could have affected anything linked against the compromised liblzma.
4. **Document the rollback** in the CycloneDX VEX, not just the upgrade.

{{< outcome type="cyclonedx" >}}
```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2024-3094",
      "affects": [
        { "ref": "pkg:generic/xz-utils@5.4.6",
          "versions": [
            { "version": "5.6.0", "status": "affected" },
            { "version": "5.6.1", "status": "affected" },
            { "version": "5.4.6", "status": "unaffected" }
          ] }
      ],
      "analysis": {
        "state": "resolved",
        "detail": "Rolled back xz-utils from 5.6.0 to 5.4.6 on 2024-03-29 across all build images. Audited build hosts for evidence of exploitation (none found). Rotated SSH host keys on affected runners. See incident INC-2024-014."
      }
    }
  ]
}
```
{{< /outcome >}}

## EOL gating and `--block-eol`

EOL findings don't have a CVE — the runtime or package is simply past its support window, so no patches will be issued for future vulnerabilities. Vulnetix flags these via the embedded EOL database. Check ad-hoc:

```bash
vulnetix vdb eol package npm jsonwebtoken 8.5.1
vulnetix vdb eol product python 3.7
```

Three actions are possible:

1. **Upgrade past EOL** — usually the right answer. Plan it as a deliberate piece of work, not a rushed fix.
2. **Accept and document** — sometimes business reality means the runtime stays on an EOL version. The OpenVEX statement is `affected` with a clear `action_statement` naming the compensating controls (isolated network, no internet access, manual security patches).
3. **Decommission** — for a service no longer worth maintaining, replace or retire.

EOL findings always go to **OpenVEX**, not CycloneDX VEX — the subject is the deployment / runtime, not a packaged component with a vulnerability advisory.

## Producing the CycloneDX VEX

Field-by-field reference, then three full examples covering the common analysis states.

| Field | Value |
|---|---|
| `vulnerabilities[].id` | The CVE / GHSA / vendor ID |
| `vulnerabilities[].source.name` | `NVD`, `GitHub`, `OSV`, etc. |
| `vulnerabilities[].ratings[]` | Severity + method (`CVSSv3`, `CVSSv4`) |
| `vulnerabilities[].affects[].ref` | The PURL of the affected component (matches an SBOM `bom-ref`) |
| `vulnerabilities[].affects[].versions[]` | Per-version `status: affected\|unaffected` |
| `vulnerabilities[].analysis.state` | `not_affected`, `in_triage`, `exploitable`, `resolved`, `resolved_with_pedigree`, `false_positive` |
| `vulnerabilities[].analysis.justification` | When `not_affected`: `code_not_present`, `code_not_reachable`, `requires_configuration`, `requires_dependency`, `requires_environment`, `protected_by_compiler`, `protected_at_runtime`, `protected_at_perimeter`, `protected_by_mitigating_control` |
| `vulnerabilities[].analysis.response[]` | When `exploitable`: `will_not_fix`, `update`, `rollback`, `workaround_available`, `can_not_fix` |
| `vulnerabilities[].analysis.detail` | Free-text explanation — the field future-you will actually read |

{{< tabs >}}
{{< tab name="not_affected" >}}
```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2024-12345",
      "affects": [{ "ref": "pkg:npm/vulnerable-lib@1.2.3" }],
      "analysis": {
        "state": "not_affected",
        "justification": "code_not_reachable",
        "detail": "vulnerable-lib's parseXML() is imported by our request validator but the validator's XML branch is dead code — the application uses JSON exclusively. Verified in MR !88 with a coverage report showing parseXML never executes in the production build."
      }
    }
  ]
}
```
{{< /tab >}}
{{< tab name="exploitable + workaround" >}}
```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2024-12345",
      "affects": [{ "ref": "pkg:npm/vulnerable-lib@1.2.3" }],
      "analysis": {
        "state": "exploitable",
        "response": ["workaround_available"],
        "detail": "ModSecurity rule 10001 blocks the path-traversal vector at the WAF. Rule deployed 2026-05-14. Patch upgrade to vulnerable-lib@1.2.4 tracked in issue #99 for sprint 24."
      }
    }
  ]
}
```
{{< /tab >}}
{{< tab name="resolved" >}}
```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2024-12345",
      "affects": [{
        "ref": "pkg:npm/vulnerable-lib@1.2.4",
        "versions": [
          { "version": "1.2.3", "status": "affected" },
          { "version": "1.2.4", "status": "unaffected" }
        ]
      }],
      "analysis": {
        "state": "resolved",
        "detail": "Upgraded vulnerable-lib from 1.2.3 to 1.2.4 in commit abc1234. Coerced via package.json overrides because the dep is transitive through three different runtime libraries. See MR !42."
      }
    }
  ]
}
```
{{< /tab >}}
{{< /tabs >}}
