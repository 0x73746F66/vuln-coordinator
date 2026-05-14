---
title: "Other ecosystems"
description: "Dart pub, Mix, Rebar3, Cabal/Stack, opam, Nix flakes, Conan, vcpkg."
weight: 100
---

The less-common ecosystems Vulnetix supports, gathered into one reference.

## Dart pub (`pubspec.lock`)

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

Reachability: `dart pub deps` lists the graph; `dart analyze` for symbol-level analysis; coverage via `dart test --coverage`.

## Mix (Elixir) (`mix.lock`)

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

Reachability: `mix xref graph --format dot` for cross-module call graph; `mix xref callers <module>.<function>/<arity>` answers reachability directly; runtime via `mix coveralls`.

## Rebar3 (Erlang) (`rebar.lock`)

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

## Cabal / Stack (Haskell) (`cabal.project.freeze` / `stack.yaml.lock`)

```yaml
# stack.yaml
resolver: lts-22.0
extra-deps:
  - aeson-2.2.1.0      # coerce transitive by including in extra-deps
```

For Cabal: `cabal.project.freeze` is produced by `cabal freeze` and contains `constraints:` for every resolved version. To coerce a transitive, add a constraint line to `cabal.project` and re-freeze.

Gotcha: Haskell's ecosystem prefers Stackage-curated resolvers — `lts-XX.YY` snapshots — over open resolution. Transitive coercion via `extra-deps` (Stack) or `constraints` (Cabal) is the escape hatch.

## opam (OCaml)

```bash
opam install package=1.2.3
opam lock -f my-project.opam.lock
```

`opam lock` is a plugin that writes a `*.opam.lock` file with pinned versions and source URLs. Coercion is by adding `package {= "1.2.3"}` to the `depends:` field of the `*.opam` file.

## Nix flakes (`flake.lock`)

```bash
nix flake lock --update-input nixpkgs
nix flake lock --update-input my-dep --override-input my-dep github:my/fork
```

`flake.lock` pins each input's git revision and `narHash`. The `--override-input` flag is the coercion mechanism — it redirects an input to a different source, useful for testing a patched upstream.

Gotcha: `follows` resolution can cause an input you pinned to be silently overridden by a parent's `follows` declaration; trace with `nix flake metadata --json | jq`.

## Conan (C/C++) (`conan.lock`)

```bash
conan install . --lockfile=conan.lock --lockfile-out=conan.lock \
  --lockfile-overrides='{"openssl/*": "openssl/3.2.1"}'
```

Conan's lockfile is JSON, records resolved versions plus build options. `--lockfile-overrides` coerces a transitive at install time. Coercion can also be done by declaring the transitive in `[requires]` of `conanfile.py` with `override=True`.

## vcpkg (C/C++) (`vcpkg.json`, `vcpkg-configuration.json`)

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

## C/C++ reachability (Conan / vcpkg)

- Static: linker map (`gcc -Wl,--print-map`), then `nm`, `readelf`, or `objdump` for symbol enumeration.
- `cflow` for source-level call graphs.
- Runtime: Valgrind callgrind (`valgrind --tool=callgrind`) under a representative load.
