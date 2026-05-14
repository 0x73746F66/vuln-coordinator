---
title: "Package managers — patching reference"
description: "Lockfile mechanics, transitive coercion, integrity verification, and gotchas — per ecosystem."
weight: 40
layout: single
---

Once a scanner has flagged a vulnerable dependency the question becomes mechanical: which lockfile to edit, how to upgrade a direct dep, how to coerce a transitive you don't declare, how to verify integrity. The answer is different for every package manager and changes slowly enough that the reference is worth keeping in one place.

These pages cover the supported ecosystems in detail. Scanner pages (Vulnetix, Snyk OSS, GitLab Dependency Scanning, Dependabot, Grype, osv-scanner) link here from their "Producing a CycloneDX VEX" sections rather than duplicating the content.

## By language family

- **[JavaScript](javascript/)** — npm, pnpm, Yarn
- **[Python](python/)** — pip + requirements, Pipenv, Poetry, uv
- **[JVM](jvm/)** — Maven, Gradle (Java / Kotlin / Scala)
- **[.NET](dotnet/)** — NuGet (with Central Package Management)
- **[Go](go/)** — Go modules
- **[Rust](rust/)** — Cargo
- **[Ruby](ruby/)** — Bundler
- **[PHP](php/)** — Composer
- **[Swift / iOS](swift-ios/)** — SwiftPM, CocoaPods, Carthage
- **[Other ecosystems](other/)** — Dart pub, Mix (Elixir), Rebar3 (Erlang), Cabal/Stack (Haskell), opam (OCaml), Nix flakes, Conan, vcpkg

## Transitive coercion — quick-reference

The single most-used view across all managers: how to force a transitive dependency to a specific version without declaring it directly.

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

## Per-manager structure

Each per-language page follows the same shape. For every package manager covered:

- **Lockfile** — path and shape
- **Direct upgrade** — single command to bump a declared dep
- **Transitive coercion** — the platform-specific way to pin a dep you don't declare
- **Integrity** — how the lockfile binds version to hash and what verifies it
- **Gotchas** — peer-dep rules, native bindings, version drift, monorepo quirks

The patterns are practical, not academic — the goal is to give you the exact thing to type next when the scanner output names a CVE on a transitive your team has never touched.
