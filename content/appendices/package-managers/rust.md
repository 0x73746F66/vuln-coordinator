---
title: "Rust — Cargo"
description: "Cargo.lock, [patch.crates-io], cargo update mechanics."
weight: 50
---

## Cargo (`Cargo.lock`)

```bash
cargo update -p reqwest

# Coerce a transitive — Cargo.toml:
#   [patch.crates-io]
#   reqwest = { version = "0.12" }
cargo update
```

`[patch.crates-io]` redirects every reference to a crate version, regardless of where in the graph it sits. For source-level patches (a fork or a local path), `[patch]` accepts `path = ...` or `git = ...`. Integrity is per-entry SHA-256.

Gotcha: `Cargo.lock` is committed for binaries but conventionally not for libraries — for an SCA fix in a library crate, the right output is a release bump rather than a lockfile change.

## Developer gotchas — written for people who live in the code

- **`Cargo.lock` is committed for binaries, ignored for libraries.** A library's downstream consumer resolves their own deps; your `Cargo.lock` doesn't ship. An SCA flag against a library crate's `Cargo.lock` only affects *your build*, not consumers — for them, publish a `Cargo.toml` bump.
- **Feature flags change the dep set drastically.** `tokio` with default features pulls in `tokio-macros`, `mio`, `socket2`, etc. With `default-features = false, features = ["sync"]`, the dep set is a tenth the size. A CVE in `mio` may not be in your build if you disabled the relevant feature.
- **`[patch.crates-io]` and `[replace]` look similar; only `[patch]` works.** `[replace]` is deprecated. Use `[patch.crates-io]` for crates-io overrides; `[patch."https://..."]` for git deps.
- **Dev-dependencies don't end up in `cargo build`'s release artefact.** `[dev-dependencies]` only compile under `cargo test` / `cargo bench`. CVE flags against them are runtime-not-affected for production binaries.
- **`build-dependencies` run on the build host.** A CVE in a `build.rs` dep (a `bindgen`, a `cc`) runs during compilation, not in your final binary. Production-runtime VEX is `vulnerable_code_not_present` if you can prove the build-dep didn't end up linked.
- **`unsafe` blocks and `extern "C"` bring in C deps invisible to `cargo`.** A CVE in `openssl-sys` may reflect a linked system OpenSSL, not Rust code. Scan the container or the linked binary, not just `Cargo.lock`.
- **Workspaces share `Cargo.lock` but not features.** In a workspace, `cargo build -p crate-a` may pick different features than `cargo build -p crate-b` even though both share the same lockfile. A feature-gated CVE in a shared dep may be reachable from one crate and dead in another.

## Reachability

- `cargo tree -p <crate> -e features --invert` shows what depends on the crate.
- `cargo-callgraph` or `cargo-modules` for symbol-level analysis.
- `cargo-udeps` flags unused dependencies (one signal that a transitive is dead in practice).
- Runtime: `cargo tarpaulin` for coverage, or `cargo llvm-cov` on nightly.
