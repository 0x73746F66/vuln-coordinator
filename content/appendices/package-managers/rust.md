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

## Reachability

- `cargo tree -p <crate> -e features --invert` shows what depends on the crate.
- `cargo-callgraph` or `cargo-modules` for symbol-level analysis.
- `cargo-udeps` flags unused dependencies (one signal that a transitive is dead in practice).
- Runtime: `cargo tarpaulin` for coverage, or `cargo llvm-cov` on nightly.
