---
title: "osv-scanner"
description: "Google's scanner against the OSV.dev database — fast, manifest-driven, no account needed."
weight: 100
---

## What osv-scanner does

<!-- TODO: One paragraph. osv-scanner reads lockfiles (`package-lock.json`, `Cargo.lock`, `go.sum`, `Gemfile.lock`, `poetry.lock`, etc.) or a directory tree, normalises each component to a PURL, and queries the OSV.dev API for known advisories. No account, no telemetry, single static binary — easy to drop into CI. -->

## Reading the output

<!-- TODO: JSON via `--format json`, SARIF via `--format sarif`, table for humans. The JSON `results[].packages[].vulnerabilities[]` array is what you'll consume for VEX work. Each entry contains the OSV record verbatim — including `affected[].package.purl`, `aliases[]` (CVE / GHSA / others), and `database_specific.severity`. -->

## What you can act on

<!-- TODO: `vulnerabilities[].id` (typically `GHSA-...` or `CVE-...`), `aliases[]` (cross-references), `affected[].package.purl`, `affected[].package.name` + ecosystem, `affected[].ranges[].events[]` (introduced and fixed versions), `database_specific.severity`. -->

## Decision tree

{{< decision >}}
osv-scanner emits PURLs by default, so findings tie directly to SBOM components.

  → CycloneDX VEX entry referencing the PURL

Is the vulnerability published with a VEX or VEX-equivalent statement (some OSV records carry `database_specific.cwe_ids` or upstream `not_affected` notes)?
  └─ Re-use upstream evidence rather than re-investigating

Is the risk mitigated by a WAF, IPS, or SIEM rule?
  └─ If yes, status is `affected` with `workaround_available` and the rule reference
{{< /decision >}}

## Producing a CycloneDX VEX

<!-- TODO: Worked example. Drop the OSV `affected[].package.purl` straight into `affects[].ref`; use `aliases[]` to populate `vulnerabilities[].references[]`. -->

## Producing an OpenVEX

<!-- TODO: Worked example for accepted-risk decisions or for findings against unmanifested components (rare for osv-scanner, but possible when scanning a directory of mixed binaries). -->
