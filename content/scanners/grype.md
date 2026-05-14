---
title: "Grype"
description: "Anchore's vulnerability scanner — runs against a container image, a directory, or an SBOM."
weight: 90
---

## What Grype does

<!-- TODO: One paragraph. Grype matches components against several vulnerability databases (NVD, GitHub Advisory, Ubuntu USN, Alpine secdb, RedHat, etc.). It accepts three inputs: a container image (`grype myimage:tag`), a filesystem (`grype dir:.`), or — most useful for VEX work — an existing CycloneDX or SPDX SBOM (`grype sbom:./sbom.cdx.json`). -->

## Reading the output

<!-- TODO: JSON output via `-o json`, SARIF via `-o sarif`, or a `table` summary for humans. JSON is the source of truth for VEX work. Show what one `matches[]` entry looks like — it carries the matched artifact (with PURL), the vulnerability ID, and the match-confidence reasoning. -->

## What you can act on

<!-- TODO: `matches[].vulnerability.id`, `matches[].vulnerability.severity`, `matches[].artifact.purl`, `matches[].artifact.locations[]` (which layer of the image), `matches[].vulnerability.fix.versions[]`, `matches[].matchDetails[]` (why Grype thinks this match is real — useful for distinguishing CPE vs PURL matches when triaging false positives). -->

## Decision tree

{{< decision >}}
Grype runs against (or alongside) an SBOM, so every finding is tied to a PURL by default.

  → CycloneDX VEX entry referencing the PURL

If the matched component is in a base image layer you don't control and the upstream maintainer has published a VEX:
  → consume their VEX rather than writing your own; let `grype --vex` suppress the finding

Is the risk mitigated by a WAF, IPS, or SIEM rule?
  └─ If yes, status is `affected` with `workaround_available` and the rule reference
{{< /decision >}}

## Producing a CycloneDX VEX

<!-- TODO: Worked example. Grype's match record already contains the PURL — drop it straight into `affects[].ref` of the CycloneDX VEX entry. -->

## Producing an OpenVEX

<!-- TODO: Worked example for findings against components that aren't first-class SBOM entries (e.g., a binary copied into the image without manifest provenance). Subject is the image digest; vulnerability is the CVE. -->
