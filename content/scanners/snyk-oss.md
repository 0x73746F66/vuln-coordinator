---
title: "Snyk OSS"
description: "Open-source dependency vulnerability scanning across npm, PyPI, Maven, Go, Cargo, RubyGems and Packagist."
weight: 10
---

## What Snyk OSS does

<!-- TODO: One paragraph. Snyk OSS resolves the declared dependency tree (from `package-lock.json`, `requirements.txt`, `pom.xml`, `go.sum`, etc.) and matches each component against the Snyk vulnerability database. Triggered by `snyk test` in CI, the IDE plugin, or `snyk monitor` for continuous tracking. Output is JSON or SARIF. -->

## Reading the output

<!-- TODO: Where to find the report — the CI job artefact (`snyk-results.json`), the merge request comment summary, or the Snyk dashboard if you `snyk monitor` from CI. Pick one as the canonical source; for VEX work, the JSON is the source of truth. Show what one `vulnerabilities[]` entry looks like. -->

## What you can act on

<!-- TODO: Useful fields: `id` (SNYK-XXX or CVE), `severity`, `packageName` + `version`, `from[]` (the dependency path showing how a transitive ended up in your build), `upgradePath[]` (which top-level bump fixes it), `isPatchable`, `fixedIn[]`. Ignore the rest until you need it. -->

## Decision tree

{{< decision >}}
Is the vulnerable package declared in your SBOM?
  ├─ Yes → CycloneDX VEX entry referencing the PURL
  └─ No  → OpenVEX statement (transitive dep not declared, or build-time-only tool)

Is the risk mitigated by a WAF, IPS, or SIEM rule?
  └─ If yes, status is `affected` with `workaround_available` and the rule reference
{{< /decision >}}

## Producing a CycloneDX VEX

<!-- TODO: Snyk OSS findings map cleanly to SBOM components, so the CycloneDX VEX entry references the same PURL as the SBOM, the Snyk or CVE identifier, and an `analysis.state` of `not_affected` / `affected` / `fixed`. Show a worked example. -->

## Producing an OpenVEX

<!-- TODO: For cases where the package isn't in the SBOM — direct-only SBOM, or a build-time tool not shipped with the artefact. Subject is the project; vulnerability is the Snyk ID; action_statement names the decision. -->
