---
title: "GitHub Dependabot"
description: "Dependency alerts and automated upgrade pull requests, driven by the GitHub Advisory Database."
weight: 60
---

## What Dependabot does

<!-- TODO: One paragraph. Dependabot watches the dependency graph (extracted from manifest files in your repo) and matches it against the GitHub Advisory Database. It surfaces in three places: the Security tab as Dependabot alerts, automatic upgrade MRs that bump the lockfile, and the `dependabot-action` GraphQL API for programmatic access. -->

## Reading the output

<!-- TODO: For VEX work the canonical source is the GraphQL `repository.vulnerabilityAlerts` endpoint, or `gh api graphql -f query='...'`. The Security tab and the auto-generated upgrade MRs are UI views over the same data. Show what one `vulnerabilityAlert` node looks like. -->

## What you can act on

<!-- TODO: `securityVulnerability.advisory.ghsaId` + `.identifiers[].value` (GHSA + CVE), `securityVulnerability.package.name`, `vulnerableManifestPath`, `securityVulnerability.firstPatchedVersion.identifier`, `securityVulnerability.severity`. -->

## Decision tree

{{< decision >}}
Is the vulnerable package declared in your SBOM?
  ├─ Yes → CycloneDX VEX entry referencing the PURL
  └─ No  → OpenVEX statement (transitive not in SBOM, or dev-only dep)

Has the auto-upgrade MR been merged?
  └─ If yes, the matching VEX entry sets `analysis.state: fixed` and the merge commit becomes the action evidence

Is the risk mitigated by a WAF, IPS, or SIEM rule?
  └─ If yes, status is `affected` with `workaround_available` and the rule reference
{{< /decision >}}

## Producing a CycloneDX VEX

<!-- TODO: Worked example. Dependabot's GHSA + CVE both go into `vulnerabilities[].id` and `.references[]`. Reference the PURL from your SBOM. -->

## Producing an OpenVEX

<!-- TODO: Worked example for dev-only deps (the SBOM is production-only) or accepted risks. Subject is the repo; vulnerability is the GHSA; action_statement references the Dependabot alert URL. -->
