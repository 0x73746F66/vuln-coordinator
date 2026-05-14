---
title: "GitLab Dependency Scanning"
description: "GitLab's built-in dependency scanner — runs on every pipeline, surfaces in the MR."
weight: 30
---

## What GitLab Dependency Scanning does

<!-- TODO: One paragraph. GitLab's Dependency Scanning job (part of the Secure stage) resolves manifest files in the repo, queries the GitLab Advisory Database, and writes a `gl-dependency-scanning-report.json` artefact. Findings surface in the MR widget, the security dashboard, and the vulnerability report. -->

## Reading the output

<!-- TODO: The `gl-dependency-scanning-report.json` artefact is the canonical source. The MR widget is a UI summary on top. Show one `vulnerabilities[]` entry, which carries `cve`, `id`, `category: "dependency_scanning"`, `location.dependency.package.name` + `.version`, `severity`, and `solution`. -->

## What you can act on

<!-- TODO: `vulnerabilities[].cve` or `.identifiers[]` for the canonical ID, `location.dependency.package.name` + `.version` for the affected component, `severity`, `solution` (often a target version), `location.file` for the manifest. -->

## Decision tree

{{< decision >}}
Is the vulnerable package declared in your SBOM?
  ├─ Yes → CycloneDX VEX entry referencing the PURL
  └─ No  → OpenVEX statement (lockfile-resolved transitive not in SBOM)

Is the risk mitigated by a WAF, IPS, or SIEM rule?
  └─ If yes, status is `affected` with `workaround_available` and the rule reference
{{< /decision >}}

## Producing a CycloneDX VEX

<!-- TODO: Worked example. Map `location.dependency.package` to the PURL, attach the CVE, set `analysis.state`. -->

## Producing an OpenVEX

<!-- TODO: Worked example for SBOMs that only list direct deps. Subject is the project, vulnerability is the CVE or GitLab identifier, action_statement names the decision. -->
