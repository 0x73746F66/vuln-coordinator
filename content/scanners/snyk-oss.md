---
title: "Snyk OSS"
description: "Open-source dependency vulnerability scanning via Snyk."
weight: 10
---

## Overview

<!-- TODO: What Snyk OSS scans, what it produces, where developers encounter it (CI pipeline, IDE, merge request comment). -->

## Reading the report

### Report format

<!-- TODO: JSON output from `snyk test --json`, SARIF via `snyk test --sarif`, or inline table in a merge request. Key fields: `vulnerabilities[].id`, `vulnerabilities[].severity`, `vulnerabilities[].from` (dependency path). -->

### Key fields

<!-- TODO: How to map a finding to a specific component version and dependency path. -->

## Decision tree

{{</* decision */>}}
Does the vulnerable component appear in your project's SBOM?
  ├─ Yes → CycloneDX VEX  (component is a known BOM entry)
  └─ No  → OpenVEX        (transitive dep not yet in SBOM, or risk accepted at code level)

Is the vulnerability mitigated by a WAF / IPS rule or SIEM detection?
  └─ Yes → OpenVEX with `workaround_available` justification + rule reference
{{</* /decision */>}}

## CycloneDX VEX outcome

<!-- TODO: When the vulnerable package IS in the SBOM. Example CycloneDX VEX JSON showing component reference, vulnerability ID, and analysis state (e.g. `not_affected`, `in_triage`, `affected`, `fixed`). -->

## OpenVEX outcome

<!-- TODO: When the package is a transitive dependency not declared in the SBOM, or when risk is accepted at the project level. Example OpenVEX JSON. -->
