---
title: "GitHub Dependabot"
description: "Automated dependency vulnerability alerts and security updates."
weight: 60
---

## Overview

<!-- TODO: What this scanner analyses, what it produces, how developers encounter it in CI or merge request workflows. -->

## Reading the report

### Report format

<!-- TODO: Output format (JSON, SARIF, table). Where to find the output in the pipeline or merge request. Key fields that drive triage. -->

### Key fields

<!-- TODO: The specific fields needed to identify the component/finding, severity, and affected version. -->

## Decision tree

{{</* decision */>}}
Is the affected component declared in your SBOM?
  ├─ Yes → CycloneDX VEX
  └─ No  → OpenVEX

Is the finding mitigated by a WAF / IPS rule or SIEM detection?
  └─ Yes → OpenVEX with workaround_available + rule reference
{{</* /decision */>}}

## CycloneDX VEX outcome

<!-- TODO: When to use CycloneDX VEX for this scanner's output. Example VEX document fragment. -->

## OpenVEX outcome

<!-- TODO: When to use OpenVEX for this scanner's output. Example OpenVEX document. -->
