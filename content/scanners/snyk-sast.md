---
title: "Snyk SAST"
description: "Static application security testing via Snyk Code."
weight: 20
---

## Overview

<!-- TODO: What Snyk Code analyses (source code patterns, taint flows), what it produces, where it surfaces (CI, IDE, MR decoration). -->

## Reading the report

### Report format

<!-- TODO: SARIF output, JSON output. Key fields: `ruleId`, `message`, `locations[].physicalLocation`. -->

### Key fields

<!-- TODO: How to identify the affected code path, CWE mapping, and severity. -->

## Decision tree

{{</* decision */>}}
Is this finding in code you own?
  ├─ Yes, and it is exploitable → Fix the code; no VEX needed until fixed
  ├─ Yes, but risk is accepted  → OpenVEX (not_affected or risk_accepted)
  └─ No  (third-party library)  → OpenVEX referencing upstream responsibility

Is there a WAF / SIEM rule that detects or blocks exploitation?
  └─ Yes → OpenVEX with workaround_available + rule reference
{{</* /decision */>}}

## CycloneDX VEX outcome

<!-- TODO: SAST findings are not directly linked to SBOM components (they are code-level, not package-level). Only use CycloneDX VEX if the finding traces to a known library component in the BOM. -->

## OpenVEX outcome

<!-- TODO: Primary attestation for SAST. Example OpenVEX JSON with `status: not_affected` or `status: affected`, justification, and optional workaround reference. -->
