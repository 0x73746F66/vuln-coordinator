---
title: "Snyk SAST"
description: "Snyk Code — taint-flow static analysis of your source, not your dependencies."
weight: 20
---

## What Snyk SAST does

<!-- TODO: One paragraph. Snyk Code (the SAST product, distinct from Snyk OSS) parses your source, builds a code graph, and flags taint-flow paths matching its library of weakness patterns — CWE-mapped. Triggered by `snyk code test` in CI or the IDE plugin. Output is JSON, SARIF, or an MR comment. -->

## Reading the output

<!-- TODO: SARIF is the canonical interop format and the source of truth for VEX work. Show what one `runs[].results[]` entry looks like — it carries `ruleId`, the CWE, `level` (note/warning/error mapped from severity), and `locations[].physicalLocation` (file + line range). The `flows[]` array shows the taint path source → sink. -->

## What you can act on

<!-- TODO: `ruleId` and `properties.cwe[]` for classification, `level` for severity, `locations[].physicalLocation.artifactLocation.uri` + `region.startLine` for the spot in the code, `codeFlows[]` if you need to follow the data flow from input to sink. -->

## Decision tree

SAST findings sit in code you own, not in a packaged component. Most decisions are OpenVEX.

{{< decision >}}
Is the flagged code reachable in the deployed artefact?
  ├─ No  (test fixture, build script, dead branch) → OpenVEX `not_affected`,
  │                                                  justification `vulnerable_code_not_in_execute_path`
  └─ Yes ↓

Can the inputs that reach the sink be controlled by an attacker?
  ├─ No  (constant, validated upstream, internal-only call site) → OpenVEX `not_affected`,
  │                                                                justification `vulnerable_code_cannot_be_controlled_by_adversary`
  └─ Yes ↓

Is the path mitigated by a WAF, IPS, or SIEM rule, or by an upstream framework hardening?
  ├─ Yes → OpenVEX `affected` with `workaround_available`
  └─ No  → fix the code; OpenVEX `fixed` once the patch ships
{{< /decision >}}

## Producing a CycloneDX VEX

<!-- TODO: Only relevant when the SAST finding actually traces to a third-party library component that is in your SBOM (rare for Snyk Code, which focuses on first-party code). When it applies, reference the library by PURL. -->

## Producing an OpenVEX

<!-- TODO: The usual outcome. Subject is the repository (or commit hash); vulnerability is the Snyk rule ID combined with the CWE; `action_statement` records the reasoning and any MR / commit references. Worked example. -->
