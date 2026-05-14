---
title: "GitHub CodeQL"
description: "Semantic query-based SAST — builds a relational model of your code and asks security questions of it."
weight: 80
---

## What CodeQL does

<!-- TODO: One paragraph. CodeQL extracts a database from your code (per language) and runs queries from the standard query packs against it. Findings surface as code scanning alerts on the Security tab and as MR annotations. The CI step runs in a GitHub Actions workflow using the `github/codeql-action` family of actions — note: this is the one place we accept a vendor action because the alternative is shipping the CodeQL CLI yourself, which is awkward. -->

## Reading the output

<!-- TODO: SARIF 2.1.0 is the native output and what GitHub stores. Pull a SARIF file via `gh api ` or via the analysis artefact in the workflow run. Show what one `results[]` entry looks like — `ruleId`, `level`, `locations[]`, `codeFlows[]` (the source → sink path that triggered the query). -->

## What you can act on

<!-- TODO: `ruleId` (the CodeQL query that fired — e.g. `js/sql-injection`), `properties.tags[]` (CWE classification), `level`, `locations[].physicalLocation`, `partialFingerprints` (useful for tracking the same finding across commits). -->

## Decision tree

CodeQL findings are code-level, not component-level. Almost all decisions are OpenVEX.

{{< decision >}}
Is the flagged code reachable in the deployed artefact?
  ├─ No  → OpenVEX `not_affected`, justification `vulnerable_code_not_in_execute_path`
  └─ Yes ↓

Can the input controlling the source taint be reached from an external boundary?
  ├─ No  → OpenVEX `not_affected`, justification `vulnerable_code_cannot_be_controlled_by_adversary`
  └─ Yes ↓

Is the path mitigated by an upstream validator, a WAF rule, or a SIEM detection?
  ├─ Yes → OpenVEX `affected` with `workaround_available`
  └─ No  → fix the code; OpenVEX `fixed` once the patch ships
{{< /decision >}}

## Producing a CycloneDX VEX

<!-- TODO: Relevant only when the query traces to a vulnerable library component in your SBOM (some CodeQL queries do this — e.g. `js/jwt-missing-verification` against a JWT library). When it applies, reference the library by PURL. -->

## Producing an OpenVEX

<!-- TODO: The usual outcome. Subject is the repo at a specific commit; vulnerability is the CodeQL query ID + CWE; action_statement records the reasoning and any MR references. The CodeQL alert URL itself makes a useful evidence reference. -->
