---
title: "GitLab DAST"
description: "Black-box probing of a running deployment — OWASP ZAP under the hood, driven by a GitLab CI job."
weight: 50
---

## What GitLab DAST does

<!-- TODO: One paragraph. The DAST CI job spins up an OWASP ZAP container, points it at a target URL (typically a review-app or staging deploy), and runs baseline or full active scans. Findings cover OWASP Top 10-style issues — header misconfig, SQLi probes, XSS probes, auth weaknesses. The `gl-dast-report.json` artefact is the canonical output. -->

## Reading the output

<!-- TODO: The `gl-dast-report.json` artefact is the source of truth. Each `vulnerabilities[]` entry carries `name`, `description`, `severity`, `location.hostname` + `.path`, `evidence.request` + `.response` (request/response that proved the finding), `identifiers[]` (CWE, WASC, OWASP). -->

## What you can act on

<!-- TODO: `name` + `identifiers[]` for classification, `location.hostname` + `.path` + `.method`, `evidence.request` (the request that triggered it — reproducing this manually is how you confirm the finding), `severity`, `solution`. -->

## Decision tree

DAST probes a running deployment. Findings are runtime, not component-level.

{{< decision >}}
Reproduce the finding by replaying the `evidence.request` against the same environment.

Is the finding confirmed?
  ├─ No  (transient, scanner artefact, environment drift) → OpenVEX `not_affected`,
  │                                                         justification `vulnerable_code_not_present`
  └─ Yes ↓

Is the affected endpoint exposed to traffic an attacker can actually send (public, partner-shared, pivot-reachable from a known foothold)?
  ├─ No  → OpenVEX `not_affected`,
  │        justification `vulnerable_code_cannot_be_controlled_by_adversary`
  └─ Yes ↓

Is the vector blocked by a WAF, IPS, or upstream auth that the attacker can't reach?
  ├─ Yes → OpenVEX `affected` with `workaround_available` and the rule reference
  └─ No  → fix the underlying handler; OpenVEX `fixed` once deployed
{{< /decision >}}

## Producing a CycloneDX VEX

<!-- TODO: Rare — DAST findings rarely tie to a packaged component. The exception is when the finding traces to a known issue in a server library in your SBOM (an outdated nginx, a vulnerable app server). In that case, attach the CycloneDX VEX entry to the library's PURL. -->

## Producing an OpenVEX

<!-- TODO: Worked example. Subject is the deployed application + environment (URL or namespace); vulnerability identifier is the DAST finding ID + CWE; action_statement names the fix or mitigation evidence. -->
