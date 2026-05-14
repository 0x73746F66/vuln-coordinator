---
title: "CycloneDX VEX"
description: "VEX as part of CycloneDX — travels with the SBOM, points to components by PURL."
weight: 25
---

## What CycloneDX VEX is

CycloneDX VEX is the VEX dialect built into the CycloneDX standard. A VEX document is either embedded inside a CycloneDX SBOM (in the same `vulnerabilities[]` array) or shipped as a standalone CycloneDX document that references the SBOM by `serialNumber`. Either way, every entry resolves back to a component declared in an SBOM — usually one of yours — by package URL.

If you already produce a [CycloneDX SBOM](../cyclonedx-sbom/) in CI, CycloneDX VEX is the natural format. Your scanner tooling already understands the SBOM's component identities, and CycloneDX VEX lets you record decisions in the same vocabulary the scanner uses.

## When to use it

Pick CycloneDX VEX when the finding ties to a packaged component you can name in your SBOM:

- A library or framework dependency flagged by SCA
- A vulnerable transitive that you've verified isn't reachable in your code path
- A container base image layer with a known CVE you're inheriting
- A component that's been upgraded and the new version is the one shipped

CycloneDX VEX is the wrong format for findings without an SBOM component — SAST findings in your own code, secrets, IaC misconfigurations, or runtime issues against unmanifested binaries. For those, use [OpenVEX](../openvex/).

## What's in an entry

A CycloneDX VEX entry is one element of the `vulnerabilities[]` array. The fields you'll touch most:

| Field | Purpose |
|---|---|
| `id` | The vulnerability identifier — CVE, GHSA, or vendor-specific |
| `source` | Where the vulnerability metadata came from (NVD, GitHub, vendor advisory) |
| `ratings[]` | Severity, optionally with method (CVSS v3, CVSS v4, OWASP RR) |
| `affects[].ref` | The PURL of the affected component — must match a `bom-ref` in your SBOM |
| `affects[].versions[]` | Which versions are affected and the status per version |
| `analysis.state` | The decision: `not_affected`, `in_triage`, `exploitable`, `false_positive`, `not_affected`, `resolved`, `resolved_with_pedigree` |
| `analysis.justification` | Why `not_affected` — vocabulary below |
| `analysis.response[]` | What you'll do when `exploitable`: `will_not_fix`, `update`, `rollback`, `workaround_available`, `can_not_fix` |
| `analysis.detail` | Free-text explanation of the decision — the part future-you will read |

**Justifications** for `not_affected` (one of):

- `code_not_present` — the affected component isn't actually used
- `code_not_reachable` — the vulnerable function is imported but never called
- `requires_configuration` — exploit needs a non-default config you don't ship
- `requires_dependency` — exploit needs a sibling component you don't have
- `requires_environment` — exploit needs a runtime context that doesn't apply
- `protected_by_compiler` — compiler hardening neutralises the vector
- `protected_at_runtime` — runtime sandbox or capability removes the risk
- `protected_at_perimeter` — a WAF / IPS / network control blocks the vector
- `protected_by_mitigating_control` — an in-process mitigation closes the path

## Worked examples

{{< tabs >}}
{{< tab name="not_affected" >}}
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:a1b2c3d4-0000-0000-0000-000000000001",
  "version": 1,
  "vulnerabilities": [
    {
      "id": "CVE-2024-12345",
      "source": { "name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345" },
      "ratings": [{ "source": { "name": "NVD" }, "severity": "high", "method": "CVSSv3" }],
      "affects": [
        {
          "ref": "pkg:npm/vulnerable-lib@1.2.3",
          "versions": [{ "version": "1.2.3", "status": "affected" }]
        }
      ],
      "analysis": {
        "state": "not_affected",
        "justification": "code_not_reachable",
        "detail": "vulnerable-lib's parseXML() is imported by our request validator but the validator's XML branch is dead code — the application uses JSON exclusively for data exchange. Verified in MR !88 with a coverage report showing parseXML never executes in the production build."
      }
    }
  ]
}
```
{{< /tab >}}
{{< tab name="exploitable + workaround" >}}
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "vulnerabilities": [
    {
      "id": "CVE-2024-12345",
      "affects": [
        {
          "ref": "pkg:npm/vulnerable-lib@1.2.3",
          "versions": [{ "version": "1.2.3", "status": "affected" }]
        }
      ],
      "analysis": {
        "state": "exploitable",
        "response": ["workaround_available"],
        "detail": "ModSecurity rule 10001 blocks the path traversal vector at the WAF. Rule deployed to production on 2026-05-14. Patch upgrade to vulnerable-lib@1.2.4 tracked in issue #99, planned for sprint 24."
      }
    }
  ]
}
```
{{< /tab >}}
{{< tab name="resolved (upgraded)" >}}
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "vulnerabilities": [
    {
      "id": "CVE-2024-12345",
      "affects": [
        {
          "ref": "pkg:npm/vulnerable-lib@1.2.4",
          "versions": [
            { "version": "1.2.3", "status": "affected" },
            { "version": "1.2.4", "status": "unaffected" }
          ]
        }
      ],
      "analysis": {
        "state": "resolved",
        "detail": "Upgraded to vulnerable-lib@1.2.4 in commit abc1234. See merge request !42 — the upgrade passed all integration tests and shipped to production on 2026-05-13."
      }
    }
  ]
}
```
{{< /tab >}}
{{< /tabs >}}

## Embedding vs standalone

Two valid shapes:

**Embedded.** The `vulnerabilities[]` array sits inside the same CycloneDX document as your SBOM `components[]`. One file, one identity. Easiest if you generate the SBOM and VEX in the same step and don't need to update the VEX more often than the SBOM.

**Standalone.** Ship the SBOM and VEX as two CycloneDX documents. The VEX has its own `serialNumber` and points to the SBOM via `metadata.tools` and `dependencies[]` references. Better when the SBOM is regenerated on every build but VEX statements accumulate across builds — the VEX has its own lifecycle.

Most CI setups start with embedded and split when VEX maintenance starts diverging from SBOM regeneration. Either shape is consumed identically by VEX-aware scanners.
