---
title: "OpenVEX"
description: "Standalone, lightweight VEX — for findings that don't map to an SBOM component."
weight: 30
---

> Or just run `/vulnetix:vex-publish` and the [AI Coding Agent](ai-coding-agent/) writes this for you — no need to learn the field names by hand.

## What OpenVEX is

OpenVEX is a standalone VEX format maintained as an open specification by the OpenSSF and a small consortium of contributors. It carries the same job description as [CycloneDX VEX](../cyclonedx-vex/) — record a decision about a vulnerability — but takes the opposite design choice: where CycloneDX VEX lives inside (or alongside) an SBOM and identifies its subject by PURL, OpenVEX is a standalone JSON-LD document and lets the subject be anything you can identify with a URL or a PURL.

An OpenVEX document is a small JSON file with a `statements[]` array. Each statement names a vulnerability, names one or more products affected (or not affected) by it, and records a status with optional justification.

## When to use it

Pick OpenVEX when the finding doesn't tie to a packaged component in your SBOM:

- **SAST findings in your own code** — the subject is your repo at a specific commit, not a library
- **Secret detections** — the subject is the repo (or a removed commit); there's no component to upgrade
- **IaC misconfigurations** — the subject is the manifest path, not a package
- **Runtime mitigations against an unpatched CVE** — the subject is the deployed service and the action_statement names the WAF / IPS / SIEM rule
- **Vulnerabilities in transitive dependencies your SBOM doesn't declare** — when the SBOM lists only direct deps
- **Cross-build statements** — when the decision applies to every release of the service, not just one SBOM

OpenVEX is the wrong format when you already have an SBOM and the finding is a packaged component named in it — at that point, CycloneDX VEX keeps the SBOM and the VEX speaking the same language.

## What's in a statement

OpenVEX documents have a small top-level header and an array of statements.

| Field | Purpose |
|---|---|
| `@context` | Fixed: `https://openvex.dev/ns/v0.2.0` |
| `@id` | A canonical URL for this document — must be unique and ideally resolvable |
| `author` | Identity of the entity making the claim |
| `timestamp` | When this document was issued (RFC 3339) |
| `version` | Document version, increments when you republish a corrected statement |
| `statements[].vulnerability.name` | CVE, GHSA, internal rule ID, or freeform identifier |
| `statements[].products[]` | What the statement applies to (`@id` + identifiers like `purl` or `cpe`) |
| `statements[].status` | `not_affected`, `affected`, `fixed`, or `under_investigation` |
| `statements[].justification` | Why `not_affected` — same vocabulary as CycloneDX |
| `statements[].action_statement` | What was done about the finding (for `affected` or `fixed`) |
| `statements[].impact_statement` | Optional: why an `affected` finding still matters (or doesn't) in context |

**Justifications** for `not_affected` — the OpenVEX vocabulary mirrors the CycloneDX one closely:

- `component_not_present`
- `vulnerable_code_not_present`
- `vulnerable_code_not_in_execute_path`
- `vulnerable_code_cannot_be_controlled_by_adversary`
- `inline_mitigations_already_exist`

## Worked examples

{{< tabs >}}
{{< tab name="not_affected (SAST)" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-sast-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "CWE-89",
        "description": "SQL injection — Semgrep rule semgrep-rules:python.flask.sql-injection in app/api/search.py:42"
      },
      "products": [
        {
          "@id": "https://github.com/yourorg/yourrepo",
          "identifiers": { "purl": "pkg:github/yourorg/yourrepo@abc1234" }
        }
      ],
      "status": "not_affected",
      "justification": "vulnerable_code_cannot_be_controlled_by_adversary",
      "action_statement": "The flagged query uses a read-only connection pool. The input concatenated into the query is validated upstream by a strict allow-list regex (see app/middleware/validate.py:18). Reviewed in MR !55 on 2026-05-14."
    }
  ]
}
```
{{< /tab >}}
{{< tab name="affected (WAF workaround)" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-waf-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": { "name": "CVE-2024-12345" },
      "products": [
        {
          "@id": "https://yourservice.example.com",
          "identifiers": { "purl": "pkg:generic/yourservice@2.1.0" }
        }
      ],
      "status": "affected",
      "action_statement": "ModSecurity rule 10001 deployed to production WAF on 2026-05-14 blocks the path traversal vector. Patch upgrade planned in sprint 24 (issue #99)."
    }
  ]
}
```
{{< /tab >}}
{{< tab name="fixed (rotated secret)" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-secret-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "SECRET-AWS-001",
        "description": "AWS access key AKIAIOSFODNN7EXAMPLE committed in def5678"
      },
      "products": [{ "@id": "https://github.com/yourorg/yourrepo" }],
      "status": "fixed",
      "action_statement": "Key revoked in AWS IAM on 2026-05-14T08:30Z. Replacement stored in CI secrets vault (path: ci/yourorg/yourrepo/aws). Secret purged from history via git filter-repo in commit ghi9012. Incident INC-2026-042."
    }
  ]
}
```
{{< /tab >}}
{{< /tabs >}}

## Republishing statements

OpenVEX statements aren't immutable. When a decision changes — a `not_affected` becomes `affected` after new exploit research, or an `affected` becomes `fixed` after the patch ships — republish the document with the same `@id`, an incremented `version`, and a new `timestamp`. VEX-aware consumers will use the latest version automatically.

The `@id` is the stable identifier for the decision. Two documents with the same `@id` are two versions of the same statement; two documents with different `@id`s are two different decisions, even if the vulnerability and product are identical.


---

Referenced in [NIST SP 800-218 (Secure Software Development Framework)](https://csrc.nist.gov/Projects/ssdf), the [CISA SSVC methodology](https://www.cisa.gov/ssvc), and the [EU Cyber Resilience Act](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act) — VEX statements form part of the evidence trail for SOC 2 Type II, PCI-DSS, ISO 27001, and FedRAMP compliance work.

See also: [Glossary](../glossary/), [SSVC Engineer Triage](../ssvc/), [Capability matrix](../../scanners/#capability-matrix).
