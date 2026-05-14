---
title: "VEX — CycloneDX VEX and OpenVEX"
description: "What a VEX statement is, when to use CycloneDX VEX vs OpenVEX, and why producing them benefits you as a developer."
weight: 20
---

## What is a VEX statement?

A Vulnerability Exploitability eXchange (VEX) statement is a machine-readable document that records a decision about a specific vulnerability in a specific piece of software. It answers the question: *"Is this CVE actually a problem for this component in this build, and what action has been taken?"*

VEX was designed to address a persistent problem in vulnerability management: scanners produce lists of CVEs that match component versions. Many of those matches are false positives — the vulnerable code path is not present, or it is unreachable in this deployment, or a compensating control already blocks it. Without a VEX statement, every person who runs the scanner against your code sees the same noise. With a VEX statement, tools can suppress findings you have already assessed.

## The two formats

### CycloneDX VEX

CycloneDX VEX is part of the CycloneDX standard. A VEX document is either embedded inside a CycloneDX SBOM or supplied as a standalone CycloneDX document that references the SBOM by serial number.

**Use CycloneDX VEX when** the finding is a known component in your SBOM — a library, a package, a container base image layer.

A CycloneDX VEX entry records:

- The affected component (referenced by PURL, matching your SBOM entry)
- The vulnerability ID (CVE or GHSA)
- The **analysis state**: `not_affected`, `in_triage`, `affected`, or `fixed`
- The **justification** (when `not_affected`): `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_cannot_be_controlled_by_adversary`, `vulnerable_code_not_in_execute_path`, `inline_mitigations_already_exist`
- A free-text **detail** explaining the decision
- A **response** (when `affected`): `will_not_fix`, `update`, `rollback`, `workaround_available`, `fix_planned`

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
      "ratings": [{ "source": { "name": "NVD" }, "severity": "high" }],
      "affects": [
        {
          "ref": "pkg:npm/vulnerable-lib@1.2.3",
          "versions": [{ "version": "1.2.3", "status": "affected" }]
        }
      ],
      "analysis": {
        "state": "not_affected",
        "justification": "vulnerable_code_not_in_execute_path",
        "detail": "The vulnerable function parseXML() is imported but never called. The application uses JSON exclusively for data exchange."
      }
    }
  ]
}
```
{{< /tab >}}
{{< tab name="fixed" >}}
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
        "state": "fixed",
        "detail": "Upgraded to vulnerable-lib@1.2.4 in commit abc1234. See merge request !42."
      }
    }
  ]
}
```
{{< /tab >}}
{{< tab name="workaround" >}}
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
        "state": "affected",
        "response": ["workaround_available"],
        "detail": "ModSecurity rule 10001 blocks the path traversal vector. Rule deployed to production WAF on 2026-05-14. Patch upgrade tracked in issue #99."
      }
    }
  ]
}
```
{{< /tab >}}
{{< /tabs >}}

### OpenVEX

OpenVEX is a lightweight, standalone VEX format defined by the OpenVEX specification. It does not require an SBOM to be useful.

**Use OpenVEX when** the finding is not tied to a component in your SBOM. Examples:

- A SAST finding in your own code
- A secret detected in a commit
- A vulnerability mitigated by a WAF rule, IPS signature, or SIEM detection (where there is no package to upgrade)
- A finding in a transitive dependency that is not declared in your SBOM

An OpenVEX document contains one or more **statements**, each with:

- A **subject** — the product or component affected (can be a PURL, a CPE, or a free-form identifier)
- A **vulnerability** — the CVE, GHSA, or internal ID
- A **status**: `not_affected`, `affected`, `fixed`, or `under_investigation`
- A **justification** (for `not_affected`): same vocabulary as CycloneDX
- A **action_statement** — free-text description of what was done

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
      "vulnerability": { "name": "CWE-89", "description": "SQL Injection — Semgrep finding semgrep-rules:python.flask.sql-injection" },
      "products": [{ "@id": "https://github.com/yourorg/yourrepo", "identifiers": { "purl": "pkg:github/yourorg/yourrepo@abc1234" } }],
      "status": "not_affected",
      "justification": "vulnerable_code_cannot_be_controlled_by_adversary",
      "action_statement": "The flagged query uses a read-only connection pool and the input is validated upstream by a strict allow-list regex. Reviewed in MR !55 on 2026-05-14."
    }
  ]
}
```
{{< /tab >}}
{{< tab name="workaround (WAF)" >}}
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
      "products": [{ "@id": "https://yourservice.example.com", "identifiers": { "purl": "pkg:generic/yourservice@2.1.0" } }],
      "status": "affected",
      "action_statement": "ModSecurity rule 10001 deployed to production WAF on 2026-05-14 blocks the path traversal vector. Patch upgrade planned in sprint 24."
    }
  ]
}
```
{{< /tab >}}
{{< tab name="fixed (secret)" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-secret-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": { "name": "SECRET-DETECT-001", "description": "AWS access key committed in commit def5678" },
      "products": [{ "@id": "https://github.com/yourorg/yourrepo" }],
      "status": "fixed",
      "action_statement": "Key revoked in AWS IAM on 2026-05-14T08:30Z. Secret removed from history via git-filter-repo. New key stored in CI secrets vault only. See incident report INC-2026-042."
    }
  ]
}
```
{{< /tab >}}
{{< /tabs >}}

## Why VEX matters to a developer

**Helps future-you.** Six months from now, when the same CVE appears in a new scanner report, the VEX statement records your original decision and the reasoning behind it. You do not need to re-investigate from scratch.

**Proves past actions.** If a cyber team or auditor asks "what did you do about CVE-2024-12345?", the VEX statement is a timestamped, machine-readable record. It is more trustworthy than a Slack message or a comment in a ticket.

**Suppresses noise for your colleagues.** Modern scanning tools that consume VEX data will suppress findings that have already been assessed as `not_affected` or `fixed`. When a colleague runs a scanner against your repository, they do not see noise that you already resolved — provided the VEX file is present and the tool supports it.

**You benefit from other people's work.** The same suppression works in reverse. If a shared library's maintainer publishes a VEX statement saying a CVE does not affect their library in its default configuration, tools that read VEX will suppress that finding for you automatically.

**Modern scanners consume VEX.** Grype, Trivy, and the Vulnetix platform all have VEX ingestion. The investment in writing the statement pays forward every time the scanner runs.

**Compliance and audit readiness.** VEX is referenced in CISA guidance, NIST SP 800-218, and the EU Cyber Resilience Act as a mechanism for communicating exploitability status. Producing VEX as part of your normal development flow means compliance artefacts exist before they are requested.
