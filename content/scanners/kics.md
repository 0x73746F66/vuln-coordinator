---
title: "KICS"
description: "Checkmarx's open-source IaC scanner — Rego-based queries across 20+ platforms, SARIF + CycloneDX + JSON output."
weight: 120
---

> **KICS** (Keeping Infrastructure as Code Secure) · Apache-2.0 OSS · [Source](https://github.com/Checkmarx/kics) · [Docs](https://docs.kics.io/) · Maintained by Checkmarx.
>
> Companion Vulnetix rule pack (clean-room port of KICS rules to Vulnetix's OPA engine): [vulnetix/opa-checkmarx-kics](https://github.com/vulnetix/opa-checkmarx-kics).

KICS runs a library of Rego queries (Open Policy Agent) over your IaC and flags misconfigurations against a known-good shape. The platform list is the widest of any IaC scanner — Terraform, OpenTofu, CloudFormation, Azure Resource Manager, Bicep, AWS CDK, AWS SAM, Google Deployment Manager, Pulumi, Crossplane, Kubernetes, Helm, Knative, Ansible, Docker, Docker Compose, Buildah, OpenAPI, gRPC, GitHub Workflows, Serverless Framework, Azure Blueprints, Databricks, NIFCloud, TencentCloud — and a single binary covers them all. Every finding carries a `cwe` field and severity (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` / `TRACE`).

The output you'll consume is JSON or SARIF — both are first-class. KICS doesn't emit VEX directly, so the triage step on this page is the usual one: read the finding, fix or document, and write the decision into an OpenVEX statement.

## What KICS finds in JSON

```bash
kics scan -p . --report-formats json -o ./results/
# Or SARIF:
kics scan -p . --report-formats sarif -o ./results/
```

Top-level JSON shape (verified against KICS 2.x):

```json
{
  "kics_version": "v2.x.x",
  "files_scanned": 142,
  "lines_scanned": 31050,
  "files_parsed": 142,
  "queries_total": 2100,
  "queries_failed_to_execute": 0,
  "total_counter": 27,
  "severity_counters": { "CRITICAL": 2, "HIGH": 6, "MEDIUM": 14, "LOW": 5, "INFO": 0, "TRACE": 0 },
  "queries": [ /* per-query results, each with a files[] list */ ]
}
```

Per-query fields under `queries[]`:

| Field | Purpose |
|---|---|
| `query_id` | Stable UUID — the rule identifier. Reference: `docs.kics.io/latest/queries/<platform>-queries/<query_id>` |
| `query_name` | Human-readable name, e.g. `"S3 Bucket Without Server-side-encryption"` |
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` / `TRACE` |
| `platform` | The IaC platform that fired (`Terraform`, `Kubernetes`, `Dockerfile`, `Ansible`, `CloudFormation`, …) |
| `category` | Query category (e.g. `Encryption`, `Access Control`, `Networking and Firewall`, `Secret Management`) |
| `cwe` | The CWE identifier (numeric string) |
| `description` | What's wrong and why |
| `description_id` | Stable ID for the description string |
| `files[]` | One entry per match — each carries the per-file location and the diff between expected and actual |
| `files[].file_name` | File path |
| `files[].line` | 1-indexed line number |
| `files[].similarity_id` | Stable hash for the same logical finding across scans — drives dedup and suppression |
| `files[].issue_type` | `MissingAttribute` / `IncorrectValue` / `RedundantAttribute` |
| `files[].search_key` | Path into the resource, e.g. `aws_s3_bucket[example].server_side_encryption_configuration` |
| `files[].expected_value` | What the resource should look like |
| `files[].actual_value` | What the resource currently looks like |

## Querying with jq

```bash
# Every finding flattened (one row per file match)
jq '.queries[] | . as $q | .files[] | {
      query_id: $q.query_id,
      query_name: $q.query_name,
      severity: $q.severity,
      platform: $q.platform,
      cwe: $q.cwe,
      file: .file_name,
      line: .line,
      similarity_id: .similarity_id,
      issue_type: .issue_type
    }' results/results.json

# Filter to CRITICAL + HIGH only
jq '.queries[] | select(.severity == "CRITICAL" or .severity == "HIGH")' results/results.json

# Group by platform — how much of each IaC type is fired?
jq '[.queries[].platform] | group_by(.) | map({platform: .[0], count: length})' results/results.json

# CWE rollup
jq '[.queries[] | {cwe, sev: .severity, n: (.files | length)}]
    | group_by(.cwe)
    | map({cwe: .[0].cwe, count: ([.[].n] | add)})
    | sort_by(-.count)' results/results.json

# Per-file rollup — split work across owners
jq '[.queries[] | . as $q | .files[] | {file: .file_name, query: $q.query_name}]
    | group_by(.file)
    | map({file: .[0].file, queries: [.[].query] | unique})' results/results.json
```

## From finding to root cause

Each `query_id` has a page at `docs.kics.io/latest/queries/<platform>-queries/<query_id>` describing the bad pattern and the fix. The cell-by-cell triage path:

1. Look up the rule — confirm what it detects on the docs page.
2. Read `search_key` to see the resource path and `expected_value` vs `actual_value` for the diff KICS wants.
3. Cross-reference `cwe` against your threat model — `CWE-311` (missing encryption) is not the same risk as `CWE-732` (incorrect permissions).
4. Fix the IaC, or document the deviation with an OpenVEX statement.

Engineer Triage inputs for KICS:

- **Reachability** — IaC reachability is "will it deploy". `VERIFIED_REACHABLE` if the resource is in the live plan (`terraform plan` shows it); `VERIFIED_UNREACHABLE` if the file is an archived module or unused example; `UNKNOWN` for shared modules pending environment-specific selectors.
- **Remediation Option** — `PATCHABLE_MANUAL` (`CODE_CHANGE` in the IaC).
- **Mitigation Option** — `INFRASTRUCTURE` (most KICS findings are infra-level); occasionally `COMPENSATING_CONTROL` when a cloud-side guardrail (SCP, Azure Policy, GCP Org Policy) blocks the misconfiguration at runtime.
- **Priority** — `severity` directly maps. CRITICAL/HIGH ≈ HIGH/CRITICAL; MEDIUM ≈ MEDIUM; LOW/INFO/TRACE ≈ LOW.

See [SSVC Engineer Triage](../appendices/ssvc/).

## Decision tree

{{< decision >}}
Does the finding tie to a known CVE in a base image or Helm chart dependency?
  ├─ Yes → CycloneDX VEX referencing the artefact PURL, alongside the OpenVEX.
  └─ No  (pure misconfiguration) → OpenVEX, subject is the repo at the scanned commit.

Suppress a known-OK match via `# kics-scan ignore-line` / `# kics-scan ignore-block`
in the IaC source, or `-x <similarity_id>` on the CLI?
  → Combine with an OpenVEX statement. The inline comment / similarity-ID stops
    KICS flagging it; the OpenVEX records why for other tools and for audit.
{{< /decision >}}

## Worked example: `S3 Bucket Without Server-side-encryption`

Terraform input:

```hcl
# infra/s3.tf
resource "aws_s3_bucket" "logs" {
  bucket = "example-logs"
}
```

KICS flags this on the Terraform query pack:

```json
{
  "query_id": "b1d2c3a4-...",
  "query_name": "S3 Bucket Without Server-side-encryption",
  "severity": "HIGH",
  "platform": "Terraform",
  "category": "Encryption",
  "cwe": "311",
  "description": "S3 Bucket should have server-side-encryption configured.",
  "files": [{
    "file_name": "infra/s3.tf",
    "line": 1,
    "similarity_id": "9f3c…",
    "issue_type": "MissingAttribute",
    "search_key": "aws_s3_bucket[logs].server_side_encryption_configuration",
    "expected_value": "'server_side_encryption_configuration' should be defined",
    "actual_value": "'server_side_encryption_configuration' is undefined"
  }]
}
```

Inputs come straight out of the JSON — `search_key` points at exactly the resource attribute to add; `expected_value` tells you what shape KICS wants. No grep across the repo required.

Fix:

```hcl
# infra/s3.tf
resource "aws_s3_bucket" "logs" {
  bucket = "example-logs"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
```

Engineer Triage:

- **Reachability** = `VERIFIED_REACHABLE` (the bucket is in the live `terraform plan`).
- **Remediation Option** = `PATCHABLE_MANUAL` (add the resource).
- **Mitigation Option** = `INFRASTRUCTURE` (cloud-config change; no application code touched).
- **Priority** = `HIGH` (KICS severity HIGH + CWE-311 + data-at-rest control).

Outcome: `IMMEDIATE` — apply, re-scan, the same `similarity_id` no longer appears.

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-kics-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:00:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": {
      "name": "KICS:b1d2c3a4-...",
      "description": "S3 Bucket Without Server-side-encryption (Terraform). CWE-311. infra/s3.tf:1 — aws_s3_bucket[logs] missing server_side_encryption_configuration. See docs.kics.io/latest/queries/terraform-queries/<query_id>."
    },
    "products": [{
      "@id": "https://github.com/yourorg/yourrepo",
      "identifiers": { "purl": "pkg:github/yourorg/yourrepo@abc1234" }
    }],
    "status": "fixed",
    "action_statement": "Engineer Triage: IMMEDIATE. Inputs: reachability=VERIFIED_REACHABLE (bucket in live terraform plan), remediation=PATCHABLE_MANUAL, mitigation=INFRASTRUCTURE, priority=HIGH (KICS HIGH + CWE-311). Added aws_s3_bucket_server_side_encryption_configuration.logs with AES256. Confirmed via re-scan: same similarity_id no longer appears. See MR !47."
  }]
}
```
{{< /outcome >}}

## Suppressing a true positive that's known-OK

For a match the query can't reason about (e.g. encryption is enforced by a bucket-policy that the Terraform module references but KICS doesn't inline):

```hcl
# kics-scan ignore-block
resource "aws_s3_bucket" "logs" {
  bucket = "example-logs"   # SSE enforced by org-wide SCP — see docs/sse-policy.md
}
```

Or, in CI, exclude by similarity ID:

```bash
kics scan -p . -x 9f3c…,a1b2…  --report-formats sarif -o ./results/
```

Pair either suppression with an OpenVEX statement — the inline comment / `-x` flag stops KICS flagging it; the OpenVEX records why for downstream consumers and for audit.

## Custom queries

For Rego queries you've written yourself, point KICS at the directory:

```bash
kics scan -p . --queries-path ./my-queries --report-formats sarif -o ./results/
```

Reference custom rules in OpenVEX by the directory path rather than a registry URL:

```json
"vulnerability": {
  "name": "yourorg.custom.tagging-policy",
  "description": "Custom KICS Rego query in my-queries/yourorg-tagging-policy.rego — flags resources missing the cost-centre tag."
}
```

## Related: Vulnetix `opa-checkmarx-kics` rule pack

Vulnetix maintains a clean-room port of KICS rules — about 205 rules reimplemented from scratch against Vulnetix's OPA engine and `input.file_contents` schema:

- 48 Dockerfile rules (`KICS-DOCKER-*`) — package pinning, root-user avoidance, multi-stage hygiene.
- 14 Ansible-AWS rules (`KICS-ANSIBLE-AWS-*`) — S3, CloudTrail, RDS, EBS.
- 16 Terraform-AWS rules (`KICS-TF-AWS-*`).
- 127 Terraform Azure/GCP rules — AKS, storage, networking, identity.

Apache-2.0. Source: [`vulnetix/opa-checkmarx-kics`](https://github.com/vulnetix/opa-checkmarx-kics). Invocation:

```bash
vulnetix scan --rule Vulnetix/opa-checkmarx-kics
# Run only this pack, disabling Vulnetix's built-in rules:
vulnetix scan --rule Vulnetix/opa-checkmarx-kics --disable-default-rules
```

If you're already running Vulnetix, this gives you KICS-shaped IaC coverage without a second scanner — and the findings land in `.vulnetix/memory.yaml` alongside every other source. If you're not, the queries on this page give you the same detections natively in KICS.

## Capability snapshot

See the [capability matrix](../#capability-matrix) for the full comparison. KICS summary:

- **Coverage**: IaC across 20+ platforms (Terraform, Kubernetes, CloudFormation, Ansible, Docker, Helm, OpenAPI, ARM, Bicep, OpenTofu, Pulumi, Crossplane, GitHub Workflows, Serverless, SAM, CDK, …). Native secrets-regex pass (on by default). No SCA, no SAST, no DAST.
- **Database quality**: N/A — rule-driven (Rego query library).
- **[Reachability](../../appendices/reachability-deep-dive/)**: **[Tier 1](../../appendices/reachability-deep-dive/#tier-1)** — pattern-match against IaC resource shapes; no dataflow, no call-graph (not applicable to IaC).
- **Outputs**: JSON, [SARIF](../../appendices/sarif/), CycloneDX SBOM, JUnit, GitLab-glsast, SonarQube, HTML, PDF, ASFF, CSV, CodeClimate. No native VEX emission.

## See also

- [Capability matrix](../#capability-matrix).
- [SARIF appendix](../../appendices/sarif/) — KICS dialect.
- [Glossary](../../appendices/glossary/).
- [`vulnetix/opa-checkmarx-kics`](https://github.com/vulnetix/opa-checkmarx-kics) — Vulnetix's clean-room port of KICS rules.
