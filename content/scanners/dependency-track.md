---
title: "OWASP Dependency-Track"
description: "OWASP Flagship Component Analysis platform — SBOM-consuming, policy-driven, CycloneDX VEX round-tripping."
weight: 125
---

> **OWASP Dependency-Track** · Apache-2.0 OSS · **[OWASP Flagship Project](https://owasp.org/www-project-dependency-track/)** · [Site](https://dependencytrack.org/) · [Docs](https://docs.dependencytrack.org/) · [Source](https://github.com/DependencyTrack/dependency-track) · Project leads: Steve Springett, Niklas Düster.
>
> Latest stable: **v4.14.2** (2026-05-07). The 4.x line has a quarterly minor / bi-monthly patch cadence; a Hyades-based v5 architecture is in active development.

Dependency-Track is the canonical **SBOM-consuming Component Analysis** platform. It is not a scanner in the same sense as Trivy, Grype, or Semgrep — it does no source-code parsing, no IaC linting, no secret detection, no DAST, and no image-binary scanning of its own. What it *does* — and does better than any other OSS tool on this site — is take a CycloneDX SBOM produced by an upstream tool, continuously re-evaluate every component against an aggregated vulnerability dictionary, enforce policy, and round-trip [CycloneDX VEX](../appendices/cyclonedx-vex/) statements cleanly through the audit workflow.

Put Dependency-Track *downstream* of every other scanner. Upstream tools (the [CycloneDX](https://cyclonedx.org/) Maven / Gradle plugins, `cyclonedx-bom` for Python / Node / Go / .NET, [syft](https://github.com/anchore/syft), [Trivy](trivy/)) produce the SBOM; Dependency-Track ingests it, matches components against NVD, GHSA, OSV, and (optionally) VulnDB, Sonatype OSS Index, Snyk, and Trivy, and surfaces findings with a [VEX-shaped triage vocabulary](#triage-workflow--the-three-enums) that maps 1:1 to the CycloneDX VEX spec.

The triage decision you record in Dependency-Track *is* the VEX statement — that round-trip is the page's hook.

## Architecture and ingestion

Dependency-Track is **server / UI first**. There is no first-party CLI.

- **API Server** — an executable WAR running on embedded Jetty. OpenAPI-documented REST. Every UI action is a REST call.
- **Frontend** — a separately-deployed Vue SPA.
- **Database** — PostgreSQL (recommended) or Microsoft SQL Server. The legacy embedded H2 mode is **dev-only** and unsupported in production.
- **Deployment** — Docker / Compose / Swarm / Kubernetes (official Helm chart) / bare JAR. Alpine container variants since v4.13.6.

SBOM upload is two endpoints:

```bash
# Base64-encoded payload, project identified by UUID
curl -X "PUT" "https://dtrack.example.com/api/v1/bom" \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: ${DTRACK_API_KEY}' \
  -d "{ \"project\": \"${PROJECT_UUID}\", \"bom\": \"$(base64 -w0 bom.json)\" }"

# Or multipart, identified by name + version with auto-create
curl -X "POST" "https://dtrack.example.com/api/v1/bom" \
  -H "X-API-Key: ${DTRACK_API_KEY}" \
  -F "autoCreate=true" \
  -F "projectName=acme-api" \
  -F "projectVersion=1.2.3" \
  -F "bom=@bom.json"
```

The CycloneDX Maven plugin / Gradle plugin / `cyclonedx-bom` CLI / GitHub Action wraps the same call.

## What Dependency-Track finds in JSON

The Findings API is the canonical machine surface. Output is JSON; SARIF is not emitted — the equivalent role is filled by CycloneDX VEX / VDR.

```bash
curl -s -H "X-API-Key: ${DTRACK_API_KEY}" \
  "https://dtrack.example.com/api/v1/finding/project/${PROJECT_UUID}" \
  -o findings.json
```

A finding record carries four nested objects:

```json
[{
  "component": {
    "uuid": "…",
    "name": "jackson-databind",
    "group": "com.fasterxml.jackson.core",
    "version": "2.13.2",
    "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2",
    "cpe": "cpe:2.3:a:fasterxml:jackson-databind:2.13.2:*:*:*:*:*:*:*",
    "project": "…"
  },
  "vulnerability": {
    "uuid": "…",
    "source": "NVD",
    "vulnId": "CVE-2022-42003",
    "severity": "HIGH",
    "severityRank": 1,
    "cvssV3BaseScore": 7.5,
    "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "epssScore": 0.0123,
    "epssPercentile": 0.83,
    "cweId": 502,
    "aliases": [{ "source": "GHSA", "vulnId": "GHSA-jjjh-jjxp-wpff" }]
  },
  "analysis": {
    "state": "NOT_SET",
    "isSuppressed": false
  },
  "attribution": {
    "analyzerIdentity": "INTERNAL",
    "attributedOn": "2026-05-14T09:00:00Z"
  }
}]
```

| Field | Purpose |
|---|---|
| `component.purl` | Package URL — stable identity across scans, the dedup key |
| `component.cpe` | CPE 2.3 — used by NVD-sourced matches |
| `vulnerability.source` | `NVD` / `GITHUB` / `OSV` / `VULNDB` / `SNYK` / `OSSINDEX` / `TRIVY` — which feed the finding came from |
| `vulnerability.vulnId` | The CVE / GHSA / OSV / VulnDB ID |
| `vulnerability.aliases[]` | Cross-feed aliases — CVE + GHSA + OSV identifiers for the same advisory |
| `vulnerability.severityRank` | Numeric rank used by Risk Score (`CRITICAL=0`, `HIGH=1`, `MEDIUM=2`, `LOW=3`, `UNASSIGNED=4`) |
| `vulnerability.cvssV3Vector` / `cvssV3BaseScore` | CVSS v3.1 from the source feed |
| `vulnerability.cvssV4Vector` | CVSS v4.0 — added in v4.14.0 |
| `vulnerability.epssScore` / `epssPercentile` | EPSS, available as a policy condition since v4.12.0 |
| `vulnerability.cweId` | CWE — also a policy subject |
| `analysis.state` | The triage outcome — see [the AnalysisState enum](#triage-workflow--the-three-enums) |
| `analysis.justification` | The CycloneDX VEX-shaped reason — populated on `NOT_AFFECTED` |
| `analysis.response` | What action was / will be taken |
| `analysis.isSuppressed` | Orthogonal to state — suppresses the finding from Risk Score and downstream syncs |
| `attribution.analyzerIdentity` | `INTERNAL` (mirrored feed match) / `OSSINDEX` / `SNYK` / `VULNDB` / `TRIVY` |

## Querying with jq

```bash
# One row per finding, flattened
jq '.[] | {
      purl: .component.purl,
      cve: .vulnerability.vulnId,
      source: .vulnerability.source,
      sev: .vulnerability.severity,
      epss: .vulnerability.epssPercentile,
      state: .analysis.state,
      suppressed: .analysis.isSuppressed
    }' findings.json

# Only the actionable findings — drop suppressed and resolved
jq '[.[] | select(.analysis.isSuppressed == false and
                   (.analysis.state // "NOT_SET") != "RESOLVED" and
                   (.analysis.state // "NOT_SET") != "FALSE_POSITIVE" and
                   (.analysis.state // "NOT_SET") != "NOT_AFFECTED")]' findings.json

# Severity rollup — the inputs to the Risk Score formula
jq '[.[] | .vulnerability.severity] | group_by(.) | map({sev: .[0], n: length})' findings.json

# EPSS >= 0.5 — the CI-gate condition (matches the v4.12.0 policy condition)
jq '[.[] | select((.vulnerability.epssScore // 0) >= 0.5)]' findings.json

# Findings still in IN_TRIAGE — the audit-debt queue
jq '[.[] | select(.analysis.state == "IN_TRIAGE")] | length' findings.json

# Group by source feed — sanity-check what's matching from where
jq '[.[] | .vulnerability.source] | group_by(.) | map({source: .[0], n: length})' findings.json
```

## Vulnerability data sources

Dependency-Track makes a clear distinction between **internal mirroring** (which populates a local vulnerability dictionary the API server matches against) and **external analyzers** (per-component lookups queried on demand).

**Internal mirroring:**

| Source | Notes |
|---|---|
| **NVD** | NVD 2.0 REST API support added in v4.10.0, fully migrated by v4.13.4. Daily incremental. API key optional but recommended. |
| **GitHub Advisories (GHSA)** | Via the GitHub GraphQL API. **EPSS scores attached to GHSA entries in v4.14.0**. |
| **OSV** | Multiple ecosystems. **Incremental mirroring added in v4.14.0** — previously a full-refresh. |
| **VulnDB** | Commercial (Risk Based Security / Flashpoint). Subscription required. |

**External analyzers** (queried per-component):

| Source | Notes |
|---|---|
| **Sonatype OSS Index** | Free; **credentials required since v4.13.5**. |
| **Snyk** | Snyk org-ID + token; paid tier for production volume. |
| **Trivy** | Client/server mode against an external Trivy server. Switched to Protobuf transport in v4.12.0. OS-distro feeds (Alpine, Debian, Ubuntu, RHEL, …) reach Dependency-Track only via this delegated analyzer. |

There is **no first-party CISA KEV feed**, **no SUSE / Red Hat OVAL ingestion**, and **no NPM Audit integration** (deliberately deprecated upstream). For KEV / EU-KEV / weaponisation / honeypot sightings / IOC pivots, cross-reference `vulnetix vdb vuln <CVE>` — see the [Vulnetix VDB](../appendices/glossary/#vulnetix-vdb) entry.

## Risk Score

The headline prioritisation number is a **weighted-severity aggregate**, quoted verbatim from the [terminology docs](https://docs.dependencytrack.org/terminology/):

```
((critical * 10) + (high * 5) + (medium * 3) + (low * 1) + (unassigned * 5))
```

The same formula rolled up the project hierarchy is the **Inherited Risk Score** — a parent project's score is the sum of its children's, so a portfolio view ranks projects by cumulative debt.

This is a single-axis weighted-severity score, not a multi-axis [CWSS](../appendices/glossary/#cwss)-shaped composite. Suppressed findings drop out of the calculation. EPSS is *available* on the finding (and as a policy condition) but does not enter the Risk Score formula.

## Triage workflow — the three enums

The triage vocabulary is three enumerations, source-of-truth in the Java model classes:

**`AnalysisState`** (`model/AnalysisState.java`):

```
EXPLOITABLE
IN_TRIAGE
FALSE_POSITIVE
NOT_AFFECTED
RESOLVED
NOT_SET
```

**`AnalysisJustification`** (`model/AnalysisJustification.java`) — populated when state is `NOT_AFFECTED`; values map 1:1 to the **CycloneDX VEX justification vocabulary**, which is what makes the round-trip clean:

```
CODE_NOT_PRESENT
CODE_NOT_REACHABLE
REQUIRES_CONFIGURATION
REQUIRES_DEPENDENCY
REQUIRES_ENVIRONMENT
PROTECTED_BY_COMPILER
PROTECTED_AT_RUNTIME
PROTECTED_AT_PERIMETER
PROTECTED_BY_MITIGATING_CONTROL
NOT_SET
```

**`AnalysisResponse`** (`model/AnalysisResponse.java`) — the action the team will take:

```
CAN_NOT_FIX
WILL_NOT_FIX
UPDATE
ROLLBACK
WORKAROUND_AVAILABLE
NOT_SET
```

Every decision carries a free-text comment and a full audit trail in PostgreSQL — each change is a row, including the analyst identity and timestamp. Suppression is orthogonal: a finding can be suppressed in any state and drops out of Risk Score and downstream syncs (Kenna, ThreadFix) regardless.

These enums are **not** [SSVC](../appendices/ssvc/). They are CycloneDX VEX-shaped. The next section bridges them.

## From finding to root cause

Dependency-Track surfaces *what's vulnerable* and *which feed said so*; the analyst supplies *whether it's exploitable in this codebase*. The bridge into this site's [SSVC Engineer Triage](../appendices/ssvc/) vocabulary:

- **Reachability** — Dependency-Track is **[Tier 1](../appendices/reachability-deep-dive/#tier-1)**: package-level only. The platform itself cannot tell you whether the vulnerable call-site is reachable from your code. For Tier 2 evidence, run [CodeQL](github-codeql/) or [Snyk SAST](snyk-sast/), produce a CycloneDX VEX statement, and ingest it — Dependency-Track will auto-apply `CODE_NOT_REACHABLE` to the analysis state. For Tier 3 (semantic / intent-to-use) evidence, see Vulnetix.
- **Remediation Option** — maps onto `AnalysisResponse`:
  - `UPDATE` ≈ `PATCHABLE_AUTOMATED` / `PATCHABLE_MANUAL`
  - `WORKAROUND_AVAILABLE` ≈ `WORKAROUND`
  - `ROLLBACK` ≈ `PATCHABLE_MANUAL` (downgrade path)
  - `WILL_NOT_FIX` / `CAN_NOT_FIX` ≈ `NO_PATCH`
- **Mitigation Option** — read off `AnalysisJustification`:
  - `PROTECTED_AT_PERIMETER` ≈ `INFRASTRUCTURE` (WAF, edge, network ACL)
  - `PROTECTED_BY_MITIGATING_CONTROL` ≈ `COMPENSATING_CONTROL`
  - `PROTECTED_AT_RUNTIME` ≈ `INFRASTRUCTURE` (RASP, runtime guard)
  - `CODE_NOT_REACHABLE` → not a mitigation, an exoneration; the finding moves to `NOT_AFFECTED`.
- **Priority** — Dependency-Track's `severityRank` + `epssScore` feed Risk Score. For the additional signal axes the matrix shows Dependency-Track does not surface — KEV due-date, weaponisation maturity, honeypot sightings, ATT&CK chain — cross-reference `vulnetix vdb vuln <CVE>`.

## Decision tree

{{< decision >}}
SBOM uploaded — components matched — finding appears with `state = NOT_SET`.
  ├─ Is the vulnerable code path actually invoked from this project?
  │    ├─ Yes (or unsure)  → `IN_TRIAGE`, then `EXPLOITABLE` if confirmed.
  │    │     ├─ Fix available?  → `AnalysisResponse = UPDATE`, ship the bump, re-scan.
  │    │     │                     On the re-scan the finding disappears
  │    │     │                     → emit CycloneDX VEX (status `fixed`).
  │    │     ├─ No fix?       → `WILL_NOT_FIX` / `CAN_NOT_FIX` +
  │    │                          `AnalysisJustification = PROTECTED_AT_PERIMETER` /
  │    │                          `PROTECTED_BY_MITIGATING_CONTROL`
  │    │                          → emit CycloneDX VEX (status `not_affected` with justification,
  │    │                            or `affected` with action_statement).
  │    └─ No  → `NOT_AFFECTED` + `CODE_NOT_PRESENT` / `CODE_NOT_REACHABLE` /
  │                              `REQUIRES_CONFIGURATION` / `REQUIRES_DEPENDENCY` /
  │                              `REQUIRES_ENVIRONMENT`.
  │              → emit CycloneDX VEX (status `not_affected` with justification).
  └─ Finding is wrong (false positive — wrong component match, e.g. stale CPE)
       → `FALSE_POSITIVE` + suppress.

Policy violation fires (`LICENSE` / `SECURITY` / `OPERATIONAL`, state `FAIL`)?
  → POLICY_VIOLATION notification → gate CI in the webhook receiver.
{{< /decision >}}

Dependency-Track's emit format is **CycloneDX VEX** (plus the combined CycloneDX VDR). It does **not** emit [OpenVEX](../appendices/openvex/) or CSAF — if you need those, convert.

## Worked example: a transitive jackson-databind CVE

A Maven project produces a CycloneDX SBOM at build time:

```bash
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom
```

The CI step uploads it to Dependency-Track:

```bash
curl -X "POST" "https://dtrack.example.com/api/v1/bom" \
  -H "X-API-Key: ${DTRACK_API_KEY}" \
  -F "autoCreate=true" \
  -F "projectName=acme-api" \
  -F "projectVersion=${CI_COMMIT_SHA}" \
  -F "bom=@target/bom.json"
```

A finding surfaces on `jackson-databind 2.13.2` for `CVE-2022-42003` — severity `HIGH`, EPSS 0.83, CWE-502 (deserialization). The dependency is transitive (pulled in by Spring Boot starter), and the team confirms via codeFlow analysis that the affected `ObjectMapper.readValue` overload is never called with untrusted input — input is only ever read from a typed message broker schema, never raw HTTP bodies. The vulnerable deserialiser path is not reachable.

Analyst sets the analysis:

- `analysis.state = NOT_AFFECTED`
- `analysis.justification = CODE_NOT_REACHABLE`
- `analysis.response = WILL_NOT_FIX`
- `analysis.comment = "ObjectMapper used only against typed Avro schemas via Spring Kafka; never raw bytes. Re-evaluate if a non-typed Kafka deserialiser is added. CodeQL run-id 4711."`

The team exports a CycloneDX VEX for this project (`GET /api/v1/vex/cyclonedx/project/{uuid}`) and stores it alongside the SBOM as a release artefact.

Engineer Triage inputs:

- **Reachability** = `VERIFIED_UNREACHABLE` (CodeQL data-flow confirmed; tier-2 evidence + Dependency-Track records it as `CODE_NOT_REACHABLE`).
- **Remediation Option** = `NO_PATCH` (recorded as `WILL_NOT_FIX` — the team is not bumping, because it is not affected).
- **Mitigation Option** = `NONE` (no mitigation needed; the path doesn't run).
- **Priority** = `DEFER` (despite EPSS 0.83 + HIGH, reachability removes the urgency).

{{< outcome type="cyclonedx" >}}
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "2026-05-14T10:00:00Z",
    "tools": [{ "vendor": "OWASP", "name": "Dependency-Track", "version": "4.14.2" }],
    "component": {
      "type": "application",
      "bom-ref": "acme-api@1.2.3",
      "name": "acme-api",
      "version": "1.2.3",
      "purl": "pkg:maven/com.acme/acme-api@1.2.3"
    }
  },
  "vulnerabilities": [{
    "bom-ref": "CVE-2022-42003-jackson",
    "id": "CVE-2022-42003",
    "source": { "name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-42003" },
    "ratings": [{
      "source": { "name": "NVD" },
      "score": 7.5,
      "severity": "high",
      "method": "CVSSv3",
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    }],
    "cwes": [502],
    "affects": [{
      "ref": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2"
    }],
    "analysis": {
      "state": "not_affected",
      "justification": "code_not_reachable",
      "response": ["will_not_fix"],
      "detail": "ObjectMapper used only against typed Avro schemas via Spring Kafka; never raw bytes. Re-evaluate if a non-typed Kafka deserialiser is added. CodeQL run-id 4711."
    }
  }]
}
```
{{< /outcome >}}

The next time CodeQL produces a VEX statement for `CVE-2022-42003-jackson` against this project, Dependency-Track will round-trip the same analysis cleanly — no double bookkeeping.

## Policy engine

Policies are evaluated at SBOM upload and on every vulnerability-data update. Violations route through the standard notification machinery.

**Violation types** (`model/PolicyViolation.java`):

```
LICENSE
SECURITY
OPERATIONAL
```

**States** (`model/Policy.java`) — also the gate severity:

```
INFO
WARN
FAIL
```

**Match operator** (`model/Policy.java`):

```
ALL    (every condition must match)
ANY    (any condition matches)
```

**Condition subjects** (`model/PolicyCondition.java`) — fifteen, including the v4.14.0 operational additions (`AGE`, `VERSION_DISTANCE`) and the v4.12.0 prioritisation condition (`EPSS`):

```
AGE
COORDINATES
CPE
LICENSE
LICENSE_GROUP
PACKAGE_URL
SEVERITY
SWID_TAGID
VERSION
IS_INTERNAL
COMPONENT_HASH
CWE
VULNERABILITY_ID
VERSION_DISTANCE
EPSS
```

**Operators**:

```
IS
IS_NOT
MATCHES
NO_MATCH
NUMERIC_GREATER_THAN
NUMERIC_LESS_THAN
NUMERIC_EQUAL
NUMERIC_NOT_EQUAL
NUMERIC_GREATER_THAN_OR_EQUAL
NUMERIC_LESSER_THAN_OR_EQUAL
CONTAINS_ALL
CONTAINS_ANY
```

A typical CI-gate policy: *fail* if any component carries an `EPSS NUMERIC_GREATER_THAN 0.5` finding *and* `SEVERITY IS HIGH` (match operator `ALL`, state `FAIL`). Pre-configured **license groups** (Copyleft, Permissive, …) ship out of the box and back the `LICENSE_GROUP` subject.

## Notifications and integrations

Notification publishers (`integrations/notifications/`):

- Slack, Microsoft Teams, Mattermost, Cisco WebEx
- Email (SMTP), Console, **Jira** (issue creation)
- Generic Webhook (the integration path for OpsGenie / PagerDuty / SOAR)

Notification groups, **PORTFOLIO** scope: `NEW_VULNERABILITY`, `NEW_VULNERABILITIES_SUMMARY`, `NEW_VULNERABLE_DEPENDENCY`, `GLOBAL_AUDIT_CHANGE`, `PROJECT_AUDIT_CHANGE`, `BOM_CONSUMED`, `BOM_PROCESSED`, `BOM_PROCESSING_FAILED`, `BOM_VALIDATION_FAILED`, `POLICY_VIOLATION`, `NEW_POLICY_VIOLATIONS_SUMMARY`.

Notification groups, **SYSTEM** scope: `ANALYZER`, `DATASOURCE_MIRRORING`, `INDEXING_SERVICE`, `FILE_SYSTEM`, `REPOSITORY`, `USER_CREATED`, `USER_DELETED`.

CI ingestion plugins (all official, all OSS):

- **Jenkins** — first-party plugin.
- **GitHub Actions** — `dependency-track/gh-upload-sbom-action`.
- **GitLab CI / CircleCI / Azure Pipelines / etc.** — `curl` against the REST API; widely-documented.

Defect-tracker sync (native, with suppression respected): **DefectDojo**, **Kenna Security**, **Fortify SSC**, **ThreadFix**.

Auth: API keys scoped to Teams (RBAC), OIDC (Keycloak / Okta / Azure AD / Google), LDAP / Active Directory, internal users.

## VEX round-trip — the strongest signal Dependency-Track gives you

Three properties make Dependency-Track the OSS reference implementation for VEX-as-triage-memory:

1. **Ingestion is auto-applying.** Upload a CycloneDX VEX document; statements matching `(component, vulnerability)` set the analysis state, justification, and response on the live finding. No manual step.
2. **The triage enums map 1:1 to the CycloneDX VEX spec.** `AnalysisState.NOT_AFFECTED` → CycloneDX `not_affected`; `AnalysisJustification.CODE_NOT_REACHABLE` → CycloneDX `code_not_reachable`; `AnalysisResponse.WILL_NOT_FIX` → CycloneDX `will_not_fix`. No translation layer.
3. **Export is per-project or portfolio**, and you can emit either a pure VEX document or a combined **CycloneDX VDR** (Vulnerability Disclosure Report — the SBOM inventory plus the embedded vulnerabilities and analysis decisions in a single signed-able document).

Gaps:

- **OpenVEX** is **not** natively consumed or emitted. Use `vexctl` or `cyclonedx-cli` to convert before upload.
- **CSAF** is **not** natively consumed or emitted.
- **Cosign signing** of the emitted SBOM / VEX / VDR is **not** built in. Sign as a post-processing step with `cosign sign-blob` and store the signature alongside the artefact. The Vulnetix [compliance-bundler](../appendices/glossary/) wraps this if you want a signed bundle out of the box.

## What Dependency-Track does NOT do

Honest gaps — call these out so a stack-design decision is informed:

- **No source-code SAST.** Pair with [CodeQL](github-codeql/) / [Snyk SAST](snyk-sast/) / [Semgrep](semgrep-opengrep/).
- **No IaC misconfiguration scanning.** Pair with [KICS](kics/) or [Trivy](trivy/) (`trivy config`).
- **No secrets detection.** Pair with [GH Secrets](github-secrets/) / [GitLab Secrets](gitlab-secrets/) / gitleaks.
- **No DAST or active probing.** Pair with [GitLab DAST](gitlab-dast/) (OWASP ZAP-based) or ZAP directly.
- **No container-image binary scan of its own.** Configure an external Trivy server as a delegated analyzer (v4.12.0+), or pre-produce the image SBOM with syft / Trivy and upload it.
- **No call-graph reachability.** Tier 1 only. For Tier 2 evidence, ingest VEX from a tool that does call-graph analysis.
- **No git-history scanning.** Server-side; sees only what the uploaded SBOM enumerates.
- **No native SPDX ingestion or emission** — convert SPDX to CycloneDX first (`cyclonedx-cli convert`).
- **No native OpenVEX or CSAF ingestion** — convert.
- **No SSVC field.** The triage vocabulary is CycloneDX VEX-shaped, not SSVC-shaped.
- **No first-party CISA KEV feed.** KEV reaches the platform only indirectly via Trivy or NVD passthrough — cross-reference `vulnetix vdb vuln <CVE>` for `x_kev.knownRansomwareCampaignUse` / `x_kev.dueDate` / `x_kev.requiredAction`.
- **No AI-malware family signatures or typosquat / dependency-confusion gates.** Pair with `vulnetix:dep-add-guard` or `vulnetix:typosquat-check` pre-add.
- **No CLI.** Every action goes through the REST API.
- **No auto-PR / auto-MR generation.** Notifications fire (Jira issue, webhook, Slack); the actual upgrade-PR is your CI's job.

Where this site's other pages emit detection content (Snort / YARA / Nuclei / Sigma / ModSecurity / traffic-filters), Dependency-Track emits **none** of it. Triage memory lives in PostgreSQL; the export surface is CycloneDX. For detection-rule generation, use Vulnetix's [detection-rules](../appendices/glossary/) family.

## Pairing recommendations

The strongest stack with Dependency-Track at its centre:

- **SBOM producers** — CycloneDX Maven / Gradle plugins for JVM, `cyclonedx-bom` for Python / Node / Go / .NET, [syft](https://github.com/anchore/syft) for container images, [Trivy](trivy/) for OS-distro + image-binary.
- **Reachability evidence** — [CodeQL](github-codeql/) or [Snyk SAST](snyk-sast/), emit VEX, ingest into Dependency-Track for `CODE_NOT_REACHABLE` round-trip.
- **IaC / Dockerfile** — [KICS](kics/) or [Trivy](trivy/) (`trivy config`); these run alongside, not through, Dependency-Track.
- **Enrichment** — [Vulnetix](vulnetix/) for KEV / EU-KEV / weaponisation maturity / sightings / SSVC / AI-discovery / typosquat / detection-rule generation — the row-by-row gaps in the [matrix](../#capability-matrix) are the integration surface.

## Capability snapshot

See the [capability matrix](../#capability-matrix) for the full comparison. Dependency-Track summary:

- **Coverage**: SBOM-consuming Component Analysis (SCA + license compliance via the policy engine). No SAST, no IaC, no secrets, no DAST, no container-binary, no git-history scan.
- **Database quality**: aggregator over NVD 2.0 + GHSA + OSV + VulnDB + OSS Index + Snyk + Trivy ([sufficient](../#database-quality-tiers); no first-party enrichment).
- **[Reachability](../appendices/reachability-deep-dive/)**: **[Tier 1](../appendices/reachability-deep-dive/#tier-1)** — package / component-level. Tier 2 evidence only via ingested VEX.
- **Triage vocabulary**: CycloneDX VEX-shaped — `AnalysisState` / `AnalysisJustification` / `AnalysisResponse` round-trip 1:1 with CycloneDX `analysis.state` / `justification` / `response`.
- **Outputs**: REST API JSON, CycloneDX SBOM (v1.5 emit / v1.6 ingest), CycloneDX VEX, **CycloneDX VDR** (combined inventory + vulnerabilities + analysis), FPF. No SARIF, no OpenVEX, no CSAF, no SPDX, no STIX.
- **License**: Apache-2.0 OSS — **OWASP Flagship Project**. Fully self-hostable; the only paid pieces are the optional commercial *external* analyzers (VulnDB, Snyk).

## See also

- [Capability matrix](../#capability-matrix).
- [CycloneDX VEX appendix](../appendices/cyclonedx-vex/) — the format the Dependency-Track triage round-trip produces.
- [SSVC Engineer Triage](../appendices/ssvc/) — the bridging vocabulary the `From finding to root cause` section maps onto.
- [Reachability deep-dive](../appendices/reachability-deep-dive/) — the three-tier model.
- [Glossary](../appendices/glossary/).
- [dependencytrack.org](https://dependencytrack.org/) · [docs](https://docs.dependencytrack.org/) · [GitHub](https://github.com/DependencyTrack/dependency-track) · [OWASP project page](https://owasp.org/www-project-dependency-track/).
