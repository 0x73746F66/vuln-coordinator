---
title: "SARIF — the SAST output format"
description: "Static Analysis Results Interchange Format. The JSON shape every SAST tool emits, with the dialect differences that catch you out."
weight: 25
---

SARIF (Static Analysis Results Interchange Format) is an [OASIS standard](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) for static-analysis tool output. Every SAST tool on this site emits it — [CodeQL](../../scanners/github-codeql/), [Snyk SAST](../../scanners/snyk-sast/), [Semgrep / Opengrep](../../scanners/semgrep-opengrep/), [Vulnetix SAST](../../scanners/vulnetix/sast/), GitLab's [SAST analyser](../../scanners/gitlab-dependencies/) — and so do most SCA tools (Snyk OSS, Grype, osv-scanner) for cross-tool ingestion.

SARIF is consumed by GitHub Code Scanning, GitLab Security Dashboard, Azure DevOps, and Vulnetix `vdb ingest`. The format is verbose; this page is the field map you'll want when you stare at a 50 KB SARIF and need to find the one finding that matters.

For terminology used here, see the [Glossary](glossary/).

## The shape

```json
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "CodeQL",
          "version": "2.15.0",
          "rules": [ /* one entry per rule the tool can fire */ ]
        }
      },
      "results": [ /* one entry per finding */ ],
      "artifacts": [ /* the files the tool scanned */ ],
      "invocations": [ /* how the tool was invoked */ ]
    }
  ]
}
```

A single SARIF file can hold multiple `runs[]`, one per tool invocation. Most CIs concatenate runs into one file for upload.

## The rule vs the result

A common confusion: `runs[].results[].message.text` is *this finding's* message; `runs[].tool.driver.rules[].help.markdown` is *the rule's* documentation. Readers wanting the full explanation of *why* this CWE matters should read the rule, not the result.

```bash
# Pull the rule docs for a result
RULE=$(jq -r '.runs[0].results[0].ruleId' codeql.sarif)
jq -r --arg id "$RULE" '
  .runs[0].tool.driver.rules[]
  | select(.id == $id)
  | .help.markdown' codeql.sarif
```

The `ruleId` field on a result keys into `runs[].tool.driver.rules[].id`. Tools sometimes also populate `rules[].helpUri` — a URL to the canonical documentation.

## Per-result fields developers actually touch

| Field | What it carries | Notes |
|---|---|---|
| `ruleId` | The rule's stable ID | `js/sql-injection`, `python.lang.security.audit.subprocess-shell-true`, `VNX-JAVA-001` |
| `level` | `error` / `warning` / `note` | Tool's recommended severity |
| `message.text` | One-line description for this instance | Distinct from the rule-level docs |
| `locations[]` | Where the finding is | See *Locations* below |
| `codeFlows[]` | Source-to-sink data flow trace | Only present for [taint-flow](glossary/#taint-flow) findings; see *codeFlow* below |
| `partialFingerprints` | Stable hashes for cross-scan tracking | Used by Code Scanning / Security Dashboard for deduplication |
| `properties.security-severity` | Numeric CVSS-style score (0–10) | The float you sort by when triaging |
| `properties.tags[]` | Free-form labels | Often carries `external/cwe/cwe-89`, `external/owasp/A03:2021`, `security` |
| `suppressions[]` | Inline suppressions on this result | If non-empty, the finding has been previously dismissed |
| `baselineState` | `new` / `existing` / `updated` / `unchanged` / `absent` | Set when the SARIF is generated as a diff against a baseline |

## Locations

A finding's location is a chain — file → region (line+column). The minimal walk:

```bash
jq '.runs[].results[]
    | { rule: .ruleId,
        file: .locations[0].physicalLocation.artifactLocation.uri,
        line: .locations[0].physicalLocation.region.startLine,
        col:  .locations[0].physicalLocation.region.startColumn,
        endLine: .locations[0].physicalLocation.region.endLine,
        msg:  .message.text }' sarif.json
```

`physicalLocation.artifactLocation.uri` is the file path; `physicalLocation.region` is the matched range. Some tools (CodeQL especially) populate `logicalLocations[]` with the enclosing function name — handy for grouping.

## codeFlow — the taint trace

For tools that perform taint analysis (CodeQL, Snyk SAST, Semgrep Pro with `--pro`, some Vulnetix SAST rules), `result.codeFlows[]` records the path from a tainted *source* through every transformation to a dangerous *sink*. Each `codeFlow` contains one or more `threadFlows[]`; each `threadFlow` contains `locations[]` ordered from source to sink.

```bash
# Walk a single codeFlow as {file, line, message} steps
jq '.runs[].results[0].codeFlows[0].threadFlows[0].locations[]
    | { file: .location.physicalLocation.artifactLocation.uri,
        line: .location.physicalLocation.region.startLine,
        step: .location.message.text }' sarif.json
```

A reader who follows the codeFlow sees the *full* path — e.g. `req.query.q` at line 18 → assigned to `q` at line 19 → interpolated into a template literal at line 24 → passed to `db.query` at line 25. That's evidence enough to make a [Tier 2 reachability claim](reachability-deep-dive/#tier-2).

## partialFingerprints — cross-scan tracking

`result.partialFingerprints` is the field that makes scans diffable. The values are stable hashes over the rule + a normalised view of the location/context, designed to survive whitespace changes, line-number drift, and minor edits. GitHub Code Scanning uses them to mark a finding as "the same" across commits.

```bash
# Find the same finding across two scans
SCAN_A_FP=$(jq -r '.runs[].results[] | select(.ruleId=="js/sql-injection") | .partialFingerprints.primaryLocationLineHash' scan-a.sarif)
jq --arg fp "$SCAN_A_FP" \
   '.runs[].results[] | select(.partialFingerprints.primaryLocationLineHash == $fp)' \
   scan-b.sarif
```

Different tools emit different fingerprint families (`primaryLocationLineHash`, `contextRegionHash`, `tool-specific`). When a tool changes versions, fingerprints may also change — track over a reasonable window only.

## jq query patterns

```bash
# Flatten every finding
jq '.runs[].results[]
    | { rule: .ruleId, level, sev: .properties."security-severity",
        file: .locations[0].physicalLocation.artifactLocation.uri,
        line: .locations[0].physicalLocation.region.startLine,
        msg: .message.text }' sarif.json

# Filter to security findings (most tools tag security results)
jq '.runs[].results[]
    | select(.properties.tags[]? | startswith("security") or contains("cwe"))' sarif.json

# Group by rule
jq '[.runs[].results[] | { rule: .ruleId }]
    | group_by(.rule)
    | map({ rule: .[0].rule, count: length })
    | sort_by(-.count)' sarif.json

# CWE rollup — feeds compliance reporting
jq '[.runs[].results[].properties.tags[]?
     | select(startswith("external/cwe/"))]
    | group_by(.)
    | map({ cwe: .[0], count: length })' sarif.json

# Critical/high security-severity findings
jq '.runs[].results[]
    | select((.properties."security-severity" // "0") | tonumber >= 7.0)' sarif.json

# New findings (when baseline is set)
jq '.runs[].results[] | select(.baselineState == "new")' sarif.json

# Suppressed findings
jq '.runs[].results[] | select(.suppressions != null and (.suppressions | length) > 0)' sarif.json
```

## Per-tool applicability — SARIF dialects

Every tool below emits SARIF, but the *shape* varies in ways that matter for your queries. The notes flag the dialect-specific fields you'll touch most.

| Tool | codeFlows | partialFingerprints | security-severity | Notes |
|---|---|---|---|---|
| **CodeQL** | ✅ Full taint flow | ✅ `primaryLocationLineHash` | ✅ Numeric | Richest SARIF dialect. `runs[].results[].relatedLocations[]` carries supplementary annotations. `automationDetails.id` identifies the workflow run. |
| **Snyk SAST (Code)** | ✅ Embedded codeFlow | ✅ `tool-specific` | ✅ Numeric | Carries `properties.snyk` extension fields (`snyk:fingerprint`, severity rationale). Some SARIF readers ignore `properties.snyk` — query `properties.security-severity` for the sortable number. |
| **Semgrep Pro / Opengrep `--pro`** | ✅ codeFlows | 🟡 Partial | ✅ Numeric in Pro | Pro mode adds taint flow. OSS engine emits SARIF *without* codeFlows. `properties.semgrep_metadata` carries Semgrep-specific fields. |
| **Semgrep OSS / Opengrep (default)** | ❌ Flat | 🟡 Partial | 🟡 String severity only | No taint trace — pattern-match only. `result.message.text` carries the matched-line description. |
| **Vulnetix SAST** | 🟡 Per-rule | ✅ `primaryLocationLineHash` | ✅ Numeric | Vulnetix-specific rule metadata in `tool.driver.rules[].properties`. See [Vulnetix SAST](../../scanners/vulnetix/sast/). Some Vulnetix rules emit codeFlow; pattern-match rules don't. |
| **GitLab SAST (Semgrep-based)** | 🟡 Depends on analyser | 🟡 Per-analyser | 🟡 String severity | GitLab also produces gemnasium-flavoured Security Report JSON alongside the SARIF; the two formats are not identical. SARIF is the cross-tool path; the gemnasium JSON is the GitLab-native one. |
| **Grype (SARIF output)** | ❌ Flat | ✅ Per-match | ✅ Numeric | SARIF is provided for compatibility (`-o sarif`) — Grype's primary format is the rich JSON. codeFlows don't apply (SCA, not SAST). |
| **Snyk OSS (SARIF output)** | ❌ Flat | ✅ | ✅ Numeric | Same shape as Snyk SAST but no codeFlow (SCA findings). |
| **osv-scanner (SARIF output)** | ❌ Flat | 🟡 Limited | 🟡 String severity | OSV-Scanner's SARIF is a minimal projection of the OSV schema; the JSON output carries more detail. |
| **GitHub Dependabot** | ❌ Flat | ✅ via API | 🟡 String severity | Dependabot doesn't emit SARIF files directly — its alerts surface via the GitHub Code Scanning REST API, which uses SARIF-shaped JSON. |
| **CodeQL custom queries** | ✅ if query returns paths | ✅ | ✅ if `@security-severity` set | Custom queries can include `@security-severity 8.5` in their metadata, surfacing the numeric score. |

## Database quality and SARIF

SARIF is a *format*, not a feed source. A SARIF file's findings depend on the rules the tool ran, which in turn depend on:

- The tool's first-party rule pack (CodeQL standard queries, Semgrep registry, Snyk's catalogue).
- Any custom rules you've added (`.semgrep/`, `.github/codeql/custom-queries/`).
- The vulnerability database the tool consults (relevant for [SCA tools emitting SARIF](#per-tool-applicability--sarif-dialects); see [database quality tiers in the capability matrix](../../scanners/#capability-matrix)).

Two SARIF outputs from different tools on the same code will disagree, often substantially. Reconcile them via [partialFingerprints](#partialfingerprints--cross-scan-tracking) plus rule-tag normalisation (the `external/cwe/cwe-NNN` tag is the most cross-tool-stable identifier).

## When SARIF isn't enough

SARIF cannot express:
- [VEX](vex/) statements (it's a findings format, not a triage-decision format).
- [SBOM](cyclonedx-sbom/) component inventory.
- Reachability tier (it can encode codeFlow → Tier 2 evidence; it can't say "Tier 3 via reflection").
- Continuous baselines older than the current scan's `automationDetails.id`.

For those, pair SARIF with CycloneDX SBOM + VEX. Many CI pipelines emit all three.

## See also

- [VEX overview](vex/) — how SARIF findings become triage decisions.
- [SSVC Engineer Triage](ssvc/) — the framework that turns a SARIF finding into a developer action.
- [Reachability deep-dive](reachability-deep-dive/) — what `codeFlows[]` actually proves, and what it doesn't.
- [Capability matrix](../../scanners/#capability-matrix) — which tool emits which SARIF dialect.
- [Glossary](glossary/) — definitions for the terms used above.
