---
title: "GitHub CodeQL"
description: "Semantic query-based SAST — extracts a relational model of your code and runs security queries against it."
weight: 80
---

> **GitHub built-in** · Free for public repositories; [GitHub Advanced Security](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security) (commercial) for private · Engine + standard queries: [github/codeql](https://github.com/github/codeql) (MIT) · [Query docs](https://codeql.github.com/) · [Code Scanning docs](https://docs.github.com/en/code-security/code-scanning) · CLI distribution gated.

CodeQL extracts a database from your source — per language, after a build for compiled languages — and runs queries from the standard query packs against it. Findings surface as code-scanning alerts on the Security tab, as inline comments on merge requests, and as SARIF stored against the analysis. The triage entry point is `gh api` for programmatic access; the UI is the same data with click-through to the codeFlow trace.

CodeQL is the one place this site recommends a vendor action: `github/codeql-action` in your workflow. The alternative is shipping the CodeQL CLI yourself, which is awkward enough that the vendor action's convenience wins.

## What CodeQL finds

CodeQL findings live on GitHub's side, accessible via REST or by downloading the SARIF artefact:

```bash
# REST — list all open alerts
gh api /repos/{owner}/{repo}/code-scanning/alerts --paginate > codeql-alerts.json

# Download the SARIF for the most recent analysis
ANALYSIS=$(gh api /repos/{owner}/{repo}/code-scanning/analyses \
            --paginate --jq '.[0].id')
gh api /repos/{owner}/{repo}/code-scanning/analyses/$ANALYSIS \
  -H "Accept: application/sarif+json" > codeql.sarif
```

Per-alert fields (REST `/code-scanning/alerts`):

| Field | Purpose |
|---|---|
| `number` | The alert's stable ID — used to dismiss / re-open via the API |
| `state` | `open` / `dismissed` / `fixed` |
| `dismissed_reason` | When dismissed: `false positive` / `won't fix` / `used in tests` |
| `rule.id` | The CodeQL query ID — e.g. `js/sql-injection`, `py/path-injection`, `java/xxe` |
| `rule.severity` | `error` / `warning` / `note` |
| `rule.security_severity_level` | `critical` / `high` / `medium` / `low` — the CVSS-style mapping |
| `rule.tags[]` | `security`, `external/cwe/cwe-89`, `external/owasp/A03:2021`, etc. |
| `most_recent_instance.location.path` + `.start_line` | Source location |
| `most_recent_instance.message.text` | Short description |

Per-result fields (SARIF `runs[].results[]`):

| Field | Purpose |
|---|---|
| `ruleId` | Same as REST `rule.id` |
| `level` | `error` / `warning` / `note` |
| `message.text` | Description |
| `locations[].physicalLocation.artifactLocation.uri` + `.region.startLine` | Sink location |
| `codeFlows[]` | Source-to-sink taint flow |
| `partialFingerprints` | Stable hashes for tracking findings across commits |
| `properties.security-severity` | Numeric CVSS-style score (e.g. `9.8`) |

## Querying with jq

```bash
# Open alerts as {number, rule, severity, file, line}
jq '[.[] | select(.state == "open") | {
       number,
       rule: .rule.id,
       severity: .rule.security_severity_level,
       cwe: ([.rule.tags[]
              | select(startswith("external/cwe/"))
              | sub("external/cwe/"; "")]
             | join(",")),
       file: .most_recent_instance.location.path,
       line: .most_recent_instance.location.start_line
     }]' codeql-alerts.json

# Filter to critical + high
jq '.[] | select(.state == "open"
                 and (.rule.security_severity_level == "critical"
                      or .rule.security_severity_level == "high"))' \
   codeql-alerts.json

# Group by rule — which queries fire most?
jq '[.[] | select(.state == "open") | {rule: .rule.id}]
    | group_by(.rule)
    | map({rule: .[0].rule, count: length})
    | sort_by(-.count)' codeql-alerts.json

# From the SARIF file — trace the codeFlow for one finding
jq '.runs[].results[0].codeFlows[0].threadFlows[0].locations[]
    | {
        file: .location.physicalLocation.artifactLocation.uri,
        line: .location.physicalLocation.region.startLine,
        message: .location.message.text
      }' codeql.sarif
```

## From finding to root cause

Every CodeQL query has an official documentation page at `https://codeql.github.com/codeql-query-help/<language>/<query-id>/` — e.g. `https://codeql.github.com/codeql-query-help/javascript/js-sql-injection/`. The page has the description, the vulnerable pattern, the fix pattern, and links to relevant CWE / OWASP references.

```bash
# Get the docs URL for an alert
RULE=$(gh api /repos/{owner}/{repo}/code-scanning/alerts/42 --jq '.rule.id')
LANG=$(echo "$RULE" | cut -d/ -f1)
QUERY=$(echo "$RULE" | cut -d/ -f2)
echo "https://codeql.github.com/codeql-query-help/${LANG}/${LANG}-${QUERY}/"
```

The triage path:

1. Read the rule docs page on `codeql.github.com`.
2. Read the codeFlow trace to identify the source location and the variable chain.
3. Assess reachability + adversary controllability of the source.
4. Either fix the code or document with OpenVEX `not_affected`.

CodeQL findings are first-party code, so the Vulnetix `vdb` integration is light — there's no CVE behind a CodeQL alert. Engineer Triage inputs come from CodeQL + your knowledge of the codebase:

- **Reachability** — codeFlow trace + your knowledge of which routes actually run.
- **Remediation Option** — `PATCHABLE_MANUAL` (the rule docs describe the fix; you apply it).
- **Mitigation Option** — `CODE_CHANGE`. `INFRASTRUCTURE` mitigation is possible for some classes (WAF in front of SQL injection sinks) but never sufficient on its own.
- **Priority** — `rule.security_severity_level` plus your understanding of the exposure.

See [SSVC Engineer Triage](../appendices/ssvc/).

## Decision tree

{{< decision >}}
Does the finding tie to a known library API (e.g. `java/jwt-missing-verification` against a JWT library)?
  ├─ Yes → CycloneDX VEX referencing the library PURL, alongside the OpenVEX
  └─ No  (first-party source code) → OpenVEX, subject is the repo at the scanned commit

Dismissing the alert on GitHub?
  → Set `dismissed_reason` on the alert via gh api PATCH /repos/.../code-scanning/alerts/<number>,
    then ALSO write the matching OpenVEX statement. GitHub's dismissal records the action;
    the OpenVEX records the reasoning your future-self and an auditor will want.
{{< /decision >}}

## Worked example: `js/sql-injection` flagged on an Express handler

CodeQL alert #134 in a Node.js project:

```json
{
  "number": 134,
  "state": "open",
  "rule": {
    "id": "js/sql-injection",
    "severity": "error",
    "security_severity_level": "high",
    "tags": ["security", "external/cwe/cwe-089", "external/owasp/owasp-a03"]
  },
  "most_recent_instance": {
    "location": {
      "path": "src/api/users.js",
      "start_line": 38,
      "start_column": 5
    },
    "message": { "text": "This query depends on a user-provided value." }
  }
}
```

The SARIF for the same alert has the codeFlow trace — the source is `req.params.id` reaching `db.query` template literal at line 38.

Open the rule docs: `https://codeql.github.com/codeql-query-help/javascript/js-sql-injection/`. The page describes parameterised queries as the fix.

The vulnerable code (from the codeFlow):

```javascript
// src/api/users.js
app.get('/api/users/:id', (req, res) => {
  const id = req.params.id;
  db.query(`SELECT * FROM users WHERE id = ${id}`, (err, rows) => {
    res.json(rows);
  });
});
```

Fix:

```javascript
app.get('/api/users/:id', (req, res) => {
  const id = req.params.id;
  db.query("SELECT * FROM users WHERE id = ?", [id], (err, rows) => {
    res.json(rows);
  });
});
```

Engineer Triage:

- **Reachability** = `VERIFIED_REACHABLE` (codeFlow proves the taint; the route is the user-list page, served on every request)
- **Remediation Option** = `PATCHABLE_MANUAL` (CODE_CHANGE)
- **Mitigation Option** = `CODE_CHANGE` (parameterised query)
- **Priority** = `HIGH` (`rule.security_severity_level: high`; CVE-style CVSS 7.5)

Outcome: `SPIKE_EFFORT` for sprint-scoped fix; `DROP_TOOLS` if the route is currently exposed to the public internet without intermediate auth.

After fixing, dismiss the alert on GitHub and write the matching OpenVEX:

```bash
gh api -X PATCH /repos/{owner}/{repo}/code-scanning/alerts/134 \
  -F state=dismissed -F dismissed_reason='false positive' \
  -F dismissed_comment='Replaced with parameterised query in MR !101'
# (Use 'won't fix' if accepting the risk; 'used in tests' for test-fixture matches)
```

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-codeql-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:00:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": {
      "name": "js/sql-injection",
      "description": "SQL injection (CWE-89) via template-literal composition in src/api/users.js:38. CodeQL alert #134. See https://codeql.github.com/codeql-query-help/javascript/js-sql-injection/"
    },
    "products": [{
      "@id": "https://github.com/yourorg/yourrepo",
      "identifiers": { "purl": "pkg:github/yourorg/yourrepo@abc1234" }
    }],
    "status": "fixed",
    "action_statement": "Engineer Triage: SPIKE_EFFORT. Inputs: reachability=VERIFIED_REACHABLE (CodeQL codeFlow trace; route is /api/users/:id, served on every users-page request), remediation=PATCHABLE_MANUAL, mitigation=CODE_CHANGE, priority=HIGH. Replaced template-literal SQL with parameterised query in src/api/users.js. CodeQL alert #134 dismissed. See MR !101."
  }]
}
```
{{< /outcome >}}

## Producing a CycloneDX VEX (cross-cutting library rules)

When the CodeQL rule targets a specific library API — e.g. `java/jwt-missing-verification` against `io.jsonwebtoken:jjwt`, or `py/insecure-deserialization` against `pyyaml.load` — pair the OpenVEX with a CycloneDX VEX entry referencing the library's PURL:

{{< outcome type="cyclonedx" >}}
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "vulnerabilities": [{
    "id": "py/insecure-deserialization",
    "source": { "name": "CodeQL" },
    "affects": [{ "ref": "pkg:pypi/pyyaml@6.0.1" }],
    "analysis": {
      "state": "not_affected",
      "justification": "code_not_reachable",
      "detail": "pyyaml is imported but only safe_load is used. Verified by `jq '.runs[].results[] | select(.ruleId==\"py/insecure-deserialization\")' codeql.sarif` returning zero results (the rule's matched API is `yaml.load` per the SARIF rule definition), cross-checked with `git grep -nE '\\byaml\\.load\\b' src/`. Engineer Triage: BACKLOG."
    }
  }]
}
```
{{< /outcome >}}
