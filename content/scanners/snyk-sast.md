---
title: "Snyk Code (SAST)"
description: "Snyk's taint-flow static analysis — SARIF 2.1.0 output with code-flow traces source-to-sink."
weight: 20
---

> **Commercial** (Snyk Ltd) · [Docs](https://docs.snyk.io/scan-using-snyk/snyk-code) · CLI source: [snyk/cli](https://github.com/snyk/cli) (Apache-2.0) · Free tier with monthly test caps; paid plans for full features.

Snyk Code parses your source, builds a control- and data-flow graph, and flags taint paths matching its library of weakness patterns — CWE-mapped, across most mainstream languages. The output you'll consume is SARIF 2.1.0 from `snyk code test --sarif-file-output`. Findings surface in CI, IDE, and merge-request decorations, all reading the same SARIF.

The killer field is `codeFlows[]` — the actual traced data path from source to sink. Without it you're reading "SQL injection in some/file.py" and guessing; with it you see "request param `name` flows through `user_filter` into `cursor.execute()` at line 42".

## What Snyk Code finds in SARIF

```bash
snyk code test --sarif-file-output=snyk-code.sarif
```

Top-level shape (SARIF 2.1.0):

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0-rtm.4.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": { "name": "SnykCode", "rules": [ /* rule definitions */ ] } },
      "results": [ /* findings */ ]
    }
  ]
}
```

Per-finding fields in `runs[].results[]`:

| Field | Purpose |
|---|---|
| `ruleId` | The Snyk Code rule identifier — `javascript/sqlInjection`, `python/CommandInjection`, etc. Reference page at `security.snyk.io/rules/<ruleId>` |
| `level` | `note` / `warning` / `error` — Snyk's mapping from severity |
| `message.text` | Short description of what fired |
| `locations[].physicalLocation.artifactLocation.uri` | File path |
| `locations[].physicalLocation.region.startLine` + `.startColumn` | The sink location |
| `codeFlows[]` | One or more traced taint flows. Each flow has `threadFlows[].locations[]` — an ordered list from source to sink |
| `fingerprints` | Stable hashes for cross-commit tracking |
| `properties.priorityScore` | Snyk's internal priority (0–1000) |

The `tool.driver.rules[]` array carries the rule definitions — useful to cross-reference if the same rule fires many times:

```json
{
  "id": "javascript/sqlInjection",
  "name": "SQL Injection",
  "shortDescription": { "text": "SQL Injection" },
  "fullDescription": { "text": "..." },
  "properties": {
    "tags": ["security", "CWE-89"],
    "categories": ["Injection"],
    "exampleCommitFixes": [ /* anonymised before/after diffs */ ]
  }
}
```

## Querying with jq

```bash
# Every finding flattened
jq '.runs[].results[] | {
      ruleId,
      level,
      file: .locations[0].physicalLocation.artifactLocation.uri,
      line: .locations[0].physicalLocation.region.startLine,
      message: .message.text
    }' snyk-code.sarif

# Group by rule for "what kinds of issue do we have?"
jq '[.runs[].results[].ruleId]
    | group_by(.)
    | map({rule: .[0], count: length})
    | sort_by(-.count)' snyk-code.sarif

# Filter to errors only
jq '.runs[].results[] | select(.level == "error")' snyk-code.sarif

# Trace the codeFlow for one finding — source → sink path
jq '.runs[].results[0].codeFlows[0].threadFlows[0].locations[]
    | {
        file: .location.physicalLocation.artifactLocation.uri,
        line: .location.physicalLocation.region.startLine,
        message: .location.message.text
      }' snyk-code.sarif

# Findings ordered by Snyk's internal priority score
jq '[.runs[].results[]
     | {ruleId, score: .properties.priorityScore, file: .locations[0].physicalLocation.artifactLocation.uri}]
    | sort_by(-.score)' snyk-code.sarif

# Stable fingerprints — track the same finding across commits
jq '.runs[].results[] | {
      fp: .fingerprints,
      ruleId,
      file: .locations[0].physicalLocation.artifactLocation.uri
    }' snyk-code.sarif
```

## From finding to root cause

The triage path for SAST findings is always: **rule → reachability + adversary controllability → fix or document**.

```bash
# 1. Get the ruleId for the most-fired rule (or read it off the report)
RULE=$(jq -r '[.runs[].results[].ruleId] | group_by(.) | sort_by(-length) | .[-1][0]' snyk-code.sarif)

# 2. Open the rule docs page in your browser
# security.snyk.io/rules/<lang>/<rule-id>  — e.g. security.snyk.io/rules/javascript/sqlInjection
echo "https://security.snyk.io/rules/${RULE}"

# 3. Read the codeFlow trace for an instance — find the source
jq --arg r "$RULE" '.runs[].results[]
    | select(.ruleId == $r)
    | .codeFlows[0].threadFlows[0].locations[0]
    | {file: .location.physicalLocation.artifactLocation.uri,
       line: .location.physicalLocation.region.startLine,
       source_msg: .location.message.text}' snyk-code.sarif

# 4. Assess: can an attacker reach the source? Is the input on the path controllable?
```

For SAST findings the Vulnetix `vdb` integration is less direct — there's typically no CVE behind a Snyk Code finding (it's first-party source, not a packaged advisory). Engineer Triage applies with all four inputs sourced locally:

- **Reachability** — does the file (and the specific function/method) execute in production? Check coverage + runtime traces.
- **Remediation Option** — almost always `CODE_CHANGE` for SAST. `AUTOMATION` applies only if a deterministic safe rewrite is available (e.g. switch every `eval` to `JSON.parse`).
- **Mitigation Option** — for taint-flow findings, an `INFRASTRUCTURE` mitigation (WAF rule) is sometimes possible if the source is HTTP input.
- **Priority** — Snyk's `level` (`error` ~ HIGH, `warning` ~ MEDIUM, `note` ~ LOW). Override based on the source/sink reach if it's clearly worse than the level suggests.

See [SSVC Engineer Triage](../appendices/ssvc/).

## Decision tree

SAST findings sit in first-party code, not in an SBOM component, so the format choice is almost always OpenVEX.

{{< decision >}}
Does the finding tie to a known library API (e.g. `crypto/sha1.New` flagged by a cross-cutting crypto rule)?
  ├─ Yes → CycloneDX VEX referencing the library PURL is appropriate alongside the OpenVEX
  └─ No  (first-party source code) → OpenVEX, subject is the repo at the scanned commit

Need a WAF / IPS / SIEM mitigation while the code fix is in flight?
  → vulnetix vdb traffic-filters <related-CVE> if a related CVE exists;
    or write the rule yourself with vulnetix vdb snort-rules / vdb nuclei as starting points
{{< /decision >}}

## Worked example: `javascript/sqlInjection` in an Express handler

Snyk Code flags `src/api/search.js` line 24:

```json
{
  "ruleId": "javascript/sqlInjection",
  "level": "error",
  "message": { "text": "Untrusted user input flows into a SQL query construction" },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": { "uri": "src/api/search.js" },
      "region": { "startLine": 24 }
    }
  }],
  "codeFlows": [{
    "threadFlows": [{
      "locations": [
        {
          "location": {
            "physicalLocation": {
              "artifactLocation": { "uri": "src/api/search.js" },
              "region": { "startLine": 18 }
            },
            "message": { "text": "(req.query.q)" }
          }
        },
        {
          "location": {
            "physicalLocation": {
              "artifactLocation": { "uri": "src/api/search.js" },
              "region": { "startLine": 24 }
            },
            "message": { "text": "db.query(`SELECT * FROM users WHERE name LIKE '%${q}%'`)" }
          }
        }
      ]
    }]
  }],
  "properties": { "priorityScore": 850 }
}
```

The flow says: `req.query.q` (an attacker-controllable HTTP parameter) flows directly into a SQL string at line 24. No sanitisation. This is the textbook case.

The vulnerable code:

```javascript
// src/api/search.js
app.get('/api/search', (req, res) => {
  const q = req.query.q;
  db.query(`SELECT * FROM users WHERE name LIKE '%${q}%'`, (err, rows) => {
    res.json(rows);
  });
});
```

Fix — parameterised query:

```javascript
app.get('/api/search', (req, res) => {
  const q = req.query.q;
  db.query(
    "SELECT * FROM users WHERE name LIKE ?",
    [`%${q}%`],
    (err, rows) => res.json(rows)
  );
});
```

Engineer Triage:

- **Reachability** = `VERIFIED_REACHABLE` (Snyk's codeFlow is the evidence — taint reaches the sink)
- **Remediation Option** = `PATCHABLE_MANUAL` (CODE_CHANGE — there's no library bump, you rewrite the call)
- **Mitigation Option** = `CODE_CHANGE` (parameterised query). A WAF rule (`INFRASTRUCTURE`) could be an interim mitigation but it's not a substitute.
- **Priority** = `HIGH` (Snyk `level: error`, priorityScore 850; CWE-89 with a reachable source on the HTTP boundary)

Outcome: `DROP_TOOLS` if this is in production right now, `SPIKE_EFFORT` if scope-and-fix can wait for the current sprint.

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-snykcode-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:00:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": {
      "name": "javascript/sqlInjection",
      "description": "SQL injection (CWE-89) in src/api/search.js:24. See https://security.snyk.io/rules/javascript/sqlInjection"
    },
    "products": [{
      "@id": "https://github.com/yourorg/yourrepo",
      "identifiers": { "purl": "pkg:github/yourorg/yourrepo@abc1234" }
    }],
    "status": "fixed",
    "action_statement": "Engineer Triage: SPIKE_EFFORT. Inputs: reachability=VERIFIED_REACHABLE (Snyk codeFlow shows req.query.q at line 18 reaching db.query template literal at line 24), remediation=PATCHABLE_MANUAL, mitigation=CODE_CHANGE (parameterised query), priority=HIGH. Replaced template-literal SQL composition with parameterised query in src/api/search.js. Confirmed no other ruleId=javascript/sqlInjection results on re-scan. See MR !87."
  }]
}
```
{{< /outcome >}}

## Producing a CycloneDX VEX (cross-cutting library rules)

Some Snyk Code rules target specific library APIs — e.g. a rule that flags any use of `crypto.createHash('sha1')` from Node's `crypto` library, or `Cipher.getInstance("DES")` from `javax.crypto`. For those, you can additionally write a CycloneDX VEX referencing the library's PURL:

{{< outcome type="cyclonedx" >}}
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "vulnerabilities": [{
    "id": "javascript/weakCrypto-sha1",
    "source": { "name": "Snyk Code" },
    "affects": [{ "ref": "pkg:npm/node@20.11.0" }],
    "analysis": {
      "state": "not_affected",
      "justification": "code_not_reachable",
      "detail": "sha1 is used only for checksumming static asset URLs (non-security context). Snyk Code rule applies to security-context hashing; documented in src/utils/asset-hash.js with a // security:non-crypto annotation."
    }
  }]
}
```
{{< /outcome >}}

Most Snyk Code findings, though, only get an OpenVEX statement.
