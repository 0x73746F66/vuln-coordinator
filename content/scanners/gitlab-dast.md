---
title: "GitLab DAST"
description: "OWASP ZAP under the hood, probes a deployed environment, JSON report with reproducible request/response evidence."
weight: 50
---

> **GitLab built-in** · Ultimate tier · [GitLab docs](https://docs.gitlab.com/ee/user/application_security/dast/) · Engine: [OWASP ZAP](https://www.zaproxy.org/) (Apache-2.0, [zaproxy/zaproxy](https://github.com/zaproxy/zaproxy))

GitLab's DAST job spins up an OWASP ZAP container, points it at a target URL (typically a review-app or staging deploy), and runs baseline or full active scans. The report — `gl-dast-report.json` — is GitLab's standard Secure-stage format, shaped like Dependency Scanning and Secret Detection. The killer field is `evidence.request` — the actual HTTP request that triggered the finding. Replay it to confirm, and you've turned a DAST result into a verifiable fact.

DAST runs against a running service, so it's the one scanner that needs a deployment — usually a GitLab review-app or a scheduled scan against staging. Out-of-cycle by design; you wouldn't gate every commit on it.

## What GitLab DAST finds in the JSON

```bash
# In CI the artefact uploads automatically; locally:
cat gl-dast-report.json
```

The shape:

```json
{
  "version": "15.0.7",
  "vulnerabilities": [ /* findings */ ],
  "scan": {
    "scanned_resources": [ /* URLs hit */ ],
    "type": "dast",
    "status": "success",
    "tool": { "name": "OWASP Zed Attack Proxy (ZAP)" }
  }
}
```

Per-finding fields:

| Field | Purpose |
|---|---|
| `id` | UUID, stable across pipelines |
| `category` | `"dast"` |
| `name` + `description` | Human-readable summary |
| `severity` | `Critical` / `High` / `Medium` / `Low` / `Info` / `Unknown` |
| `cve` | CVE reference if the finding ties to a known vulnerability (rare for DAST) |
| `identifiers[]` | `{type: "ZAP_PluginID", value: "10202"}`, `{type: "CWE", value: "89"}`, OWASP / WASC mappings |
| `location.hostname` | The target host |
| `location.path` | The URL path that triggered the finding |
| `location.method` | HTTP method (`GET` / `POST` / `PUT` / etc.) |
| `location.param` | The parameter name that was probed |
| `evidence.request.method` + `.url` + `.body` + `.headers[]` | The full request — replay this verbatim |
| `evidence.response.status_code` + `.body` + `.headers[]` | What ZAP got back |
| `solution` | Free-text remediation suggestion |
| `links[]` | URLs to OWASP / ZAP / CWE references |

## Querying with jq

```bash
# Every finding flattened
jq '[.vulnerabilities[] | {
       id,
       name,
       severity,
       method: .location.method,
       url: (.location.hostname + .location.path),
       param: .location.param,
       cwe: (.identifiers[]? | select(.type == "CWE") | .value)
     }]' gl-dast-report.json

# Critical + High only
jq '.vulnerabilities[]
    | select(.severity == "Critical" or .severity == "High")
    | {name, url: (.location.hostname + .location.path)}' \
   gl-dast-report.json

# Group by endpoint — find the riskiest routes
jq '[.vulnerabilities[] | {url: .location.path}]
    | group_by(.url)
    | map({url: .[0].url, count: length})
    | sort_by(-.count)' gl-dast-report.json

# Extract the replayable request for one finding
jq '.vulnerabilities[]
    | select(.id == "550e8400-e29b-41d4-a716-446655440000")
    | .evidence.request' gl-dast-report.json

# CWE rollup — compliance reporting
jq '[.vulnerabilities[] | .identifiers[]? | select(.type == "CWE") | .value]
    | group_by(.)
    | map({cwe: .[0], count: length})
    | sort_by(-.count)' gl-dast-report.json
```

## From finding to root cause

DAST gives you something rare in scanner output: the exact request that triggered the finding. The triage loop is:

1. Extract `evidence.request` for the finding.
2. Replay it against the same environment. Does the response still match `evidence.response`?
3. If yes, the finding is real. Assess exposure (public / partner-shared / pivot-reachable from a foothold).
4. If no (transient, scanner artefact, environment drift), the finding doesn't reproduce — document and move on.

```bash
# Extract and replay the probe with curl
FINDING_ID="550e8400-e29b-41d4-a716-446655440000"
REQ=$(jq -r --arg id "$FINDING_ID" \
  '.vulnerabilities[] | select(.id == $id) | .evidence.request' \
  gl-dast-report.json)

METHOD=$(echo "$REQ" | jq -r '.method')
URL=$(echo "$REQ"   | jq -r '.url')
BODY=$(echo "$REQ"  | jq -r '.body')
HEADERS=$(echo "$REQ" | jq -r '.headers[]? | "-H \"" + .name + ": " + .value + "\""')

eval curl -X $METHOD "$HEADERS" --data "'$BODY'" "$URL" -i
```

## Engineer Triage for DAST

DAST findings are runtime, against a deployed service. Engineer Triage inputs:

- **Reachability** = `VERIFIED_REACHABLE` if the request reproduces (the endpoint accepts and processes it); `VERIFIED_UNREACHABLE` only when the endpoint is gone (deleted route, deployment-level WAF blocks it).
- **Remediation Option** = `PATCHABLE_MANUAL` (`CODE_CHANGE`) — DAST findings are application-level bugs, not library bumps.
- **Mitigation Option** = `INFRASTRUCTURE` (WAF rule) is the common interim measure while the code fix is in flight. `vulnetix vdb traffic-filters <CVE>` if the finding ties to a known CVE; for app-specific findings, write the WAF rule yourself targeting the request shape.
- **Priority** = severity from the report + exposure context. Public-facing finding → escalate; internal-only → de-escalate.

See [SSVC Engineer Triage](../appendices/ssvc/).

## Decision tree

{{< decision >}}
DAST findings are runtime, not component-level — almost always OpenVEX.

Subject is the deployed application (URL or PURL of the service binary)
Vulnerability is the finding's CWE + ZAP plugin ID

Need a WAF / IPS / SIEM mitigation while the code fix is in flight?
  → For a known CVE-backed finding (rare): vulnetix vdb traffic-filters <CVE>
  → For app-specific findings: write a WAF rule targeting the request shape;
    vulnetix vdb snort-rules / nuclei give starting-point templates by ATT&CK technique

Does the request reproduce against the target?
  ├─ No  → OpenVEX `not_affected`, justification `vulnerable_code_not_present` (transient)
  └─ Yes ↓

Is the endpoint exposed to traffic an attacker can send?
  ├─ No  → OpenVEX `not_affected`, justification `vulnerable_code_cannot_be_controlled_by_adversary`
  └─ Yes → OpenVEX `affected` while in flight; `fixed` after the code change ships
{{< /decision >}}

## Worked example: reflected XSS in a search endpoint

GitLab DAST flags the search endpoint with a reflected XSS probe:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "category": "dast",
  "name": "Cross-Site Scripting (Reflected)",
  "severity": "High",
  "identifiers": [
    { "type": "CWE", "name": "CWE-79", "value": "79" },
    { "type": "ZAP_PluginID", "value": "40012" },
    { "type": "OWASP", "value": "A03:2021" }
  ],
  "location": {
    "hostname": "https://review-app-mr-42.example.com",
    "path": "/api/search",
    "method": "GET",
    "param": "q"
  },
  "evidence": {
    "request": {
      "method": "GET",
      "url": "https://review-app-mr-42.example.com/api/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
      "headers": [
        { "name": "Accept", "value": "text/html" }
      ]
    },
    "response": {
      "status_code": 200,
      "headers": [
        { "name": "Content-Type", "value": "text/html; charset=utf-8" }
      ],
      "body": "<html>... You searched for: <script>alert(1)</script> ..."
    }
  },
  "solution": "Encode user-supplied input before reflecting it in HTML."
}
```

Replay to confirm:

```bash
curl -i 'https://review-app-mr-42.example.com/api/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E' \
  -H 'Accept: text/html'
# Expect 200 + the body containing the literal <script>alert(1)</script>
```

Reproduces. The endpoint reflects the `q` parameter into the HTML response without escaping.

Engineer Triage:

- **Reachability** = `VERIFIED_REACHABLE` (replay confirms the probe lands)
- **Remediation Option** = `PATCHABLE_MANUAL` (`CODE_CHANGE`)
- **Mitigation Option** = both `CODE_CHANGE` (HTML-escape the reflection) and `INFRASTRUCTURE` (WAF rule blocking the `<script>` pattern in the `q` param) — the code fix is the right answer; the WAF rule is the bridge while you ship it
- **Priority** = `HIGH` (CWE-79, reflected, public-facing on the review app)

Outcome: `SPIKE_EFFORT` — sprint-scoped code fix; deploy a WAF rule in the same day as a bridge.

Fix (server-side template auto-escaping, e.g. for Express + EJS):

```javascript
// Before
app.get('/api/search', (req, res) => {
  res.send(`<html>You searched for: ${req.query.q}</html>`);
});

// After — use a template engine with auto-escape
app.get('/api/search', (req, res) => {
  res.render('search', { q: req.query.q });
  // search.ejs: <html>You searched for: <%= q %></html>
  // EJS escapes by default with <%= %>
});
```

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://gitlab.com/yourorg/yourrepo/-/vex/2026-05-14-dast-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:00:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": {
      "name": "ZAP-40012",
      "description": "Reflected XSS in /api/search?q=. CWE-79. OWASP A03:2021."
    },
    "products": [{
      "@id": "https://yourservice.example.com",
      "identifiers": { "purl": "pkg:generic/yourservice@2.1.0" }
    }],
    "status": "fixed",
    "action_statement": "Engineer Triage: SPIKE_EFFORT. Reproduced via curl replay of evidence.request — endpoint returned 200 with the literal <script> tag in the body. Inputs: reachability=VERIFIED_REACHABLE, remediation=PATCHABLE_MANUAL, mitigation=CODE_CHANGE (HTML-escape via EJS template), priority=HIGH. ModSecurity rule 10042 deployed to the review-app WAF on 2026-05-14T11:00Z as a bridge while the code fix shipped. Code fix: src/routes/search.js switched from template-literal response to EJS render with auto-escape (MR !187). Re-ran GitLab DAST against the deployed fix; ZAP-40012 no longer fires."
  }]
}
```
{{< /outcome >}}

## When the request doesn't reproduce

Sometimes DAST findings don't replay — a flaky session, a CSRF token that expired, a race condition that fired on one ZAP attempt and not another:

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://gitlab.com/yourorg/yourrepo/-/vex/2026-05-14-dast-002.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:00:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": {
      "name": "ZAP-10202",
      "description": "Absence of Anti-CSRF Tokens flagged on /api/checkout (POST). CWE-352."
    },
    "products": [{
      "@id": "https://yourservice.example.com",
      "identifiers": { "purl": "pkg:generic/yourservice@2.1.0" }
    }],
    "status": "not_affected",
    "justification": "vulnerable_code_cannot_be_controlled_by_adversary",
    "action_statement": "Engineer Triage: BACKLOG. /api/checkout requires SameSite=Strict session cookies (verified in production response headers) — CSRF is not exploitable cross-origin even without an explicit anti-CSRF token. Documented the design decision in docs/security/csrf.md. Added a CSP report-uri to monitor for any cross-origin POST attempts. ZAP plugin 10202 fires on absence of a specific token shape; the SameSite cookie defence is equivalent for our threat model."
  }]
}
```
{{< /outcome >}}
