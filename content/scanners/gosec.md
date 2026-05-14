---
title: "gosec (Go Security Checker)"
description: "Securego's Go SAST scanner — AST + SSA pattern matching with intra-procedural taint, JSON / SARIF output, CWE-tagged."
weight: 25
---

> **OSS** (Apache-2.0) · securego · [securego/gosec](https://github.com/securego/gosec) · [Docs](https://github.com/securego/gosec#readme) · CII Best Practices certified · Companion Vulnetix Rego port: [Vulnetix/opa-gosec](https://github.com/Vulnetix/opa-gosec)

gosec inspects Go source by walking the AST and, for newer rules, the SSA intermediate representation. Most checks (the G1xx–G6xx families plus a handful of `crypto.*` import blocks) are pattern matchers; G113, G115, G118–G124 and the entire G7xx taint family use SSA-driven intra-procedural data-flow. Every finding is CWE-mapped, scored on two axes (`severity` + `confidence`), and emitted in the format you pick with `-fmt` — JSON and SARIF being the two that survive a triage pipeline.

The triage surface is narrower than [Snyk SAST](snyk-sast/) or [CodeQL](github-codeql/): no SARIF `codeFlows[]`, no whole-program call graph, no framework awareness. What gosec gives you is fast, deterministic, single-language coverage of the Go-idiomatic weakness catalogue — and a stable rule-ID namespace (`G101` … `G710`) that downstream tools, including the Vulnetix Rego port, key off.

## What gosec finds in JSON

```bash
gosec -fmt json -out gosec.json ./...
```

Top-level shape:

```json
{
  "Issues": [
    {
      "severity": "HIGH",
      "confidence": "HIGH",
      "cwe": { "id": "89", "url": "https://cwe.mitre.org/data/definitions/89.html" },
      "rule_id": "G201",
      "details": "SQL string formatting",
      "file": "/repo/internal/db/users.go",
      "code": "23: \tq := fmt.Sprintf(\"SELECT * FROM users WHERE name = '%s'\", name)\n",
      "line": "23",
      "column": "7",
      "nosec": false,
      "suppressions": null
    }
  ],
  "Stats": { "files": 142, "lines": 18420, "nosec": 3, "found": 7 },
  "GosecVersion": "v2.26.1"
}
```

Per-finding fields in `Issues[]`:

| Field | Purpose |
|---|---|
| `rule_id` | gosec rule identifier — `G101` … `G710`. Stable across versions; retired slots (e.g. G105) are not reused for unrelated checks |
| `severity` | `LOW` / `MEDIUM` / `HIGH` — rule-author's intrinsic severity |
| `confidence` | `LOW` / `MEDIUM` / `HIGH` — how sure the rule is *this* match is real (the second axis is what you filter on to drop noisy G104 / G304 hits) |
| `cwe.id` + `cwe.url` | CWE mapping per rule (gosec maintains the rule → CWE table in the `cwe` package) |
| `details` | Short description of what fired |
| `file` | Absolute path to the source file |
| `code` | The offending line(s), prefixed with the line number |
| `line` | Line number, or a `start-end` range for multi-line matches |
| `column` | Start column |
| `nosec` | `true` if the finding was suppressed by an inline `#nosec` comment |
| `suppressions` | Array of `{kind, justification}` when `-track-suppressions` is set |
| `autofix` | Optional AI-suggested fix string (opt-in; omitted by default) |

The SARIF emitter (`-fmt sarif`) is a flat result list — no `codeFlows[]`. The mapping is mechanical: `rule_id` → `ruleId`, severity → `level` (`HIGH` → `error`, `MEDIUM` → `warning`, `LOW` → `note`), `details` → `message.text`, `file`/`line`/`column` → `locations[].physicalLocation`, and the CWE surfaces as a `taxa` reference under `runs[].taxonomies[]`.

## Rule families

The full list lives in upstream [`RULES.md`](https://github.com/securego/gosec/blob/master/RULES.md). The prefix tells you the engine and the category:

| Prefix | Engine | Category |
|---|---|---|
| **G1xx** | AST (most), SSA for G113/G115/G118–G124 | General secure coding — hardcoded credentials (G101), bind to all interfaces (G102), `unsafe` use (G103), unchecked errors (G104), Trojan-source bidi (G116), secret exposure via marshalling (G117), missing HTTP timeouts (G112/G114), integer overflow (G115) |
| **G2xx** | AST | Injection — SQL format-string (G201), SQL concatenation (G202), unescaped `html/template` data (G203), command-exec audit (G204) |
| **G3xx** | AST | Filesystem & permissions — bad dir/file perms (G301/G302/G306), predictable tempfiles (G303), tainted file paths (G304), zip-slip (G305) |
| **G4xx** | AST, SSA for G407/G408 | Cryptography & TLS — MD5/SHA1 (G401), bad TLS settings (G402), weak RSA (G403), `math/rand` for security (G404), DES/RC4 (G405), MD4/RIPEMD160 (G406), hardcoded IV (G407) |
| **G5xx** | AST | Blocklisted imports — `crypto/md5` (G501), `crypto/des` (G502), `crypto/rc4` (G503), `net/http/cgi` (G504), `crypto/sha1` (G505), `x/crypto/md4` (G506), `x/crypto/ripemd160` (G507) |
| **G6xx** | AST + SSA | Language / runtime safety — implicit loop-variable aliasing (G601), slice bounds out-of-range (G602) |
| **G7xx** | SSA — intra-procedural taint | Taint analysis family — G701 SQLi, G702 cmd-inj, G703 path-traversal, G704 SSRF, G705 XSS, G706 log-inj, G707 SMTP-inj, G708 SSTI, G709 unsafe deserialisation, G710 open redirect |

The G7xx family is the most useful for triage because it carries adversary-controllability evidence inside the analysis itself — the rule fires only when a known source reaches a known sink within the same function. Outside G7xx, the AST-pattern rules will fire on any syntactic match: G104 and G304 in particular are routinely noisy and the first thing teams tune with `-exclude` or per-path `--exclude-rules`.

## Querying with jq

```bash
# Every finding flattened
jq '.Issues[] | {rule_id, severity, confidence, file, line, details}' gosec.json

# High-severity high-confidence only — the bar you should default to in CI
jq '.Issues[] | select(.severity == "HIGH" and .confidence == "HIGH")' gosec.json

# Group by rule_id — "what kinds of issue do we have?"
jq '[.Issues[].rule_id] | group_by(.) | map({rule: .[0], count: length}) | sort_by(-.count)' gosec.json

# Map of file → finding count
jq '[.Issues[] | .file] | group_by(.) | map({file: .[0], count: length}) | sort_by(-.count)' gosec.json

# Findings that lost a CWE mapping (rare, but worth catching in the report)
jq '.Issues[] | select(.cwe.id == "" or .cwe == null)' gosec.json

# Suppression audit — every #nosec that fired, with the comment justification
jq '.Issues[] | select(.nosec == true) | {rule_id, file, line, suppressions}' gosec.json
```

## From finding to root cause

The triage path for a gosec finding is: **rule_id → CWE → reachability (per engine) + adversary controllability → fix or document**.

```bash
# 1. The rule_id already carries the CWE — read it off the finding
jq '.Issues[0] | {rule_id, cwe: .cwe.id, details}' gosec.json

# 2. Pull the Vulnetix enrichment for that CWE — ATT&CK chain, weaponisation, defensive guidance
CWE=$(jq -r '.Issues[0].cwe.id' gosec.json)
vulnetix vdb cwe "CWE-${CWE}"

# 3. Decide reachability from the rule family (no codeFlow trace in gosec output)
#    G7xx — SSA taint, source→sink confirmed intra-procedurally → strong reachability signal
#    G1xx–G6xx AST rules — pattern match only; reachability is your call
jq -r '.Issues[].rule_id' gosec.json | sort -u

# 4. Inspect the offending line in context — gosec gives you `code` and `line`, no surrounding flow
jq -r '.Issues[0] | "\(.file):\(.line)\n\(.code)"' gosec.json
```

Engineer Triage inputs (link: [SSVC Engineer Triage](../appendices/ssvc/)):

- **Reachability** — for G7xx the SSA taint trace is your evidence of `VERIFIED_REACHABLE` *within the function*. For AST rules (G1xx–G6xx) you have a pattern hit; reachability of the enclosing function is something you assess from coverage data or `vulnetix:fix` workflow. There is no SARIF `codeFlows[]` to lean on like [Snyk SAST](snyk-sast/) or [Semgrep](semgrep-opengrep/) Pro give you.
- **Remediation Option** — almost always `CODE_CHANGE`. A handful of rules (G401/G405/G501–G507 — weak crypto / blocked imports) have a deterministic safe rewrite that `gosec --autofix` will suggest if enabled.
- **Mitigation Option** — `CODE_CHANGE` for the rule's own fix. WAF / network mitigations (`INFRASTRUCTURE`) only make sense for G7xx HTTP-sourced taint (G701/G702/G704/G705/G710).
- **Priority** — combine gosec's `severity` × `confidence` matrix with the CWE's exploitation profile from `vulnetix vdb`. A `severity: HIGH, confidence: HIGH` G201 on a function that handles HTTP input is the textbook `DROP_TOOLS`.

## Customising rules

gosec's rule set is fixed in the binary — you tune via the command line or a JSON config:

```bash
# Severity / confidence floor — drop the noise
gosec -severity medium -confidence medium ./...

# Whitelist a specific subset (everything else off)
gosec -include=G101,G201,G401 ./...

# Blacklist a specific rule (everything else on)
gosec -exclude=G104,G304 ./...

# Path-scoped: silence G204 + G304 in cmd/, silence everything in scripts/
gosec --exclude-rules="cmd/.*:G204,G304;scripts/.*:*" ./...
```

Inline suppression uses `#nosec`:

```go
//#nosec G401 -- legacy hash for cache key, non-security context
h := sha1.New()
```

Strictness toggles tighten what counts as a valid suppression: `-nosec-require-rules` rejects bare `#nosec` (you must name the rule), and `-nosec-require-justification` mandates the `-- comment` text. Pair with `-track-suppressions` to surface the suppression in the JSON output instead of silently dropping the finding.

Config file shape (passed via `-conf config.json`):

```json
{
  "global": {
    "nosec": "enabled",
    "audit": "enabled",
    "nosec-require-rules": "enabled",
    "nosec-require-justification": "enabled"
  },
  "exclude-rules": [
    {"path": "cmd/.*", "rules": ["G204", "G304"]},
    {"path": "scripts/.*", "rules": ["*"]}
  ]
}
```

### Vulnetix Code Scanner (`opa-gosec`)

[Vulnetix/opa-gosec](https://github.com/Vulnetix/opa-gosec) is an Apache-2.0 clean-room Rego implementation of the gosec rule catalogue, designed for the Vulnetix CLI's SAST engine. It re-uses the same `Gxxx` rule IDs (so a finding from either tool routes to the same CWE and the same triage memory entry) but the engine is entirely different: each rule is a `.rego` policy in `package vulnetix.rules.gosec_g<NNN>` that consumes raw source text (`input.file_contents`) rather than a Go AST or SSA graph. That trade-off makes it toolchain-free — it runs anywhere OPA / the Vulnetix CLI runs, with no `go.mod` resolution, no build tags, no vendoring quirks — at the cost of textual heuristics in place of upstream's AST and SSA precision. Taint rules (G7xx) use per-file source-and-sink co-location rather than true SSA flow, so cross-file flows are invisible and renamed-variable evasion is more likely than with upstream gosec. The emitted finding shape is leaner than gosec's (`rule_id` / `message` / `artifact_uri` / `start_line` / `snippet` / `severity` / `level` — no `confidence`, no `cwe` per finding) and feeds the Vulnetix CLI's own SARIF / CycloneDX VEX serialisers. Coverage at the current snapshot is 60 rules, matching upstream's active set minus G710. Invoke with `vulnetix sast --rule Vulnetix/opa-gosec /path/to/project` (add `--disable-default-rules` to run the Rego port in isolation); extend by dropping a new `.rego` file into `rules/` — no Go binary to rebuild, no upstream PR required.

## Decision tree

gosec findings sit in first-party Go source, not in an SBOM component, so the format default is OpenVEX. The exception is rules that name a specific library API (`crypto/sha1.New`, `crypto/des.NewCipher`, `text/template.Execute` on tainted input) — those can additionally carry a CycloneDX VEX statement against the standard-library or third-party module PURL.

{{< decision >}}
Does the finding tie to a known library API (blocked import G5xx, or SSTI on `text/template`)?
  ├─ Yes → CycloneDX VEX referencing the module PURL alongside the OpenVEX
  └─ No  (first-party source, typical case) → OpenVEX, subject is the repo at the scanned commit

Need a WAF / IPS mitigation while the fix lands (G7xx HTTP-sourced rules)?
  → vulnetix vdb traffic-filters <related-CWE-or-CVE>
    or write the rule yourself with vulnetix vdb snort-rules as a starting point
{{< /decision >}}

## Worked example: `G201` SQL string-formatting in an HTTP handler

gosec reports:

```json
{
  "severity": "HIGH",
  "confidence": "HIGH",
  "cwe": { "id": "89", "url": "https://cwe.mitre.org/data/definitions/89.html" },
  "rule_id": "G201",
  "details": "SQL string formatting",
  "file": "/repo/internal/api/users.go",
  "code": "42: \tq := fmt.Sprintf(\"SELECT * FROM users WHERE name = '%s'\", name)\n",
  "line": "42",
  "column": "7",
  "nosec": false
}
```

The vulnerable code:

```go
// internal/api/users.go
func searchUsers(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    q := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
    rows, err := db.Query(q)
    // ...
}
```

`name` comes off the HTTP query string and lands inside an `fmt.Sprintf`-built SQL string. G201 fires on the format-string pattern alone; the matching G701 (taint) rule would additionally confirm the source→sink flow in the same function. The fix is a parameterised query:

```go
func searchUsers(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    rows, err := db.Query("SELECT * FROM users WHERE name = ?", name)
    // ...
}
```

Engineer Triage:

- **Reachability** = `VERIFIED_REACHABLE` (HTTP handler bound on a public route; if G701 also fires, the SSA taint trace seals it inside the function)
- **Remediation Option** = `PATCHABLE_MANUAL` (`CODE_CHANGE` — swap `fmt.Sprintf` for parameter placeholders)
- **Mitigation Option** = `CODE_CHANGE`. A WAF (`INFRASTRUCTURE`) is a stop-gap, not a substitute
- **Priority** = `HIGH` (`severity: HIGH × confidence: HIGH`, CWE-89, HTTP-reachable source)

Outcome: `DROP_TOOLS` if the handler is in production, `SPIKE_EFFORT` if it can wait for the current sprint.

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-gosec-g201-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:00:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": {
      "name": "gosec/G201",
      "description": "SQL string formatting (CWE-89) in internal/api/users.go:42. See https://github.com/securego/gosec/blob/master/RULES.md"
    },
    "products": [{
      "@id": "https://github.com/yourorg/yourrepo",
      "identifiers": { "purl": "pkg:github/yourorg/yourrepo@abc1234" }
    }],
    "status": "fixed",
    "action_statement": "Engineer Triage: SPIKE_EFFORT. Inputs: reachability=VERIFIED_REACHABLE (HTTP handler on /api/users; G201 severity=HIGH confidence=HIGH), remediation=PATCHABLE_MANUAL, mitigation=CODE_CHANGE (parameterised query), priority=HIGH. Replaced fmt.Sprintf-built SQL with parameterised db.Query in internal/api/users.go. Confirmed no other rule_id=G201 results on re-scan. See PR #142."
  }]
}
```
{{< /outcome >}}

## Capability snapshot

See the [capability matrix](../#capability-matrix) for the full comparison. gosec summary:

- **Coverage**: SAST only, Go only. No SCA, no container, no IaC, no secrets beyond G101's hardcoded-credentials heuristic and G117's marshalling-exposure check.
- **Database quality**: N/A — first-party rule set, not a vulnerability-DB consumer.
- **[Reachability](../appendices/reachability-deep-dive/)**: **mixed**. G7xx taint rules sit at [Tier 2 intra-procedural](../appendices/reachability-deep-dive/#tier-2); G1xx–G6xx AST rules are pattern matchers at [Tier 1](../appendices/reachability-deep-dive/#tier-1). No whole-program call graph and no SARIF `codeFlows[]` trace in the output.
- **Outputs**: JSON (flagship), [SARIF](../appendices/sarif/) (flat), JUnit-XML, HTML, YAML, CSV, sonarqube, text/golint.
- **VEX**: no native emission or consumption. `#nosec` is inline-only and per-rule.

## See also

- [Capability matrix](../#capability-matrix).
- [Reachability deep-dive](../appendices/reachability-deep-dive/) — where AST pattern-match, SSA taint, and call-graph each apply.
- [SARIF appendix](../appendices/sarif/) — what's missing from gosec's flat SARIF dialect.
- [Glossary](../appendices/glossary/).
