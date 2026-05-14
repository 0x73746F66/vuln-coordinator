---
title: "Semgrep / Opengrep"
description: "Pattern-matching SAST that reads like the language it scans — and a community fork that drops the cloud licence."
weight: 110
---

> **Semgrep**: OSS core (LGPL-2.1) + commercial Pro tier (Semgrep, Inc.) · [Source](https://github.com/semgrep/semgrep) · [Docs](https://semgrep.dev/docs/) · Rule registry: [semgrep.dev/r](https://semgrep.dev/r)
>
> **Opengrep**: OSS fork (LGPL-2.1) · [Source](https://github.com/opengrep/opengrep) · [Docs](https://opengrep.dev/)
>
> Used by GitLab as the [SAST analyser](https://docs.gitlab.com/ee/user/application_security/sast/) for several languages.

Both engines run pattern rules expressed as code snippets with metavariables ("show me any `eval($X)` where `$X` came from a request parameter"). Semgrep is the original commercial-led project with a free OSS core; Opengrep is the community fork that exists because Semgrep relicensed the Pro analyses. Either runs identically against the same rule packs — `semgrep --config p/owasp-top-ten` works on Opengrep too. The flags, the rule format, and the JSON / SARIF output are interchangeable.

This page uses `semgrep` in commands; substitute `opengrep` if you're on the fork.

## What Semgrep / Opengrep finds in JSON

```bash
semgrep --config=p/python --json --output=semgrep.json src/
# Or SARIF:
semgrep --config=p/python --sarif --output=semgrep.sarif src/
```

Top-level JSON keys (verified against Semgrep 1.157):

```json
{
  "version": "1.157.0",
  "results": [ /* findings */ ],
  "errors": [ /* parse errors */ ],
  "paths": { "scanned": [ /* file paths */ ] },
  "engine_requested": "...",
  "skipped_rules": []
}
```

Per-result fields:

| Field | Purpose |
|---|---|
| `check_id` | The rule identifier, often dotted: `python.lang.security.audit.subprocess-shell-true.subprocess-shell-true` |
| `path` | Absolute or relative file path |
| `start.line`, `start.col` + `end.line`, `end.col` | The matched range |
| `extra.severity` | `ERROR` / `WARNING` / `INFO` |
| `extra.message` | Human-readable description |
| `extra.metadata.cwe[]` | CWE references (long form, e.g. `"CWE-78: Improper Neutralization of Special Elements..."`) |
| `extra.metadata.owasp[]` | OWASP references |
| `extra.metadata.references[]` | URLs to upstream advisories / docs |
| `extra.metadata.confidence` | `HIGH` / `MEDIUM` / `LOW` |
| `extra.metadata.likelihood` / `impact` | Semgrep's scoring inputs |
| `extra.fingerprint` | Stable hash (requires login for the value to be populated) |
| `extra.lines` | The matched source lines, inline in the JSON |

## Querying with jq

```bash
# Every finding flattened
jq '.results[] | {
      check_id,
      severity: .extra.severity,
      file: .path,
      line: .start.line,
      message: .extra.message
    }' semgrep.json

# Filter to ERROR only
jq '.results[] | select(.extra.severity == "ERROR")' semgrep.json

# Group by rule for "what kinds of issue?"
jq '[.results[].check_id]
    | group_by(.)
    | map({rule: .[0], count: length})
    | sort_by(-.count)' semgrep.json

# Per-file rollup — split work across maintainers
jq '[.results[] | {file: .path, rule: .check_id}]
    | group_by(.file)
    | map({file: .[0].file, rules: [.[].rule] | unique})' semgrep.json

# CWE rollup — useful for compliance reporting
jq '[.results[] | .extra.metadata.cwe[]?]
    | group_by(.)
    | map({cwe: .[0], count: length})
    | sort_by(-.count)' semgrep.json

# Findings with HIGH confidence — start the triage here
jq '.results[]
    | select(.extra.metadata.confidence == "HIGH")
    | {check_id, file: .path, line: .start.line}' semgrep.json
```

## From finding to root cause

Every Semgrep rule has a registry page at `https://semgrep.dev/r/<check_id>` (or it's a custom rule in your repo's `rules/` directory). The page carries the description, the bad pattern, the fix, and links to references.

```bash
# Get the registry URL for one finding
CHECK=$(jq -r '.results[0].check_id' semgrep.json)
echo "https://semgrep.dev/r/${CHECK}"
```

The triage path:

1. Read the rule on the registry — confirm what it detects.
2. Read the matched lines in `extra.lines` (or open the file at the location).
3. Assess reachability and adversary controllability.
4. Fix the code, or document with OpenVEX.

For taint-mode findings (Semgrep Pro / Opengrep with `--pro`), the SARIF includes `codeFlows[]` similar to Snyk Code and CodeQL — read the flow to find the source. For pattern-mode findings (the default OSS engine), there's no flow; the finding is a syntactic match and you assess controllability yourself.

Engineer Triage inputs for Semgrep/Opengrep:

- **Reachability** — pattern matches are syntactic. `VERIFIED_REACHABLE` if the file runs and the pattern is on a live code path; `VERIFIED_UNREACHABLE` if the file is dead code or a test fixture; `UNKNOWN` otherwise.
- **Remediation Option** — almost always `PATCHABLE_MANUAL` (`CODE_CHANGE`).
- **Mitigation Option** — `CODE_CHANGE` primarily; `INFRASTRUCTURE` for some classes (a WAF rule for taint findings on HTTP input).
- **Priority** — `extra.severity` (`ERROR` ~ HIGH/CRITICAL, `WARNING` ~ MEDIUM, `INFO` ~ LOW), plus `extra.metadata.likelihood` and `impact`.

See [SSVC Engineer Triage](../appendices/ssvc/).

## Decision tree

{{< decision >}}
Does the finding tie to a library API (e.g. `crypto/sha1`, `yaml.load`, `unserialize`)?
  ├─ Yes → CycloneDX VEX referencing the library PURL, alongside the OpenVEX
  └─ No  (custom code pattern) → OpenVEX, subject is the repo at the scanned commit

Suppress a known-OK match via `// nosemgrep: <rule-id>` comment in source?
  → Combine with an OpenVEX statement. The inline comment stops Semgrep flagging it;
    the OpenVEX records why for other tools and for audit.
{{< /decision >}}

## Worked example: `python.lang.security.audit.subprocess-shell-true.subprocess-shell-true`

Run against a small Python project (verified locally):

```python
# src/app.py
import subprocess
def run(cmd):
    subprocess.call(cmd, shell=True)
```

Semgrep flags this on `p/python`:

```json
{
  "check_id": "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
  "path": "/tmp/scanner-test/src/app.py",
  "start": { "line": 3, "col": 5 },
  "end": { "line": 3, "col": 41 },
  "extra": {
    "severity": "ERROR",
    "message": "Found 'subprocess' function 'call' with 'shell=True'. This is dangerous because this call will spawn the command using a shell process. Doing so propagates current shell settings and variables, which makes it much easier for a malicious actor to execute commands. Use 'shell=False' instead.",
    "metadata": {
      "cwe": ["CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"],
      "owasp": ["A03:2021 - Injection"],
      "confidence": "HIGH",
      "likelihood": "HIGH",
      "impact": "HIGH"
    }
  }
}
```

The rule fires on a syntactic pattern (`subprocess.* with shell=True`); whether the `cmd` variable is attacker-controllable depends on the caller. Drive the caller-grep from Semgrep's own results — the matched location and the wrapping function name come straight out of the JSON, so you don't have to type either:

```bash
# Sink locations — file:line of every rule match
jq -r '.results[]
        | select(.check_id=="python.lang.security.audit.subprocess-shell-true.subprocess-shell-true")
        | "\(.path):\(.start.line)"' semgrep-results.json

# Names of the wrapping functions to grep callers for.
# Preferred: a `$FUNC` metavar in the rule. Fallback: parse `extra.lines` for the enclosing `def`.
WRAPPERS=$(jq -r '.results[]
                   | select(.check_id=="python.lang.security.audit.subprocess-shell-true.subprocess-shell-true")
                   | (.extra.metavars."$FUNC".abstract_content
                      // (.extra.lines | capture("def\\s+(?<n>[A-Za-z_][A-Za-z0-9_]*)\\s*\\(").n))' \
            semgrep-results.json | sort -u)

# Now grep for every caller of those wrapping functions
printf '%s\n' $WRAPPERS | xargs -I{} git grep -nE "\\b{}\\(" src/
```

If every caller passes a constant string from a config file, the pattern is reachable but the input isn't adversary-controllable — Engineer Triage `Reachability: VERIFIED_REACHABLE` but priority may drop. If any caller passes a request-derived value, the finding is genuine.

Fix:

```python
# src/app.py
import subprocess
import shlex
def run(cmd):
    subprocess.call(shlex.split(cmd))   # shell=False is the default
```

Engineer Triage:

- **Reachability** = `VERIFIED_REACHABLE`
- **Remediation Option** = `PATCHABLE_MANUAL` (rewrite the call)
- **Mitigation Option** = `CODE_CHANGE`
- **Priority** = `HIGH` (Semgrep ERROR + HIGH confidence/likelihood/impact + CWE-78)

Outcome: `SPIKE_EFFORT` to confirm callers and rewrite, then merge.

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-semgrep-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:00:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": {
      "name": "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
      "description": "Command injection via subprocess(shell=True) in src/app.py:3. CWE-78. See https://semgrep.dev/r/python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"
    },
    "products": [{
      "@id": "https://github.com/yourorg/yourrepo",
      "identifiers": { "purl": "pkg:github/yourorg/yourrepo@abc1234" }
    }],
    "status": "fixed",
    "action_statement": "Engineer Triage: SPIKE_EFFORT. Inputs: reachability=VERIFIED_REACHABLE (wrapping functions extracted from semgrep-results.json metavars/extra.lines, callers identified by piping through jq into git grep; one passes a request-derived path), remediation=PATCHABLE_MANUAL, mitigation=CODE_CHANGE, priority=HIGH. Replaced subprocess.call(cmd, shell=True) with subprocess.call(shlex.split(cmd)). Confirmed no other subprocess-shell-true results on re-scan. See MR !46."
  }]
}
```
{{< /outcome >}}

## Suppressing a true positive that's known-OK

A known-safe pattern that the rule can't reason about (e.g. a hard-coded constant command that a `shell=True` reads from):

```python
subprocess.call("ls /etc", shell=True)   # nosemgrep: python.lang.security.audit.subprocess-shell-true.subprocess-shell-true
```

The inline comment stops Semgrep flagging that single match. Pair it with an OpenVEX statement recording the reasoning — the comment doesn't tell future-you *why* this one is OK, the OpenVEX does.

## Custom rules

For rules you've written yourself (in your repo's `rules/` directory, run with `--config rules/`), the OpenVEX `vulnerability.description` field should point at the rule file path:

```json
"vulnerability": {
  "name": "yourorg.custom.unsanitised-template",
  "description": "Custom rule in rules/yourorg-custom.yaml — flags unsanitised user input in template literals."
}
```

## Capability snapshot

See the [capability matrix](../#capability-matrix) for the full comparison. Semgrep / Opengrep summary:

- **Coverage**: SAST. Can be extended to IaC and secret patterns via rule packs.
- **Database quality**: N/A — pattern-rule-driven.
- **[Reachability](../../appendices/reachability-deep-dive/)**: **[Tier 1 pattern-match](../../appendices/reachability-deep-dive/#tier-1)** in OSS / default mode; **[Tier 2 taint flow](../../appendices/reachability-deep-dive/#tier-2)** in Semgrep Pro / `opengrep --pro` mode. OSS misses dataflow but is fast and free.
- **Outputs**: JSON, [SARIF](../../appendices/sarif/) (flat OSS, codeFlows in Pro). No native VEX emission.

## See also

- [Capability matrix](../#capability-matrix).
- [Reachability deep-dive](../../appendices/reachability-deep-dive/) — pattern-match vs taint flow distinction.
- [SARIF appendix](../../appendices/sarif/) — Semgrep dialect (codeFlows in Pro only).
- [Glossary](../../appendices/glossary/).
