---
title: "Ruff"
description: "Astral's Rust-powered Python linter — 800+ built-in rules plus the Vulnetix opa-py-ruff Rego port that the Vulnetix CLI consumes."
weight: 115
---

> **Ruff**: OSS (MIT) by Astral · [Source](https://github.com/astral-sh/ruff) · [Docs](https://docs.astral.sh/ruff/) · Rule catalogue: [docs.astral.sh/ruff/rules](https://docs.astral.sh/ruff/rules/)
>
> **opa-py-ruff** (Vulnetix Code Scanner rule pack): OSS (Apache-2.0) · [Source](https://github.com/Vulnetix/opa-py-ruff) — clean-room OPA/Rego port of 956 Ruff rules consumed by the [Vulnetix CLI](https://github.com/Vulnetix/cli).
>
> Python-only. Single-file pattern / AST match. Not a vulnerability scanner in its own right — it's a code-quality + bandit linter that overlaps with SAST on the `S` (flake8-bandit) prefix.

Ruff folds Flake8 + Black + isort + pydocstyle + pyupgrade + ~30 other linters into one Rust binary. The findings most relevant to a vulnerability workflow come from the `S` (flake8-bandit) prefix — `S101` (`assert`), `S105`/`S106`/`S107` (hard-coded credentials), `S602` (`subprocess` with `shell=True`), and so on. Style rules (E/W/F/UP/I) generate noise on a security pass and are usually filtered with `--select S`.

The Vulnetix Code Scanner reuses Ruff's rule catalogue via **opa-py-ruff** — a clean-room Rego port preserving the original Ruff `code`, `linter`, `since`, `fix`, and `help_uri` metadata, and adding `cwe[]` on bandit S-rules (e.g. `CWE-78` on `S602`). It's invoked as `vulnetix scan --rule Vulnetix/opa-py-ruff`.

## What Ruff finds in JSON

```bash
ruff check --select S --output-format json --output-file ruff.json src/
# Or SARIF, for GitHub Code Scanning ingestion:
ruff check --select S --output-format sarif --output-file ruff.sarif src/
```

Output is a flat JSON array (verified against Ruff 0.13). Per-result fields:

| Field | Purpose |
|---|---|
| `code` | The rule identifier, prefixed by linter (`S602`, `B904`, `UP032`, …) |
| `filename` | Absolute file path |
| `location.row`, `location.column` | Start position (1-indexed) |
| `end_location.row`, `end_location.column` | End position |
| `message` | Human-readable description (rule-specific) |
| `fix` | `null` or `{ applicability, message, edits[] }` when autofix is available |
| `fix.applicability` | `safe` / `unsafe` / `display` |
| `noqa_row` | Line where a `# noqa` comment must be placed to suppress |
| `url` | Permalink to `docs.astral.sh/ruff/rules/<rule-name>/` |

## Querying with jq

```bash
# Every bandit security finding flattened
jq '.[] | select(.code | startswith("S")) | {
      code,
      file: .filename,
      line: .location.row,
      message
    }' ruff.json

# Group by rule — what kinds of security issues?
jq '[.[] | select(.code | startswith("S")) | .code]
    | group_by(.)
    | map({rule: .[0], count: length})
    | sort_by(-.count)' ruff.json

# Per-file rollup — split work across maintainers
jq '[.[] | {file: .filename, rule: .code}]
    | group_by(.file)
    | map({file: .[0].file, rules: [.[].rule] | unique})' ruff.json

# Findings with autofix available — easy wins
jq '.[] | select(.fix != null and .fix.applicability == "safe")
        | {code, file: .filename, line: .location.row, fix: .fix.message}' ruff.json

# Bandit rules without fixes — manual review queue
jq '.[] | select(.code | startswith("S")) | select(.fix == null)
        | {code, file: .filename, line: .location.row}' ruff.json
```

## From finding to root cause

Every Ruff rule has a permalink at `https://docs.astral.sh/ruff/rules/<rule-name>/` — the URL is in each finding's `url` field. The page documents what the rule flags, the rewrite Ruff applies (when `fix` is non-null), references back to the upstream tool the rule was ported from (Bandit, Bugbear, etc.), and the CWE / OWASP context for security rules.

```bash
# Open the docs page for one finding
jq -r '.[0].url' ruff.json
```

The triage path:

1. Read the rule on `docs.astral.sh/ruff/rules/` — confirm what it detects.
2. Open the file at `location.row` and inspect the matched code.
3. Assess reachability and adversary controllability — Ruff is **single-file pattern / AST** (not call-graph, not taint), so the controllability decision is yours to make from the surrounding context.
4. Fix the code (`ruff check --fix` for `safe` autofixes), or document with OpenVEX.

Engineer Triage inputs for Ruff:

- **Reachability** — Ruff matches are syntactic. `VERIFIED_REACHABLE` if the file is on a live code path; `VERIFIED_UNREACHABLE` if it's dead code, a test fixture, or a script not shipped in the package; `UNKNOWN` otherwise.
- **Remediation Option** — `PATCHABLE_AUTO` when `fix.applicability == "safe"` (`ruff check --fix` will rewrite); `PATCHABLE_MANUAL` (`CODE_CHANGE`) otherwise.
- **Mitigation Option** — `CODE_CHANGE` primarily; bandit S-rules sometimes also admit `INFRASTRUCTURE` (e.g. a WAF rule for `S602` callers).
- **Priority** — Ruff carries no severity field. Use the rule prefix as a proxy: `S` (bandit) is the security tier and warrants HIGH/CRITICAL; everything else (`E`, `W`, `F`, `B`, `UP`, …) is hygiene and rarely escalates. The `opa-py-ruff` port adds explicit `severity` per rule.

See [SSVC Engineer Triage](../appendices/ssvc/).

## Decision tree

{{< decision >}}
Does the finding tie to a library API (e.g. `subprocess`, `hashlib`, `pickle`)?
  ├─ Yes → CycloneDX VEX referencing the stdlib / library PURL, alongside the OpenVEX
  └─ No  (custom code pattern) → OpenVEX, subject is the repo at the scanned commit

Is `fix` non-null and `fix.applicability == "safe"`?
  → Apply `ruff check --fix` first, then write the OpenVEX. The autofix is the
    remediation; the OpenVEX records the decision for downstream consumers.

Suppress a known-OK match via `# noqa: <rule-code>` comment in source?
  → Combine with an OpenVEX statement. The inline comment stops Ruff flagging it;
    the OpenVEX records why for other tools and for audit.
{{< /decision >}}

## Worked example: `S602` (`subprocess-popen-with-shell-equals-true`)

Same example as the [Semgrep page](semgrep-opengrep/#worked-example-pythonlangsecurityauditsubprocess-shell-truesubprocess-shell-true) for direct comparison — Ruff and Semgrep flag the same pattern with different output shapes.

```python
# src/app.py
import subprocess
def run(cmd):
    subprocess.call(cmd, shell=True)
```

```bash
ruff check --select S602 --output-format json src/
```

```json
[
  {
    "code": "S602",
    "filename": "/tmp/scanner-test/src/app.py",
    "location": { "row": 3, "column": 5 },
    "end_location": { "row": 3, "column": 41 },
    "message": "`subprocess` call with `shell=True` identified, security issue",
    "fix": null,
    "noqa_row": 3,
    "url": "https://docs.astral.sh/ruff/rules/subprocess-popen-with-shell-equals-true/"
  }
]
```

Ruff's `S602` is a syntactic match on `subprocess.* with shell=True` — controllability of `cmd` is your call. Drive the caller-grep from Ruff's own results:

```bash
# Sink locations — file:line of every S602 hit
jq -r '.[] | select(.code=="S602") | "\(.filename):\(.location.row)"' ruff.json

# Names of wrapping functions — parse the source line for the enclosing `def`
WRAPPERS=$(jq -r '.[] | select(.code=="S602") | .filename + ":" + (.location.row|tostring)' ruff.json \
  | while IFS=: read -r f l; do
      awk -v ln="$l" 'NR<=ln && /^[[:space:]]*def[[:space:]]+/ {match($0,/def[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)/,a); name=a[1]} END {print name}' "$f"
    done | sort -u)

# Grep every caller of those wrapping functions
printf '%s\n' $WRAPPERS | xargs -I{} git grep -nE "\\b{}\\(" src/
```

Fix:

```python
# src/app.py
import subprocess
import shlex
def run(cmd):
    subprocess.call(shlex.split(cmd))   # shell=False is the default
```

Re-scan to confirm no more `S602` results.

Engineer Triage:

- **Reachability** = `VERIFIED_REACHABLE` (caller passes a request-derived path).
- **Remediation Option** = `PATCHABLE_MANUAL` (`S602` has `fix: null` — Ruff knows the smell but not the safe rewrite).
- **Mitigation Option** = `CODE_CHANGE`.
- **Priority** = `HIGH` (CWE-78 on `S602`'s `opa-py-ruff` metadata; flake8-bandit security tier).

Outcome: `SPIKE_EFFORT` to confirm callers and rewrite, then merge.

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-ruff-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:00:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": {
      "name": "S602",
      "description": "subprocess-popen-with-shell-equals-true in src/app.py:3. CWE-78. See https://docs.astral.sh/ruff/rules/subprocess-popen-with-shell-equals-true/"
    },
    "products": [{
      "@id": "https://github.com/yourorg/yourrepo",
      "identifiers": { "purl": "pkg:github/yourorg/yourrepo@abc1234" }
    }],
    "status": "fixed",
    "action_statement": "Engineer Triage: SPIKE_EFFORT. Inputs: reachability=VERIFIED_REACHABLE (caller grep against wrapping functions extracted from ruff.json found a request-derived path), remediation=PATCHABLE_MANUAL (S602 has no safe autofix), mitigation=CODE_CHANGE, priority=HIGH (CWE-78). Replaced subprocess.call(cmd, shell=True) with subprocess.call(shlex.split(cmd)). Confirmed no other S602 results on re-scan."
  }]
}
```
{{< /outcome >}}

## Suppressing a true positive that's known-OK

A known-safe pattern Ruff can't reason about (e.g. a hard-coded constant command):

```python
subprocess.call("ls /etc", shell=True)   # noqa: S602
```

Or globally in `pyproject.toml`:

```toml
[tool.ruff.lint.per-file-ignores]
"scripts/admin.py" = ["S602"]
```

Pair either form with an OpenVEX statement — the inline / TOML suppression stops Ruff flagging the location, the OpenVEX records *why* for other tools and audit.

## Vulnetix Code Scanner custom rule set: `opa-py-ruff`

[`Vulnetix/opa-py-ruff`](https://github.com/Vulnetix/opa-py-ruff) is a clean-room OPA/Rego port of the Ruff rule catalogue, designed to run inside the Vulnetix CLI SAST scanner. It exists because the Vulnetix CLI is written in Go and OPA-driven, not Rust, so it can't link Ruff directly — but Ruff's rule catalogue is one of the most comprehensive Python linting bodies in OSS.

**Coverage**:

- **956 rules total**, mirroring every Ruff rule code.
- **478 rules** as regex/pattern-based Rego (runs identically to Ruff's syntactic matchers — these are the ones useful in a scan today).
- **478 rules** shipped as **stubs** because they require AST that's beyond Rego's expressive capability without a pre-parsed Python AST in `input`. Stubs preserve metadata so a future AST-aware backend can swap them in.

**Metadata preserved per rule**:

```rego
metadata := {
    "id":            "RUFF-S602",
    "ruff_code":     "S602",
    "ruff_linter":   "flake8-bandit",
    "ruff_name":     "subprocess-popen-with-shell-equals-true",
    "ruff_since":    "v0.0.262",
    "ruff_fix":      "None",
    "help_uri":      "https://docs.astral.sh/ruff/rules/subprocess-popen-with-shell-equals-true/",
    "severity":      "high",
    "level":         "error",
    "kind":          "sast",
    "cwe":           [78],
    "tags":          ["python", "ruff", "flake8-bandit", "s", "security"],
    ...
}
```

The `cwe[]` field is **added by `opa-py-ruff`** — upstream Ruff has no CWE mapping. Currently populated on flake8-bandit S-rules; expanding over time.

**Invocation**:

```bash
# Run opa-py-ruff alongside Vulnetix's built-in rules
vulnetix scan --rule Vulnetix/opa-py-ruff

# Run opa-py-ruff exclusively (e.g. for a Python-only repo)
vulnetix scan --rule Vulnetix/opa-py-ruff --disable-default-rules
```

**When to prefer `opa-py-ruff` over upstream Ruff**:

- You want the rule output integrated into Vulnetix's [SSVC Engineer Triage](../appendices/ssvc/) memory (`.vulnetix/memory.yaml`) instead of being a standalone JSON file.
- You want CWE attribution per finding (Vulnetix VDB pivots on `cwe[]`).
- You're running the [AI Coding Agent](../appendices/ai-coding-agent/) plugin — `vulnetix:sast-scan` invokes `opa-py-ruff` rules transparently.

**When to prefer upstream Ruff**:

- You want the AST-only rules (the 478 stubs in `opa-py-ruff` will be no-ops).
- You want `ruff check --fix` autofixes (`opa-py-ruff` does not auto-apply).
- You want maximum-speed Python-only linting with no security tooling stack — Ruff's Rust implementation runs at ~10–100× the speed of Rego over the same source.

Most teams run **both**: upstream Ruff in pre-commit for fast feedback + autofix, then `opa-py-ruff` in CI through the Vulnetix CLI for the SARIF + VEX + memory.yaml triage trail.

## Capability snapshot

See the [capability matrix](../#capability-matrix) for the full comparison. Ruff summary:

- **Coverage**: SAST. Python only. Secrets only at the `S105`/`S106`/`S107` (hard-coded credential) level — no entropy or token-provider patterns.
- **Database quality**: N/A — Ruff is rule-pack-driven; `opa-py-ruff` adds CWE attribution per bandit S-rule.
- **[Reachability](../../appendices/reachability-deep-dive/)**: **[Tier 1 pattern / AST](../../appendices/reachability-deep-dive/#tier-1)** — single-file syntactic match. No call-graph, no taint, no semantic. Pair with [CodeQL](github-codeql/) or [Snyk SAST](snyk-sast/) for traditional call-edge questions on Python code, or with [Vulnetix](vulnetix/) for semantic / intent-to-use coverage.
- **Outputs**: JSON / [SARIF](../../appendices/sarif/) (flat — no `codeFlows[]`) / GitLab gemnasium JSON / JUnit XML / GitHub Actions annotations. No native SBOM, no VEX emission.

## See also

- [Capability matrix](../#capability-matrix).
- [Semgrep / Opengrep](semgrep-opengrep/) — the other pattern-match Python SAST option; broader language coverage, richer rule metadata, slower.
- [Vulnetix SAST](vulnetix/sast/) — the Vulnetix-native SAST surface that consumes `opa-py-ruff` rules.
- [Reachability deep-dive](../../appendices/reachability-deep-dive/) — Tier 1 pattern / AST limits.
- [SARIF appendix](../../appendices/sarif/) — Ruff's SARIF dialect (flat, no `codeFlows[]`).
- [AI Coding Agent](../appendices/ai-coding-agent/) — `vulnetix:sast-scan` slash-command that wraps `opa-py-ruff`.
- [Glossary](../../appendices/glossary/).
