---
title: "Semgrep / Opengrep"
description: "Pattern-matching SAST that reads like the language it scans — and a community fork that drops the cloud licence."
weight: 110
---

## What Semgrep and Opengrep do

<!-- TODO: One paragraph. Both engines run pattern rules expressed as code snippets with metavariables ("show me any `eval($X)` where `$X` came from a request parameter"). Semgrep is the original commercial-led project with a free OSS core; Opengrep is the community fork that exists because Semgrep relicensed the Pro analyses. Either runs identically against the same rule packs — `semgrep --config p/owasp-top-ten` works on Opengrep too. -->

## Reading the output

<!-- TODO: JSON via `--json`, SARIF via `--sarif`, plain text for humans. SARIF is the canonical interop format. Show what one `results[]` entry looks like — `check_id` (the rule that fired), `path` + `start.line`, `extra.message`, `extra.severity`, `extra.metadata.cwe[]`. -->

## What you can act on

<!-- TODO: `check_id` for the rule + ruleset provenance, `path` + line range for the location, `extra.metadata.cwe[]` and `extra.metadata.owasp[]` for classification, `extra.severity`, `extra.fingerprint` for tracking the same finding across commits. -->

## Decision tree

Semgrep / Opengrep findings are pattern matches against your source. Decisions are OpenVEX.

{{< decision >}}
Does the matched code actually run in production, or is it test / fixture / vendored / generated code the rule shouldn't have flagged?
  ├─ Doesn't run → OpenVEX `not_affected`,
  │                justification `vulnerable_code_not_in_execute_path` (and consider tightening the ruleset's `paths.exclude`)
  └─ Runs ↓

Can an attacker reach the source the pattern matched (request body, header, query string, message queue)?
  ├─ No  → OpenVEX `not_affected`, justification `vulnerable_code_cannot_be_controlled_by_adversary`
  └─ Yes ↓

Is the sink defanged by upstream validation, an ORM, a templating auto-escape, or a WAF / IPS / SIEM rule?
  ├─ Yes → OpenVEX `affected` with `workaround_available`
  └─ No  → fix the code; OpenVEX `fixed` once shipped
{{< /decision >}}

## Producing a CycloneDX VEX

<!-- TODO: Rare for Semgrep — most rules fire on first-party code. The exception is rules that target a specific vulnerable library API (e.g. `python.lang.security.use-of-md5`); these can be paired with a CycloneDX VEX entry against the library PURL if the library is in the SBOM. -->

## Producing an OpenVEX

<!-- TODO: The usual outcome. Worked example: subject is the repo at a commit, vulnerability identifier is `<ruleset>/<check_id>` plus the CWE, action_statement records the decision and any MR / commit references. -->
