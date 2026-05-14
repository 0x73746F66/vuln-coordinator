---
title: "GitHub Secret Scanning"
description: "GitHub's first-party token scanner — runs continuously, talks directly to issuing providers for verified leaks."
weight: 70
---

## What GitHub Secret Scanning does

<!-- TODO: One paragraph. GitHub runs token-pattern scans across the entire repository (history included) and against new pushes. For partner tokens (AWS, Stripe, GCP, etc.) it goes one step further: it verifies the token with the issuer, and on a positive match the issuer can auto-revoke or notify. Findings appear on the Security tab; push protection blocks pushes that contain a known token shape. -->

## Reading the output

<!-- TODO: The canonical API is `gh api /repos/{owner}/{repo}/secret-scanning/alerts` or the GraphQL `repository.secretScanningAlerts` connection. Each alert carries the `secret_type`, `secret_type_display_name`, `state`, `resolution`, `locations[]` (commit, blob path, line range), and — for verified partner secrets — a `validity` field. -->

## What you can act on

<!-- TODO: `secret_type` (e.g. `aws_access_key_id`), `validity` (`active` / `inactive` / `unknown`), `state` (`open` / `resolved`), `resolution` (`false_positive` / `wont_fix` / `revoked` / `pattern_deleted` / `pattern_edited` / `used_in_tests`), `locations[].details` for commit + path. -->

## Decision tree

Secrets are not SBOM components. Decisions are always OpenVEX, and the action order matters more than the format.

{{< decision >}}
Is the alert a verified-active partner token, or a regex match against a fixture / test value?
  ├─ Fixture / test → OpenVEX `not_affected`,
  │                   justification `vulnerable_code_not_present`,
  │                   resolve the GitHub alert as `used_in_tests` so it stops appearing
  └─ Active token ↓

Rotate the credential immediately. If GitHub's partner integration already revoked it (validity flipped to `inactive` after the push), you still owe a replacement.

Purge from history if the repo is private. For a public repo the token must be considered exposed forever, regardless of what `git filter-repo` does — but rewriting history is still worth it to stop the alert re-firing.

  → OpenVEX `fixed`. `action_statement` records: the rotation timestamp, the new vault location,
    the history-rewrite commit, and the GitHub alert URL.
{{< /decision >}}

## Producing a CycloneDX VEX

<!-- TODO: Not applicable — secrets aren't SBOM components. -->

## Producing an OpenVEX

<!-- TODO: Worked example. Subject is the repo at a specific commit; vulnerability is the alert ID combined with `secret_type`; action_statement names the rotation, the resolution chosen on GitHub, and the history-rewrite evidence. -->
