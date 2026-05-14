---
title: "GitLab Secret Detection"
description: "Greps for token shapes across commits, blocks merges that introduce them, files a finding when one slips through."
weight: 40
---

## What GitLab Secret Detection does

<!-- TODO: One paragraph. The Secret Detection CI job scans diffs (and optionally history) for token patterns — AWS keys, GCP service accounts, generic high-entropy strings. Driven by Gitleaks under the hood. Findings surface in the MR Security widget and the vulnerability report; the JSON artefact is `gl-secret-detection-report.json`. -->

## Reading the output

<!-- TODO: The `gl-secret-detection-report.json` artefact is the canonical source. Each `vulnerabilities[]` entry carries the `Description` (which token type matched), `location.file` + `.start_line`, `commit.sha`, and `raw_source_code_extract`. The raw value isn't included verbatim — only enough context to identify it. -->

## What you can act on

<!-- TODO: `vulnerabilities[].description` (token type), `location.file` + `.start_line` + `.commit.sha` (where + when), `raw_source_code_extract` (snippet), `category: "secret_detection"`. -->

## Decision tree

Secrets are not SBOM components. Every decision is OpenVEX. The action order matters more than the format.

{{< decision >}}
Is the detected string an actual live credential, or a fixture / placeholder / example token?
  ├─ Fixture or placeholder → OpenVEX `not_affected`,
  │                           justification `vulnerable_code_not_present`,
  │                           (and add the path to your scanner's allow-list to stop re-triaging)
  └─ Real credential ↓

Rotate the credential. Now, before writing anything else. Store the replacement in a secrets vault, never in the repo.

Once rotated, purge the secret from git history (`git filter-repo` or BFG), and force-push if the branch is shared.

  → OpenVEX `fixed`. `action_statement` records: the rotation timestamp, the new storage location,
    the history-rewrite commit, and the incident reference if one was raised.
{{< /decision >}}

## Producing a CycloneDX VEX

<!-- TODO: Not applicable — secrets aren't components in the SBOM sense. Use OpenVEX. -->

## Producing an OpenVEX

<!-- TODO: Worked example. Subject is the repo; vulnerability is the GitLab finding ID combined with the token type; action_statement names the rotation and history-rewrite evidence. -->
