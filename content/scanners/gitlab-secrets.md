---
title: "GitLab Secret Detection"
description: "GitLab's Gitleaks-driven secret scanner — JSON report, fires on token shapes, surfaces in the MR widget."
weight: 40
---

> **GitLab built-in** · All tiers · [GitLab docs](https://docs.gitlab.com/ee/user/application_security/secret_detection/) · Engine: [Gitleaks](https://github.com/gitleaks/gitleaks) (MIT)

GitLab's Secret Detection job (Secure stage) scans diffs (and optionally the full history with `--full-history`) for token patterns. Driven by Gitleaks under the hood, but the report format is GitLab's standard `gl-secret-detection-report.json`, identical in shape to the other Secure-stage reports.

Detections fire on regex patterns for cloud creds, VCS tokens, payment keys, generic high-entropy strings, and certificate / private-key headers. The MR Security widget is the day-to-day UI; the JSON artefact is what you read for triage.

## What GitLab Secret Detection finds in the JSON

```bash
# In CI the artefact uploads automatically; locally:
cat gl-secret-detection-report.json
```

The shape mirrors the Dependency Scanning report:

```json
{
  "version": "15.0.7",
  "vulnerabilities": [ /* findings */ ],
  "dependency_files": [],
  "scan": { /* tool, type, status, duration */ }
}
```

Per-finding fields:

| Field | Purpose |
|---|---|
| `id` | A UUID — stable across pipelines |
| `category` | `"secret_detection"` |
| `name` | Short descriptive name, e.g. `"AWS API Key"` |
| `description` | Long-form description from the rule |
| `severity` | Almost always `Critical` for real secrets |
| `location.file` | Path of the file with the secret |
| `location.start_line` + `end_line` | The line range |
| `location.commit.sha` + `.author_email` + `.date` | The commit where the secret was added |
| `raw_source_code_extract` | A sanitised snippet — Gitleaks redacts the matched value but shows context |
| `identifiers[]` | One entry with `type: "gitleaks_rule_id"` carrying the rule that fired (e.g. `aws-access-token`, `github-pat`, `slack-bot-token`) |
| `links[]` | URLs to upstream documentation |

## Querying with jq

```bash
# Every secret finding flattened
jq '[.vulnerabilities[] | {
       id,
       name,
       rule: .identifiers[0].value,
       file: .location.file,
       line: .location.start_line,
       commit: .location.commit.sha
     }]' gl-secret-detection-report.json

# Group by rule — which token types have leaked?
jq '[.vulnerabilities[] | {rule: .identifiers[0].value}]
    | group_by(.rule)
    | map({rule: .[0].rule, count: length})
    | sort_by(-.count)' gl-secret-detection-report.json

# Every file with a secret — the rotation work list
jq '[.vulnerabilities[].location.file] | unique' \
   gl-secret-detection-report.json

# Every commit SHA that introduced a secret — for history rewrite planning
jq '[.vulnerabilities[].location.commit.sha] | unique' \
   gl-secret-detection-report.json

# Pivot to Gitleaks rule definition — useful if you want to tighten the regex
jq -r '.vulnerabilities[] | .identifiers[0].value' \
   gl-secret-detection-report.json | sort -u
```

## From finding to root cause

A secret finding is an incident, not a backlog item. The order of operations matters more than the format of the eventual VEX.

The five-step rotation playbook is the same regardless of which scanner found the secret. It's covered in detail on **[Vulnetix's secrets page](vulnetix/secrets/#the-five-step-rotation-playbook)** — rotate at the issuer, replace in code with an env var or vault reference, purge from git history, scan history for related leaks, add prevention. Apply that playbook for every GitLab-flagged finding.

## Engineer Triage for secrets

Secret findings collapse Engineer Triage to a near-deterministic outcome:

- **Reachability** = `VERIFIED_REACHABLE` (the secret is in the source tree)
- **Remediation Option** = `PATCHABLE_MANUAL` (rotate, replace, purge)
- **Mitigation Option** = `CODE_CHANGE` (env-var injection) + `AUTOMATION` (Push Protection / pre-commit hook for prevention)
- **Priority** = `CRITICAL` for active credentials, `LOW` for verified fixtures

Outcome: **`DROP_TOOLS`** for active credentials (rotation can't wait), `BACKLOG` for confirmed test fixtures (add to allow-list).

See [SSVC Engineer Triage](../appendices/ssvc/).

## Decision tree

{{< decision >}}
Secrets are not SBOM components. Format is always OpenVEX.

Is the matched string an actual live credential?
  ├─ No  (fixture, placeholder, example token) → OpenVEX `not_affected`
  │      justification: `vulnerable_code_not_present`
  └─ Yes ↓

Rotate → replace → purge history → scan for related leaks → enable Push Protection
  → OpenVEX `fixed`, action_statement records all five steps + the rotation timestamp
{{< /decision >}}

## Worked example: AWS access key leak

GitLab Secret Detection flags `src/config.py:42`:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "category": "secret_detection",
  "name": "AWS API Key",
  "severity": "Critical",
  "location": {
    "file": "src/config.py",
    "start_line": 42,
    "end_line": 42,
    "commit": {
      "sha": "def5678abcdef",
      "author_email": "developer@example.com",
      "date": "2026-05-13T14:22:00Z"
    }
  },
  "raw_source_code_extract": "aws_access_key_id='AKIA[REDACTED]'",
  "identifiers": [{
    "type": "gitleaks_rule_id",
    "name": "Gitleaks rule ID",
    "value": "aws-access-token"
  }]
}
```

Run the playbook:

```bash
# 1. Rotate at the issuer
aws iam delete-access-key --access-key-id AKIA[REDACTED] --user-name svc-uploader
aws iam create-access-key --user-name svc-uploader
# (Store the new key in the GitLab CI/CD variables vault, not in any file)

# 2. Replace the source-code use with the env-var path
sed -i "s/aws_access_key_id='AKIA[A-Z0-9]\{16\}'/aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID']/" src/config.py

# 3. Purge from git history
git filter-repo --path src/config.py --invert-paths --force
git push --force-with-lease origin main

# 4. Scan history for related leaks
gitleaks detect --log-opts="--all" --redact --report-path gitleaks-history.json

# 5. Enable Push Protection (or GitLab's pre-receive secret scan)
# In GitLab: Project → Settings → Repository → Push rules → Reject pushes that match secret patterns
```

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://gitlab.com/yourorg/yourrepo/-/vex/2026-05-14-gitlab-secret-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:30:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": {
      "name": "gitleaks:aws-access-token",
      "description": "AWS Access Key ID leaked in src/config.py:42 (commit def5678). CWE-798."
    },
    "products": [{
      "@id": "https://gitlab.com/yourorg/yourrepo",
      "identifiers": { "purl": "pkg:gitlab/yourorg/yourrepo" }
    }],
    "status": "fixed",
    "action_statement": "Engineer Triage: DROP_TOOLS. Five-step playbook executed. Key AKIA[REDACTED] revoked in AWS IAM at 2026-05-14T09:15Z. Replacement issued and stored in GitLab CI/CD variable AWS_ACCESS_KEY_ID. src/config.py updated to read from env (MR !128). Secret purged from history via git filter-repo (force-push at 2026-05-14T10:00Z). Gitleaks scan of full history shows no related leaks. Push rule enabled at project level to reject future matches. Incident INC-2026-042."
  }]
}
```
{{< /outcome >}}

## False-positive: fixture token

If the matched string is a documented example (e.g. `AKIAIOSFODNN7EXAMPLE` — AWS's published example access key) or a test fixture in a `tests/` directory:

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://gitlab.com/yourorg/yourrepo/-/vex/2026-05-14-gitlab-secret-002.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:30:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": {
      "name": "gitleaks:aws-access-token",
      "description": "AWS access key pattern matched in tests/fixtures/sample-config.py:8. The value AKIAIOSFODNN7EXAMPLE is AWS's documented public example."
    },
    "products": [{
      "@id": "https://gitlab.com/yourorg/yourrepo",
      "identifiers": { "purl": "pkg:gitlab/yourorg/yourrepo@abc1234" }
    }],
    "status": "not_affected",
    "justification": "vulnerable_code_not_present",
    "action_statement": "Engineer Triage: BACKLOG. The matched string is AWS's published example (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html), not an active credential. Added tests/fixtures/** to the secret-detection allow-list in .gitlab/secret-detection-ruleset.toml to stop re-flagging."
  }]
}
```
{{< /outcome >}}

## Capability snapshot

See the [capability matrix](../#capability-matrix) for the full comparison. GitLab Secrets summary:

- **Coverage**: Secrets only.
- **Database quality**: N/A — signature/pattern-driven via gitleaks.
- **[Reachability](../../appendices/reachability-deep-dive/)**: N/A.
- **Outputs**: gitleaks Security Report JSON, [SARIF](../../appendices/sarif/) (limited).
- **VEX**: GitLab Vulnerability Management dashboard records dismissals.

## See also

- [Capability matrix](../#capability-matrix).
- [Glossary](../../appendices/glossary/).
