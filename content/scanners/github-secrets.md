---
title: "GitHub Secret Scanning"
description: "GitHub's first-party secret scanner — partner-token verification, Push Protection, REST + GraphQL access."
weight: 70
---

> **GitHub built-in** · Free for public repositories; [GitHub Advanced Security](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security) (commercial) required for private repositories and Push Protection at scale · [GitHub docs](https://docs.github.com/en/code-security/secret-scanning) · [Partner programme](https://docs.github.com/en/code-security/secret-scanning/secret-scanning-partner-program) · Engine is closed-source (GitHub-internal).

GitHub runs continuous secret scans across your repository (and across pushes if Push Protection is enabled). For partner tokens — AWS, Stripe, GCP, GitHub itself, Slack, Twilio, and 200+ more — the secret pattern matches plus the issuer-side verification can confirm whether the token is still active and auto-revoke it on detection.

Alerts live on the Security tab. For triage at scale you'll use `gh api`, REST or GraphQL — both pull the same data.

## What GitHub Secret Scanning finds

```bash
# REST
gh api /repos/{owner}/{repo}/secret-scanning/alerts --paginate > alerts.json

# Or GraphQL when you want only specific fields
gh api graphql --paginate -F owner=$OWNER -F repo=$REPO -f query='
  query($owner:String!, $repo:String!, $cursor:String) {
    repository(owner:$owner, name:$repo) {
      secretScanningAlerts(first:100, after:$cursor, states:[OPEN]) {
        pageInfo { hasNextPage endCursor }
        nodes {
          number
          state
          secretType
          secretTypeDisplayName
          createdAt
          publiclyLeaked
        }
      }
    }
  }' > alerts.json
```

Per-alert fields (REST):

| Field | Purpose |
|---|---|
| `number` | The alert's stable ID |
| `state` | `open` / `resolved` |
| `resolution` | When resolved: `false_positive` / `wont_fix` / `revoked` / `pattern_deleted` / `pattern_edited` / `used_in_tests` |
| `secret_type` | The detector's canonical identifier — `aws_access_key_id`, `github_personal_access_token`, `stripe_api_key`, etc. |
| `secret_type_display_name` | Human-readable name |
| `validity` | `active` / `inactive` / `unknown` — only set for partner-token introspection |
| `publicly_leaked` | Boolean — set if the secret was pushed to a public location |
| `multi_repo` | Boolean — set if the same secret appears in multiple repos |
| `locations[].details.path` + `.commit_sha` + `.blob_sha` + `.start_line` + `.end_line` | Where the secret lives |
| `push_protection_bypassed` | Boolean — was push protection bypassed by the committer |
| `push_protection_bypassed_reason` | If yes, why |

## Querying with jq

```bash
# Active partner tokens — start here
jq '[.[] | select(.state == "open" and .validity == "active") | {
       number,
       type: .secret_type,
       leaked: .publicly_leaked,
       commit: .locations[0].details.commit_sha,
       path: .locations[0].details.path
     }]' alerts.json

# Group by secret type to plan rotation work
jq '[.[] | select(.state == "open") | {type: .secret_type}]
    | group_by(.type)
    | map({type: .[0].type, count: length})
    | sort_by(-.count)' alerts.json

# Bypassed Push Protection — incidents in disguise
jq '.[] | select(.push_protection_bypassed == true)' alerts.json

# Validity check for everything — feeds into priority decisions
jq '.[] | {number, type: .secret_type, validity, state}' alerts.json
```

## Partner tokens vs generic patterns

14+ of GitHub's detectors are partner-shape tokens whose issuers participate in the [GitHub partner programme](https://docs.github.com/en/code-security/secret-scanning/secret-scanning-partner-program). When such a token gets pushed to a public repo, GitHub notifies the issuer, who can auto-revoke immediately. The alert's `validity` field reflects the partner's response: `active` (token still works), `inactive` (issuer has revoked it), or `unknown` (no partner verification — usually generic patterns).

The implication for triage: a partner-shape token leaked to a **public** repo is often already revoked by the time you read the alert. Check `validity` first. The remaining rotation steps (history purge, related-leak scan, prevention) still apply.

For non-partner shapes (private keys, generic high-entropy, internal API keys) and any leak to a **private** repo, the issuer can't help — rotate yourself.

## From finding to root cause

The five-step rotation playbook is covered in detail on **[Vulnetix's secrets page](vulnetix/secrets/#the-five-step-rotation-playbook)**. The GitHub-specific notes:

```bash
# 1. For partner tokens, check validity first
gh api /repos/{owner}/{repo}/secret-scanning/alerts/<number> --jq '.validity'

# 2. Rotate at the issuer (varies per partner)

# 3. Mark resolved on GitHub so the alert closes
gh api -X PATCH /repos/{owner}/{repo}/secret-scanning/alerts/<number> \
  -F state=resolved -F resolution=revoked

# 4. Purge from history
gh api /repos/{owner}/{repo}/secret-scanning/alerts/<number>/locations \
  --jq '.[].details.commit_sha' | sort -u > commits-to-purge.txt
git filter-repo --replace-text replacements.txt   # or path-based

# 5. Enable Push Protection at the org level if not already
gh api -X PATCH /orgs/{org} \
  -F secret_scanning_push_protection_enabled_for_new_repositories=true
```

## Engineer Triage for secrets

Same as the [GitLab Secrets page](gitlab-secrets/#engineer-triage-for-secrets):

- **Reachability** = `VERIFIED_REACHABLE`
- **Remediation Option** = `PATCHABLE_MANUAL` (rotate / replace / purge)
- **Mitigation Option** = `CODE_CHANGE` + `AUTOMATION` (Push Protection)
- **Priority** = `CRITICAL` for active partner tokens leaked publicly; `HIGH` for active in a private repo; `LOW` for fixtures

Outcome: `DROP_TOOLS` for active credentials; `BACKLOG` for confirmed fixtures.

See [SSVC Engineer Triage](../appendices/ssvc/).

## Decision tree

{{< decision >}}
Is .validity == "active"?
  ├─ Yes → DROP_TOOLS, run the five-step playbook now
  ├─ No (inactive) → partner already revoked; still purge history + scan for related
  └─ Unknown → assume active until proven otherwise

Is .publicly_leaked == true?
  ├─ Yes → secret must be considered exposed forever (caches, archives, forks).
  │        History rewrite reduces future exposure, not past.
  └─ No  → private-repo leak; rotation + history purge contains the exposure
{{< /decision >}}

## Worked example: `ghp_*` GitHub PAT leak

GitHub Secret Scanning fires alert #88 against a `.env.local` committed to a public repo:

```json
{
  "number": 88,
  "state": "open",
  "secret_type": "github_personal_access_token",
  "secret_type_display_name": "GitHub Personal Access Token",
  "validity": "active",
  "publicly_leaked": true,
  "push_protection_bypassed": false,
  "locations": [{
    "type": "commit",
    "details": {
      "path": ".env.local",
      "commit_sha": "abc1234def5678",
      "blob_sha": "9abcdef0",
      "start_line": 3
    }
  }]
}
```

Validity is `active`. Drop tools. Rotate:

```bash
# Get the token ID (from gh's own auth records, not the leaked token)
gh auth status

# Revoke via the API — the token itself isn't in the alert payload,
# you read it from .env.local before deleting:
LEAKED=$(grep '^GITHUB_TOKEN=' .env.local | cut -d= -f2)
# Revoke through Settings UI: github.com/settings/tokens → find by leaked
# prefix → Revoke. Or for fine-grained PATs: /settings/personal-access-tokens.

# Mark the alert resolved
gh api -X PATCH /repos/{owner}/{repo}/secret-scanning/alerts/88 \
  -F state=resolved -F resolution=revoked

# Purge from history
git filter-repo --path .env.local --invert-paths --force
git push --force-with-lease origin main

# Scan history for related leaks
gitleaks detect --log-opts="--all" --redact --report-path gitleaks-history.json

# Add .env* to .gitignore + enable Push Protection at the org level
echo '.env*' >> .gitignore
```

For a `ghp_*` token leaked publicly, also rotate **anything that token had access to** — issue keys it pushed to, repos it had write access to, secrets it could read. The token is permanently considered exposed; the post-rotation review is whether anything was abused before revocation.

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-ghsec-088.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:30:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": {
      "name": "github-secret-scanning:github_personal_access_token",
      "description": "GitHub PAT leaked in .env.local (commit abc1234). Alert #88. CWE-798."
    },
    "products": [{
      "@id": "https://github.com/yourorg/yourrepo",
      "identifiers": { "purl": "pkg:github/yourorg/yourrepo" }
    }],
    "status": "fixed",
    "action_statement": "Engineer Triage: DROP_TOOLS. Five-step playbook executed. ghp_* token revoked via Settings → PATs at 2026-05-14T09:18Z. .env.local removed from history via git filter-repo + force-push at 2026-05-14T10:00Z. gitleaks history scan shows no related leaks. .env* added to .gitignore. Push Protection enabled at org level. GitHub alert #88 resolved with resolution=revoked. The publicly-leaked token is considered permanently exposed; audit of org Actions runs in the leak window (2026-05-13T14:22Z → 2026-05-14T09:18Z) shows no anomalous activity. Incident INC-2026-051."
  }]
}
```
{{< /outcome >}}

## False-positive: a token shape that's actually a placeholder

```bash
# Resolve the alert as 'used in tests'
gh api -X PATCH /repos/{owner}/{repo}/secret-scanning/alerts/<number> \
  -F state=resolved -F resolution=used_in_tests \
  -F resolution_comment='Documented example token from tests/fixtures/'
```

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-ghsec-099.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:00:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": {
      "name": "github-secret-scanning:stripe_api_key",
      "description": "Stripe test-mode key sk_test_... in tests/fixtures/stripe-mock.js:12. Test-mode keys cannot move real money."
    },
    "products": [{
      "@id": "https://github.com/yourorg/yourrepo",
      "identifiers": { "purl": "pkg:github/yourorg/yourrepo@abc1234" }
    }],
    "status": "not_affected",
    "justification": "vulnerable_code_not_present",
    "action_statement": "Engineer Triage: BACKLOG. Stripe test-mode keys are documented as safe to embed — they only access Stripe's test mode and cannot move funds. Resolved GitHub alert #99 with resolution=used_in_tests."
  }]
}
```
{{< /outcome >}}

## Capability snapshot

See the [capability matrix](../#capability-matrix) for the full comparison. GitHub Secrets summary:

- **Coverage**: Secrets only (signature-based).
- **Database quality**: N/A — signature/pattern-driven.
- **[Reachability](../../appendices/reachability-deep-dive/)**: N/A — secrets-as-content; reachability is a CVE concept.
- **Outputs**: Alerts via the GitHub Secret Scanning REST API + UI.
- **VEX**: no native emission. Resolution status (`revoked`, `wont-fix`, `false-positive`, `used-in-tests`) recorded on the alert.

## See also

- [Capability matrix](../#capability-matrix).
- [Glossary](../../appendices/glossary/).
