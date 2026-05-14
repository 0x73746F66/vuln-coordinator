---
title: "Secrets — credential detection"
description: "Triaging VNX-SEC-* findings: the 32 built-in rules, the five-step rotation playbook, worked examples for AWS keys, GitHub PATs, and private keys."
weight: 30
---

A secret finding is almost always an incident, not a backlog item. The order of operations matters more than the format of the eventual VEX — rotate, replace, purge, scan, prevent — and only then attest.

## What the secrets evaluator finds

The Vulnetix secrets evaluator runs 32 built-in rules (`VNX-SEC-001` through `VNX-SEC-032`) against every file in scope. Findings land in `.vulnetix/sast.sarif` alongside SAST results, distinguished by the rule ID. The categories from the Vulnetix docs:

- **Cloud providers** — AWS access key + secret, Azure storage credentials, GCP service accounts.
- **Version control** — GitHub tokens (`ghp_`, `gho_`, `ghs_`, `ghu_`, `ghr_`), GitLab tokens.
- **Communication services** — Slack tokens (`xoxa-`, `xoxb-`, `xoxp-`, `xoxr-`), Twilio.
- **Payment systems** — Stripe.
- **Cryptographic material** — RSA, DSA, EC, OpenSSH, PGP private keys.
- **Generic patterns** — high-entropy API keys, bearer tokens, OAuth client secrets.

Each rule fires on a regex (typically a vendor-specific prefix + length) and, for the partner tokens, an entropy check to reduce false positives on test fixtures.

The full rule list (with detection patterns) lives at [docs.cli.vulnetix.com/docs/sast-rules/](https://docs.cli.vulnetix.com/docs/sast-rules/) under the `vnx-sec-*` IDs.

## Why the partner-token shapes matter

14 of the 32 rules detect tokens whose **issuer can auto-revoke**. GitHub Secret Scanning, AWS Trusted Advisor, Stripe, Slack, Twilio, and others all participate in the [GitHub partner programme](https://docs.github.com/en/code-security/secret-scanning/secret-scanning-partner-program): if a token shape that one of these issuers controls gets pushed to a public GitHub repo, the issuer is notified and revokes it within minutes.

The implication: a leak of a partner-shape token to a public repo is often **already revoked** by the time you find it in a scan. Don't skip rotation — but check the validity first (`aws sts get-caller-identity` for AWS, the API's introspection endpoint for OAuth tokens) before declaring an incident.

For non-partner shapes (private keys, generic high-entropy, internal API keys) and for any token leaked to a **private** repo, the issuer can't help. Rotate yourself.

## The five-step rotation playbook

The same sequence applies to every secret type. Departures from it (skipping history purge, rotating later) create durable risk.

### 1. Rotate the credential at the issuer

Different per vendor. The principle is universal: invalidate the leaked secret before doing anything else. Until rotated, the secret is exfiltrable by anyone with access to your git history.

- AWS: `aws iam delete-access-key --access-key-id AKIA...` (or via the console).
- GCP: revoke and re-issue the service account key.
- GitHub PAT: Settings → Developer settings → Personal access tokens → Revoke.
- Stripe / Twilio / Slack: revoke via the partner dashboard.
- Private keys: regenerate the key pair and re-authorise the new public key.

### 2. Replace the source-code use

The token gets removed from source. The replacement is **never** another token committed to source. Two acceptable patterns:

- **Environment variable / secrets vault** — runtime injection. Local: `.env` file ignored by `.gitignore`. CI: secret variable. Production: secrets manager (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault, Kubernetes Secrets).
- **Workload identity** — preferred for cloud. GitHub Actions → AWS IAM via OIDC, GCP service accounts via Workload Identity Federation, Azure AD with federated credentials. The runtime gets short-lived tokens automatically; nothing to leak.

### 3. Purge the secret from git history

A revoked secret is still a leaked secret if it remains in history. Rewrite history:

```bash
# git-filter-repo (modern, preferred)
git filter-repo --path path/to/leaked-file --invert-paths --force

# Or scrub by content (be careful — overruns):
git filter-repo --replace-text replacements.txt

# After rewrite, force-push (with team coordination):
git push --force-with-lease origin main
```

For a public repo, the secret must be considered exposed forever — search caches, archive.org, and clones may still hold it. History rewriting reduces *future* exposure, not past.

### 4. Scan history for related leaks

A leaked secret often travels with others. Run a deep scan over the entire history:

```bash
gitleaks detect --log-opts="--all" --redact --report-path gitleaks.json
```

If any related secret is found, repeat steps 1–3 for each.

### 5. Add prevention

Once you've cleaned up, make it harder to do again:

- **GitHub Secret Scanning + Push Protection** for GitHub repos — blocks pushes containing known token shapes.
- **GitLab Secret Detection in pre-receive hooks** — equivalent for GitLab.
- **Pre-commit hooks locally** (`pre-commit` + `gitleaks-precommit`) — catches secrets before commit.
- **Vulnetix in CI** — catches what slips through.

## Worked example: AWS access key leak (VNX-SEC-001)

Vulnetix flags `AKIA[0-9A-Z]{16}` in `src/config.py:42`:

```python
# FLAGGED
import boto3

client = boto3.client(
    's3',
    aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
    aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
)
```

### Rotate

```bash
aws iam list-access-keys --user-name svc-uploader
aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE --user-name svc-uploader
aws iam create-access-key --user-name svc-uploader
```

Store the replacement in your secrets manager. **Don't paste it into Slack, even in a private channel.**

### Replace

```python
# SAFE — default credential chain reads env, instance profile, or SSO
import boto3
client = boto3.client('s3')
```

For CI, use OIDC federation to AWS IAM — short-lived tokens, no long-lived key in a CI secret variable:

```yaml
# GitHub Actions
permissions:
  id-token: write
  contents: read

steps:
  - uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::123456789012:role/gha-uploader
      aws-region: us-east-1
```

### Purge

```bash
git filter-repo --path src/config.py --invert-paths --force
git push --force-with-lease origin main
```

If `src/config.py` had other valid contents, use a content replacement file instead of removing the file:

```
# replacements.txt
AKIAIOSFODNN7EXAMPLE==>REDACTED_AWS_KEY
wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY==>REDACTED_AWS_SECRET
```

```bash
git filter-repo --replace-text replacements.txt
```

### Scan history for related

```bash
gitleaks detect --log-opts="--all" --redact --report-path gitleaks.json
jq '.[] | select(.RuleID | startswith("aws-"))' gitleaks.json
```

### Prevent

Enable GitHub Push Protection at the org level (Settings → Code security and analysis → Push protection). Add Vulnetix to CI with `--severity high` so secret findings are gated automatically.

### Attest

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-aws-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:30:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "VNX-SEC-001",
        "description": "AWS Access Key ID leaked in source. CWE-798. See https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-001/"
      },
      "products": [{
        "@id": "https://github.com/yourorg/yourrepo",
        "identifiers": { "purl": "pkg:github/yourorg/yourrepo" }
      }],
      "status": "fixed",
      "action_statement": "Key AKIAIOSFODNN7EXAMPLE revoked in AWS IAM at 2026-05-14T09:15Z. Replacement issued and stored in AWS Secrets Manager. Application switched to default credential chain via IAM role + OIDC (commit def5678). Secret purged from history via git filter-repo and force-pushed (commit ghi9012). Gitleaks scan of full history shows no related leaks. Push Protection enabled at org level. See incident INC-2026-042."
    }
  ]
}
```
{{< /outcome >}}

## Worked example: GitHub PAT leak

A `ghp_*` token committed in `.env.local` that wasn't `.gitignore`d. Vulnetix flags the rule (one of `VNX-SEC-*` for GitHub tokens — check the rule ID in your SARIF output).

GitHub's Push Protection should have blocked the push — possible reasons it didn't:

- The token was committed before Push Protection was enabled on the repo.
- The token was added via a commit on a fork before merge into the source repo.
- The token was a fine-grained PAT, and Push Protection wasn't yet aware of the shape at the time of the push.

### Rotate via GitHub

Settings → Developer settings → Personal access tokens → Tokens (classic) → find the token → Revoke. Or via the REST API:

```bash
gh api -X DELETE /authorizations/<token-id>
```

For fine-grained tokens, the path is Settings → Developer settings → Personal access tokens → Fine-grained tokens. Revocation is immediate.

### Replace with a short-lived alternative

If the token was for a workflow, prefer:

- **GitHub App installation token** — short-lived (~1 hour), issued per-workflow via `tibdex/github-app-token` or `actions/create-github-app-token@v1`.
- **`GITHUB_TOKEN`** — built into every workflow, scoped to the repo, doesn't need creating.

For a personal use case (local CLI), `gh auth login` and let `gh` manage the token under `~/.config/gh/hosts.yml`.

### Purge + scan + prevent + attest

Same as the AWS example. The OpenVEX `vulnerability.name` becomes `VNX-SEC-NNN` for the GitHub-token rule that fired.

## Worked example: RSA / OpenSSH private key leak

Detected by header signature:

```
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN RSA PRIVATE KEY-----
-----BEGIN DSA PRIVATE KEY-----
-----BEGIN EC PRIVATE KEY-----
-----BEGIN PGP PRIVATE KEY BLOCK-----
```

The leak is qualitatively worse than an API token. A private key authorises identity-bearing operations; depending on what the key was for, that's SSH access, signing, decryption, or all three.

### Rotate

Generate a new key pair. Authorise the new public key everywhere the old one was authorised (`~/.ssh/authorized_keys` on servers, the GitHub deploy keys list, the signing key in your CI's signing service). Remove the old public key from each.

If the key was used for signing (git commit signing, package signing), check what was signed with it during the window the key was exposed. Re-sign if needed. Publish a revocation notice if downstream consumers verify signatures.

### Purge history

Same as above. The key file should be deleted, not just have its contents removed — keep `.gitignore` honest.

### Scan history

In addition to gitleaks, search for the **specific** public-key fingerprint across systems where it was authorised, to make sure removal is complete:

```bash
ssh-keygen -lf old_public_key.pub   # fingerprint
# search authorized_keys files / deploy-key lists for that fingerprint
```

### Attest

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-sshkey-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T11:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "VNX-SEC-0XX",
        "description": "OpenSSH private key leaked in source. CWE-798."
      },
      "products": [{
        "@id": "https://github.com/yourorg/yourrepo",
        "identifiers": { "purl": "pkg:github/yourorg/yourrepo" }
      }],
      "status": "fixed",
      "action_statement": "Key SHA256:abc... regenerated 2026-05-14T10:30Z. New public key authorised on bastion (2 servers) and as the GitHub deploy key for yourorg/yourrepo. Old public key removed from authorized_keys on both servers (commits in deploy repo) and from GitHub deploy keys (verified via gh api). History purged via git filter-repo on src/keys/deploy.pem and force-pushed. Incident INC-2026-043."
    }
  ]
}
```
{{< /outcome >}}

## Producing the OpenVEX — reference

Secrets always go to OpenVEX (no SBOM component). Required structure:

| Field | Value |
|---|---|
| `vulnerability.name` | The `VNX-SEC-NNN` rule ID |
| `vulnerability.description` | Short text + a link to the rule page |
| `products[].@id` | Your repo URL |
| `products[].identifiers.purl` | `pkg:github/<org>/<repo>` or `pkg:gitlab/<group>/<project>` |
| `status` | `fixed` once rotated + purged. Use `under_investigation` only if rotation is in progress and you want a record of the open work |
| `action_statement` | Rotation timestamp, replacement storage location, history-rewrite commit, related-leak scan outcome, prevention added, incident reference |

A `not_affected` status is rare for secrets — appropriate only when the matched string is provably a fixture (it's in a `tests/` directory, it's a documented example token, it's the AWS public example `AKIAIOSFODNN7EXAMPLE` in a tutorial). In those cases, also exclude the path via `--exclude` so the scan stops re-flagging it.
