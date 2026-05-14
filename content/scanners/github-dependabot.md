---
title: "GitHub Dependabot"
description: "GitHub's first-party dep scanner — Security tab alerts + auto-upgrade MRs, accessed via GraphQL / REST."
weight: 60
---

> **GitHub built-in** · Free on all repositories · [GitHub docs](https://docs.github.com/en/code-security/dependabot) · Engine source: [dependabot/dependabot-core](https://github.com/dependabot/dependabot-core) (MIT) · Advisory database: [github/advisory-database](https://github.com/github/advisory-database) (CC-BY-4.0)

Dependabot watches your repository's resolved dependency graph against the GitHub Advisory Database and surfaces every match in three places: as alerts under the Security tab, as auto-generated merge requests that bump the affected lockfile, and as a GraphQL / REST endpoint for programmatic access. The first two are UIs over the same data; the third is what you'll automate against for triage and reporting.

Auto-upgrade MRs are the lever that makes Dependabot different from a vanilla SCA scanner. When the alert and the bot agree on the bump, the workflow is "review the MR, confirm green CI, merge" — most of Engineer Triage resolves to `NIGHTLY_AUTO_PATCH` for them.

## What Dependabot finds

Dependabot doesn't write a file on disk in your repo. Findings live on the GitHub side and you fetch them via `gh`:

```bash
# REST — most flexible for shell pipelines
gh api /repos/{owner}/{repo}/dependabot/alerts --paginate > alerts.json

# Or GraphQL — when you want only the fields you'll use
gh api graphql --paginate -F owner=$OWNER -F repo=$REPO -f query='
  query($owner:String!,$repo:String!,$cursor:String) {
    repository(owner:$owner,name:$repo) {
      vulnerabilityAlerts(first:100, after:$cursor, states:[OPEN]) {
        pageInfo { hasNextPage endCursor }
        nodes {
          number
          state
          securityVulnerability {
            severity
            package { ecosystem name }
            firstPatchedVersion { identifier }
            advisory {
              ghsaId
              summary
              identifiers { type value }
            }
          }
          vulnerableManifestPath
          vulnerableRequirements
        }
      }
    }
  }' > alerts.json
```

Per-alert fields you'll triage on:

| Field | Purpose |
|---|---|
| `number` | The alert's stable ID — used to dismiss / re-open via the API |
| `state` | `open` / `fixed` / `dismissed` / `auto_dismissed` |
| `securityVulnerability.severity` | `CRITICAL` / `HIGH` / `MODERATE` / `LOW` |
| `securityVulnerability.package.ecosystem` + `.name` | The affected component, ecosystem-tagged |
| `securityVulnerability.firstPatchedVersion.identifier` | The fixed version (when known) |
| `securityVulnerability.advisory.ghsaId` | GHSA reference |
| `securityVulnerability.advisory.identifiers[]` | Cross-refs to CVE / Snyk / OSV |
| `vulnerableManifestPath` | Which manifest file declares the affected dep |
| `vulnerableRequirements` | The version range your manifest pins |
| `auto_dismissed_at` | Set when Dependabot auto-dismissed (rule changes, version corrected, etc.) |
| `dismissed_reason` | When manually dismissed: `fix_started` / `inaccurate` / `no_bandwidth` / `not_used` / `tolerable_risk` |

## Querying with jq

```bash
# Every open alert flattened
jq '[.[] | select(.state == "open") | {
       number,
       ghsa: .security_advisory.ghsa_id,
       cve: (.security_advisory.cve_id // "n/a"),
       severity: .security_advisory.severity,
       package: .security_vulnerability.package.name,
       ecosystem: .security_vulnerability.package.ecosystem,
       fix: .security_vulnerability.first_patched_version.identifier,
       manifest: .dependency.manifest_path
     }]' alerts.json

# Critical + high only
jq '.[] | select(.state == "open"
                 and (.security_advisory.severity == "critical"
                      or .security_advisory.severity == "high"))' alerts.json

# Group by ecosystem to split the work
jq '[.[] | select(.state == "open")
         | {ecosystem: .security_vulnerability.package.ecosystem}]
    | group_by(.ecosystem)
    | map({ecosystem: .[0].ecosystem, count: length})' alerts.json

# CVE / GHSA list — feed into vulnetix vdb in a loop
jq -r '.[] | select(.state == "open")
           | .security_advisory.cve_id // .security_advisory.ghsa_id' \
   alerts.json | sort -u
```

## From finding to root cause

Dependabot's strongest signal is the auto-generated MR. If one exists for an alert, the triage path is short:

```bash
# Find the auto-upgrade MR for one alert
ALERT_NUMBER=42
gh pr list --repo "$OWNER/$REPO" --search "dependabot/$ALERT_NUMBER in:branch" --json number,title,state,url

# Or list every Dependabot-authored MR in one shot
gh pr list --repo "$OWNER/$REPO" --author "app/dependabot" --state open
```

For the alerts without an auto-MR (the bot can't always propose a safe bump — peer-dep conflicts, missing fixed versions in your ecosystem, restricted scope), pivot to `vulnetix vdb`:

```bash
# Pull Engineer Triage priority input + affected routines
CVE=$(jq -r '.security_advisory.cve_id' alert.json)
vulnetix vdb vuln "$CVE" --output json \
  | jq '.[0].containers.adp[0] | {
          coordinator: .x_ssvc.decision,
          exploitation: .x_exploitationMaturity.level,
          kev: .x_kev.knownRansomwareCampaignUse,
          routines: .x_affectedRoutines
        }'
```

Engineer Triage inputs from the alert + Vulnetix:

- **Reachability** — grep the codebase for the names in `x_affectedRoutines`, then use the ecosystem-specific reachability tool from the [package managers appendix](../appendices/package-managers/).
- **Remediation Option** — auto-MR exists → `PATCHABLE_DEPLOYMENT`. Auto-MR can't be opened (Dependabot says no safe bump) → `PATCHABLE_VERSION_LOCKED` or `PATCHABLE_MANUAL` depending on whether the constraint is the blocker.
- **Mitigation Option** — almost always `AUTOMATION` for Dependabot (the bot is the mitigation tool).
- **Priority** — alert severity + Vulnetix coordinator / exploitation reads.

See [SSVC Engineer Triage](../appendices/ssvc/) for the framework.

## Decision tree

{{< decision >}}
Is the vulnerable package declared in your SBOM?
  ├─ Yes → CycloneDX VEX entry referencing the PURL from the SBOM
  └─ No  → OpenVEX statement (dev-only dep, or a transitive your SBOM doesn't declare)

Has the auto-upgrade MR been merged?
  └─ If yes, the VEX entry's analysis.state is `resolved` and the merge commit is the action evidence

Need a WAF / IPS / SIEM mitigation while the upgrade is pending?
  └─ vulnetix vdb traffic-filters <CVE> supplies the rule; status is `affected` + `workaround_available`
{{< /decision >}}

## Worked example: a Dependabot alert on `lodash@4.17.20` (GHSA-35jh-r3h4-6jhm)

Dependabot raises alert #58 against `lodash@4.17.20` in a Node.js project. The alert payload:

```json
{
  "number": 58,
  "state": "open",
  "dependency": {
    "package": { "ecosystem": "npm", "name": "lodash" },
    "manifest_path": "package-lock.json"
  },
  "security_advisory": {
    "ghsa_id": "GHSA-35jh-r3h4-6jhm",
    "cve_id": "CVE-2021-23337",
    "severity": "high",
    "summary": "Command injection in lodash"
  },
  "security_vulnerability": {
    "package": { "ecosystem": "npm", "name": "lodash" },
    "vulnerable_version_range": "< 4.17.21",
    "first_patched_version": { "identifier": "4.17.21" }
  }
}
```

Dependabot opens an MR — typically titled "Bump lodash from 4.17.20 to 4.17.21". Confirm:

```bash
gh pr list --author "app/dependabot" --search "lodash" --json number,title,url,statusCheckRollup
```

Run Engineer Triage:

- **Reachability** = `VERIFIED_REACHABLE` — package name comes from the Dependabot alert payload, not typed: `PKG=$(gh api repos/:owner/:repo/dependabot/alerts/58 --jq '.dependency.package.name')` then `git grep -l "$PKG" src/` returns 14 files. For function-level reach (is `lodash.template` actually called, not just imported?) drive symbols from `vulnetix vdb vuln CVE-2021-23337 | jq '.[0].containers.adp[0].x_affectedRoutines[].name'`.
- **Remediation Option** = `PATCHABLE_DEPLOYMENT` (caret range `^4.17.20` in `package.json` accepts 4.17.21; the MR proves it)
- **Mitigation Option** = `AUTOMATION` (Dependabot is the automation)
- **Priority** = `HIGH` (alert severity; Vulnetix coordinator returns `Track*`, exploitation `POC`, EPSS ~0.2 — no urgency multiplier)

Outcome: `NIGHTLY_AUTO_PATCH`. Review the MR's diff, confirm CI is green, merge.

{{< outcome type="cyclonedx" >}}
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "vulnerabilities": [{
    "id": "CVE-2021-23337",
    "source": {
      "name": "GitHub Advisory Database",
      "url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm"
    },
    "ratings": [{ "source": { "name": "GitHub" }, "severity": "high" }],
    "affects": [{
      "ref": "pkg:npm/lodash@4.17.21",
      "versions": [
        { "version": "4.17.20", "status": "affected" },
        { "version": "4.17.21", "status": "unaffected" }
      ]
    }],
    "analysis": {
      "state": "resolved",
      "detail": "Engineer Triage: NIGHTLY_AUTO_PATCH. Dependabot alert #58 (GHSA-35jh-r3h4-6jhm). Inputs: reachability=VERIFIED_REACHABLE, remediation=PATCHABLE_DEPLOYMENT (caret range allows 4.17.21), mitigation=AUTOMATION (Dependabot auto-MR), priority=HIGH. Merged Dependabot MR !212 on 2026-05-14T22:00Z after green CI. Alert auto-closed to state=fixed."
    }
  }]
}
```
{{< /outcome >}}

## Producing an OpenVEX

When the alert is on a dev-only dep or you decide to dismiss it:

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-dependabot-058.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:00:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": {
      "name": "CVE-2021-23337",
      "description": "Command injection in lodash.template. GHSA-35jh-r3h4-6jhm. Dependabot alert #58."
    },
    "products": [{
      "@id": "https://github.com/yourorg/yourrepo",
      "identifiers": { "purl": "pkg:github/yourorg/yourrepo@abc1234" }
    }],
    "status": "not_affected",
    "justification": "vulnerable_code_not_in_execute_path",
    "action_statement": "Engineer Triage: BACKLOG. lodash@4.17.20 is in devDependencies via the test fixture generator. Production npm ci --omit=dev strips it from the shipped artefact. Dismissed Dependabot alert #58 with reason 'not_used'. Will pick up the bump on the next regular dev-deps refresh."
  }]
}
```
{{< /outcome >}}

## Verify-affected and direct-vs-transitive

Dependabot opens an MR but the version it picks isn't always the version your build will actually resolve once merged. Three quick checks before approving the MR:

- **Is the alerted version the version in your resolved lockfile?** Dependabot reads the manifest, not necessarily the resolved tree; re-walk with the ecosystem-native command (`npm ls <pkg>`, `mvn dependency:tree -Dincludes=...`, `pip show <pkg>`, `go list -m <module>`).
- **Is the dep direct or transitive?** Dependabot's `dependency.relationship` field (when present) is the authoritative answer: `direct` vs `indirect`. Cross-check by running the ecosystem-native dependency-walk command.
- **Will the auto-MR actually fix it?** Dependabot's auto-MR bumps the *direct* dep it knows about. If the affected artefact is a transitive of one of your direct deps, Dependabot may not be able to coerce it — you'll need the lockfile / dependencyManagement / constraints mechanism from the [package managers appendix](../appendices/package-managers/) on top of (or instead of) the auto-MR.

For Java specifically (alert mentions `pom.xml` or `build.gradle`), Dependabot frequently opens an MR that bumps a Spring Boot parent or a BOM rather than the transitive itself — sometimes correct, sometimes a bump introducing unrelated breaking changes. The [JVM appendix](../appendices/package-managers/jvm/) covers when to override at the BOM-property level, when to use `<dependencyManagement>`, when to use Gradle `constraints { }` / `dependencySubstitution`, and how to gate with the maven-enforcer-plugin so a future regression can't slip past.

Full workflow: [Vulnetix SCA verify-affected](../vulnetix/sca/#verify-affected---is-the-finding-real-for-your-build) and [direct-vs-transitive triage](../vulnetix/sca/#direct-vs-transitive-triage--which-knob-do-you-turn).

## Patching mechanics

The [package managers appendix](../appendices/package-managers/) covers lockfile editing, transitive coercion, and integrity verification for every supported ecosystem — useful for the alerts Dependabot can't auto-upgrade.

## Capability snapshot

See the [capability matrix](../#capability-matrix) for the full comparison. Dependabot summary:

- **Coverage**: SCA only.
- **[Database quality](../#database-quality-tiers)**: **CVE + GHSA** (*minimal*). Adds GitHub Advisory ingestion which is GHSA-shaped.
- **[Reachability](../../appendices/reachability-deep-dive/)**: **[Tier 1](../../appendices/reachability-deep-dive/#tier-1)** only — package-level. For function-level reachability, cross-reference [Vulnetix `x_affectedRoutines`](../../appendices/glossary/#x_affectedroutines).
- **Exploit maturity**: GHSA flag only; KEV surfaced in some advisories. No EPSS, sightings, weaponisation.
- **[EOL](../../appendices/eol/)**: not native; cross-reference [endoflife.date](https://endoflife.date/) or Vulnetix.
- **[Supply-chain threats](../../appendices/supply-chain-threats/)**: surfaces `GHSA-MAL-` advisories reactively; no proactive typosquat detection.
- **Outputs**: Alerts via the GitHub UI / REST API (SARIF-shaped Code Scanning), auto-MRs.
- **VEX**: no native emission. Dismissal API records "won't fix" state separately.

## See also

- [Capability matrix](../#capability-matrix).
- [Reachability deep-dive](../../appendices/reachability-deep-dive/) — Tier-1 floor + cross-reference paths for Tier 2/3.
- [Supply-chain threats](../../appendices/supply-chain-threats/).
- [EOL appendix](../../appendices/eol/).
- [Glossary](../../appendices/glossary/).
