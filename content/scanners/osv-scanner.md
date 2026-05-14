---
title: "osv-scanner"
description: "Google's OSV-database scanner — fast, account-free, native OSV-schema records with cross-feed aliases."
weight: 100
---

> **OSS** (Apache-2.0) · Google · [google/osv-scanner](https://github.com/google/osv-scanner) · [Docs](https://google.github.io/osv-scanner/) · Backed by [OSV.dev](https://osv.dev/) (aggregator across GHSA, NVD, RUSTSEC, PYSEC, GO, MAL and more)

`osv-scanner` reads lockfiles directly (`package-lock.json`, `Cargo.lock`, `go.sum`, `Gemfile.lock`, `poetry.lock`, and many more), normalises each component to a PURL, and queries the OSV.dev API. No account, no telemetry, single static binary — easy to drop into CI as a `run:` step.

The output is the OSV schema verbatim — `aliases[]` cross-references every database (GHSA, CVE, RUSTSEC, PYSEC, GO, MAL, OSV), so you can pivot from osv-scanner's identifier to any of them.

## What osv-scanner finds in JSON

```bash
osv-scanner --format json -L package-lock.json > osv.json
# Or scan a directory
osv-scanner --format json -r ./src > osv.json
# SARIF output
osv-scanner --format sarif -L package-lock.json > osv.sarif
```

Top-level shape:

```json
{
  "results": [
    {
      "source": { "path": "package-lock.json", "type": "lockfile" },
      "packages": [
        {
          "package": { "name": "lodash", "version": "4.17.20", "ecosystem": "npm" },
          "vulnerabilities": [ /* full OSV records */ ],
          "groups": [ /* aliases for de-duplication */ ]
        }
      ]
    }
  ]
}
```

Per-vulnerability fields (these are the upstream OSV schema):

| Field | Purpose |
|---|---|
| `id` | OSV's primary identifier — typically `GHSA-...` for GitHub-tracked, `CVE-...` for NVD-only, or ecosystem-prefixed (`RUSTSEC-...`, `PYSEC-...`, `GO-...`, `MAL-...`) |
| `aliases[]` | Every cross-feed identifier — the canonical bridge to `vulnetix vdb` and other tools |
| `summary` + `details` | Short and long descriptions |
| `affected[].package.purl` | The affected component as a PURL (when ecosystem-derivable) |
| `affected[].package.name` + `.ecosystem` | The component identity |
| `affected[].ranges[].events[]` | A list of `{introduced: "X"}` / `{fixed: "Y"}` events that describe the affected range |
| `affected[].versions[]` | An explicit version list (when ranges are unwieldy) |
| `severity[]` | CVSS vectors when known (`type: "CVSS_V3"`, `score: "CVSS:3.1/..."`) |
| `database_specific.severity` | Severity bucket if `severity[]` is empty — `LOW` / `MODERATE` / `HIGH` / `CRITICAL` |
| `references[].url` | URLs to advisories, patches, PRs |

## Querying with jq

```bash
# Every finding flattened
jq '[.results[].packages[]
     | .package as $pkg
     | .vulnerabilities[]
     | {
         id,
         cve: (.aliases[] | select(startswith("CVE-")) // null),
         severity: (.database_specific.severity // "Unknown"),
         package: $pkg.name,
         ecosystem: $pkg.ecosystem,
         version: $pkg.version,
         fixed: ([.affected[].ranges[].events[] | select(has("fixed")) | .fixed] | first)
       }]' osv.json

# CRITICAL / HIGH only
jq '.results[].packages[].vulnerabilities[]
    | select(.database_specific.severity == "CRITICAL"
             or .database_specific.severity == "HIGH")
    | {id, summary}' osv.json

# Alias resolution — pull every CVE for downstream vulnetix vdb queries
jq -r '[.results[].packages[].vulnerabilities[].aliases[]
        | select(startswith("CVE-"))]
       | unique[]' osv.json

# Group by ecosystem to split the work across maintainers
jq '[.results[].packages[]
     | {ecosystem: .package.ecosystem, vuln_count: (.vulnerabilities | length)}]
    | group_by(.ecosystem)
    | map({ecosystem: .[0].ecosystem,
           total: ([.[].vuln_count] | add)})' osv.json

# All PURLs affected — direct input to CycloneDX VEX entries
jq -r '.results[].packages[].vulnerabilities[].affected[].package.purl' osv.json \
  | sort -u
```

## From finding to root cause

OSV's `aliases[]` is the bridge. Pull the CVE (or any other identifier `vdb` accepts) and feed it forward:

```bash
# Pull every CVE alias for a finding, then call vdb for each
jq -r '.results[].packages[].vulnerabilities[]
       | select(.id == "GHSA-35jh-r3h4-6jhm")
       | .aliases[] | select(startswith("CVE-"))' osv.json | while read cve; do
  vulnetix vdb vuln "$cve" --output json | jq '.[0].containers.adp[0] | {
    coordinator: .x_ssvc.decision,
    exploitation: .x_exploitationMaturity.level,
    kev: .x_kev.knownRansomwareCampaignUse,
    routines: .x_affectedRoutines
  }'
done
```

Engineer Triage from osv-scanner:

- **Reachability** — `affected[].package.purl` plus `x_affectedRoutines` for the grep target. Use the ecosystem-specific tool from the [package managers appendix](../appendices/package-managers/).
- **Remediation Option** — `affected[].ranges[].events[]` carries the fixed version. Check your lockfile to decide `PATCHABLE_DEPLOYMENT` vs `PATCHABLE_VERSION_LOCKED`.
- **Mitigation Option** — usually `AUTOMATION` (Dependabot / Renovate equivalent for your VCS).
- **Priority** — OSV `database_specific.severity` + Vulnetix `coordinator` + `exploitation`.

See [SSVC Engineer Triage](../appendices/ssvc/).

## Verify-affected and direct-vs-transitive

Before triaging, confirm the artefact is in the *running* build (not just the manifest), then classify direct vs transitive — the workflow is identical to any SCA finding and is covered in detail in the [Vulnetix SCA guide](../vulnetix/sca/#verify-affected---is-the-finding-real-for-your-build).

OSV-Scanner's JSON helps:

- `results[].packages[].package` is the affected package — match against your lockfile to confirm version drift.
- `results[].packages[].vulnerabilities[].affected[].package` plus `.ranges[]` tells you whether your installed version is in scope.
- `results[].packages[].dependencyGroups[]` (when present) distinguishes runtime from dev/test groups — a `dev`-only finding may not be in production at all (`vulnerable_code_not_present` candidate).

For Java findings reported against `pom.xml` or `gradle.lockfile`, jump straight to the [JVM appendix](../appendices/package-managers/jvm/) — it walks each of the dozen-plus mechanisms (direct version bump, `<dependencyManagement>` pin, BOM property override, Gradle `constraints { }` / `strictly` / `dependencySubstitution`, etc.) and which fits a transitive vs a direct finding.

## Patching mechanics

The [package managers appendix](../appendices/package-managers/) covers lockfile editing, transitive coercion, and integrity verification for every supported ecosystem.

## Decision tree

{{< decision >}}
osv-scanner emits PURLs by default, so findings tie directly to SBOM components.

  → CycloneDX VEX entry referencing the PURL from .affected[].package.purl

Is the OSV record from MAL-* (malicious package)?
  → Treat as incident, not a CVE — see ../scanners/vulnetix/sca/#worked-example-cve-2024-3094-xz-utils-backdoor for the pattern

Need a WAF / IPS / SIEM mitigation rule?
  → vulnetix vdb traffic-filters <CVE-from-aliases> supplies the rule
{{< /decision >}}

## Worked example: GHSA-35jh-r3h4-6jhm (lodash command injection) in a Go module's `go.sum`

That's a typo in the title — GHSA-35jh covers `lodash` which is npm-only. Let me use a real Go-side advisory instead: **GHSA-cg3q-j54f-5p7p** (`golang.org/x/crypto` SSH server panic, aliased to CVE-2024-45337).

osv-scanner output for `go.sum`:

```json
{
  "results": [{
    "source": { "path": "go.sum", "type": "lockfile" },
    "packages": [{
      "package": {
        "name": "golang.org/x/crypto",
        "version": "v0.30.0",
        "ecosystem": "Go"
      },
      "vulnerabilities": [{
        "id": "GHSA-cg3q-j54f-5p7p",
        "aliases": ["CVE-2024-45337", "GO-2024-3321"],
        "summary": "Misuse of ServerConfig.PublicKeyCallback may cause authorization bypass in golang.org/x/crypto",
        "affected": [{
          "package": {
            "name": "golang.org/x/crypto",
            "ecosystem": "Go",
            "purl": "pkg:golang/golang.org/x/crypto"
          },
          "ranges": [{
            "type": "SEMVER",
            "events": [
              { "introduced": "0" },
              { "fixed": "0.31.0" }
            ]
          }]
        }],
        "database_specific": { "severity": "CRITICAL" }
      }]
    }]
  }]
}
```

Pivot the alias to a CVE and pull Vulnetix's data:

```bash
vulnetix vdb vuln CVE-2024-45337 --output json \
  | jq '.[0].containers.adp[0] | {
          coordinator: .x_ssvc.decision,
          exploitation: .x_exploitationMaturity.level,
          routines: .x_affectedRoutines
        }'
# → coordinator: "Attend", exploitation: "POC", routines: [{
#     "kind": "function",
#     "name": "golang.org/x/crypto/ssh.ServerConfig.PublicKeyCallback"
#   }]
```

Reachability — do you build an SSH server using `golang.org/x/crypto/ssh.ServerConfig.PublicKeyCallback`? Drive the grep targets from OSV's own `affected[].ecosystem_specific.imports[]` when the advisory populates it, then fall back to vulnetix `x_affectedRoutines`:

```bash
go mod why golang.org/x/crypto
# → if it shows your main module → directly used; otherwise transitive

# Primary — OSV-native, from osv-scanner.json
SYMBOLS=$(jq -r '.results[].packages[].vulnerabilities[]
                  | select(.id=="GHSA-cg3q-j54f-5p7p")
                  | .affected[].ecosystem_specific.imports[]?.symbols[]?' osv-scanner.json \
            | sort -u)

# Fallback when OSV doesn't carry symbols
[ -z "$SYMBOLS" ] && SYMBOLS=$(vulnetix vdb vuln CVE-2024-45337 --output json \
  | jq -r '.[0].containers.adp[0].x_affectedRoutines[]?
           | select(.kind=="function") | .name')

# Grep for any of the affected APIs — regex composed from the symbol list
printf '%s\n' $SYMBOLS | paste -sd'|' - \
  | xargs -I{} git grep -nE '{}' ./
```

If the affected API isn't used, Engineer Triage → `Reachability: VERIFIED_UNREACHABLE`, `Remediation: PATCHABLE_DEPLOYMENT` (Go module bump), `Mitigation: AUTOMATION`, `Priority: HIGH` → `NIGHTLY_AUTO_PATCH`. If it is used (you operate an SSH server), `Reachability: VERIFIED_REACHABLE`, priority shifts to `CRITICAL` (the `Attend` Coordinator + active SSH service) → likely `DROP_TOOLS` for the immediate bump.

The bump from the [Go appendix](../appendices/package-managers/go/):

```bash
go get golang.org/x/crypto@v0.31.0
go mod tidy
```

{{< outcome type="cyclonedx" >}}
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "vulnerabilities": [{
    "id": "CVE-2024-45337",
    "source": {
      "name": "OSV",
      "url": "https://osv.dev/vulnerability/GHSA-cg3q-j54f-5p7p"
    },
    "ratings": [{ "source": { "name": "OSV" }, "severity": "critical" }],
    "affects": [{
      "ref": "pkg:golang/golang.org/x/crypto@v0.31.0",
      "versions": [
        { "version": "v0.30.0", "status": "affected" },
        { "version": "v0.31.0", "status": "unaffected" }
      ]
    }],
    "analysis": {
      "state": "resolved",
      "detail": "Engineer Triage: NIGHTLY_AUTO_PATCH. osv-scanner GHSA-cg3q-j54f-5p7p (CVE-2024-45337). Inputs: reachability=VERIFIED_UNREACHABLE (no ServerConfig usage; we're a client only, verified via go mod why plus git grep driven from OSV `affected.ecosystem_specific.imports` — symbols: PublicKeyCallback, ServerConfig — cross-checked with vulnetix `x_affectedRoutines`), remediation=PATCHABLE_DEPLOYMENT, mitigation=AUTOMATION, priority=HIGH. go get golang.org/x/crypto@v0.31.0 + go mod tidy in MR !91."
    }
  }]
}
```
{{< /outcome >}}

## Producing an OpenVEX

For OSV findings where the affected package lacks a PURL (rare — usually only when scanning a directory of binaries):

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-osv-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:00:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": {
      "name": "CVE-2024-45337",
      "description": "Misuse of ssh.ServerConfig.PublicKeyCallback. OSV: GHSA-cg3q-j54f-5p7p."
    },
    "products": [{
      "@id": "https://github.com/yourorg/yourrepo",
      "identifiers": { "purl": "pkg:github/yourorg/yourrepo@abc1234" }
    }],
    "status": "not_affected",
    "justification": "vulnerable_code_not_in_execute_path",
    "action_statement": "Engineer Triage: BACKLOG. We use golang.org/x/crypto as an SSH client only (golang.org/x/crypto/ssh.Dial), not as a server. ServerConfig.PublicKeyCallback is never instantiated. Confirmed with go mod why plus git grep driven from OSV `affected.ecosystem_specific.imports` (fallback: vulnetix `x_affectedRoutines`). Will pick up the bump on next module refresh."
  }]
}
```
{{< /outcome >}}
