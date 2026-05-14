---
title: "Trivy"
description: "Aqua Security's polyscanner — SCA + secrets + IaC + SBOM + license in one binary; native VEX consumption (CycloneDX + OpenVEX)."
weight: 95
---

> **OSS** (Apache-2.0) · [Aqua Security](https://www.aquasec.com/) · [aquasecurity/trivy](https://github.com/aquasecurity/trivy) · [Docs](https://aquasecurity.github.io/trivy/) · Companion check set: [aquasecurity/trivy-checks](https://github.com/aquasecurity/trivy-checks)

Trivy is the polyscanner alternative to [Grype](../grype/): the same OS-package and language-ecosystem SCA coverage *plus* secrets, IaC, SBOM, license, and Dockerfile / Kubernetes misconfiguration analysis under a single binary and a single feed pipeline. One invocation against an image returns OS-package CVEs, lockfile CVEs, embedded secrets, and misconfig findings together — the trait that makes Trivy the right pick when a team wants one tool to cover several finding classes from one report.

The other feature worth calling out up front is **native consumption of both CycloneDX VEX and OpenVEX** via `--vex` (Grype consumes OpenVEX only). For a triage workflow that already maintains a CycloneDX VEX next to the SBOM, this halves the format-juggling.

## Modes overview

Trivy is one binary with many subcommands; the triage workflow you choose depends on which mode you ran:

| Mode | Command | What it scans | Findings produced |
|---|---|---|---|
| Image | `trivy image <ref>` | OCI image layers | OS pkgs + lang deps + secrets + misconfig + licenses |
| Filesystem | `trivy fs <path>` | Local source tree | Manifests + secrets + IaC + licenses |
| Repo | `trivy repo <url>` | Remote git repo | Same as `fs` (cloned first) |
| SBOM | `trivy sbom <file>` | Existing CycloneDX or SPDX SBOM | Vuln matches against the SBOM components |
| Config | `trivy config <path>` | Terraform / CloudFormation / Dockerfile / k8s YAML / Helm | Misconfig findings only |
| Kubernetes | `trivy k8s <cluster>` | Live k8s cluster | All finding classes across every resource |
| VM | `trivy vm <ref>` | VM images (qcow2 / vmdk / AMI) | OS pkgs + secrets |
| AWS | `trivy aws` | Live AWS account | Cloud-config misconfig |
| Plugin | `trivy plugin run …` | Third-party plugin | Plugin-specific |

The two most common triage entry points are `image` (CI / pre-deploy gate on a built container) and `fs` (developer-local pre-commit). The `sbom` mode is the recommended path for VEX-aware triage — same reasoning as Grype's `sbom:` mode: you re-scan the artefact you already trust, no re-resolution.

## What Trivy finds in JSON

```bash
# Image scan, JSON output
trivy image -f json -o trivy.json ghcr.io/yourorg/myapp:2.3.0

# Filesystem scan
trivy fs -f json -o trivy.json .

# SBOM re-scan (the recommended path for VEX-aware triage)
trivy sbom -f json -o trivy.json ./.vulnetix/sbom.cdx.json

# Include every scanner family in one image run
trivy image --scanners vuln,secret,misconfig,license -f json -o trivy.json <ref>
```

Top-level shape:

```json
{
  "SchemaVersion": 2,
  "ArtifactName": "ghcr.io/yourorg/myapp:2.3.0",
  "ArtifactType": "container_image",
  "Results": [
    {
      "Target": "ghcr.io/yourorg/myapp (debian 12.5)",
      "Class": "os-pkgs",
      "Type": "debian",
      "Vulnerabilities": [ /* one per OS-pkg finding */ ]
    },
    {
      "Target": "app/package-lock.json",
      "Class": "lang-pkgs",
      "Type": "npm",
      "Vulnerabilities": [ /* one per lockfile finding */ ]
    },
    {
      "Target": "Dockerfile",
      "Class": "config",
      "Type": "dockerfile",
      "Misconfigurations": [ /* one per misconfig */ ]
    },
    {
      "Target": "src/.env",
      "Class": "secret",
      "Secrets": [ /* one per secret hit */ ]
    }
  ]
}
```

Per-vulnerability fields:

| Field | Purpose |
|---|---|
| `Results[].Vulnerabilities[].VulnerabilityID` | CVE / GHSA / OS-vendor advisory ID |
| `Results[].Vulnerabilities[].PkgName` + `.InstalledVersion` | Matched component |
| `Results[].Vulnerabilities[].PkgIdentifier.PURL` | PURL — direct input to a CycloneDX VEX entry |
| `Results[].Vulnerabilities[].FixedVersion` | Versions that include the fix (empty when no fix) |
| `Results[].Vulnerabilities[].Status` | `fixed` / `affected` / `under_investigation` / `will_not_fix` / `fix_deferred` / `end_of_life` |
| `Results[].Vulnerabilities[].Severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `UNKNOWN` |
| `Results[].Vulnerabilities[].CVSS` | Map keyed by vendor (`nvd`, `redhat`, `ghsa`) with `V3Vector`, `V3Score`, `V40Vector`, `V40Score` |
| `Results[].Vulnerabilities[].PrimaryURL` | Canonical advisory URL |
| `Results[].Vulnerabilities[].DataSource` | Which feed supplied the record (NVD / GHSA / Debian / Alpine / RedHat / GitLab) |
| `Results[].Class` | `os-pkgs` / `lang-pkgs` / `config` / `secret` / `license` |
| `Results[].Type` | Within a class: e.g. `debian`, `alpine`, `rpm`, `npm`, `pip`, `gomod`, `maven`, `dockerfile`, `kubernetes`, `terraform` |

Per-misconfig and per-secret records carry different shapes:

| Field | Purpose |
|---|---|
| `Results[].Misconfigurations[].ID` | Built-in rule ID (`DS001`..`DS031` for Dockerfile, `KSV001`..` ` for k8s) |
| `Results[].Misconfigurations[].AVDID` | Aqua Vulnerability DB ID |
| `Results[].Misconfigurations[].Title` / `.Description` / `.Message` | Human-readable explanation |
| `Results[].Misconfigurations[].Resolution` | One-line fix recipe |
| `Results[].Misconfigurations[].References[]` | External advisory URLs |
| `Results[].Misconfigurations[].CauseMetadata.StartLine` / `.EndLine` | File coordinates |
| `Results[].Secrets[].RuleID` | Provider rule (`aws-access-key-id`, `github-pat`, …) |
| `Results[].Secrets[].Match` | Redacted match snippet |
| `Results[].Secrets[].StartLine` / `.EndLine` | File coordinates |

## Querying with jq

```bash
# Every vulnerability flattened across all Results
jq '[.Results[]
     | select(.Vulnerabilities)
     | .Class as $class | .Target as $target
     | .Vulnerabilities[]
     | {id: .VulnerabilityID, pkg: .PkgName, version: .InstalledVersion,
        fix: .FixedVersion, severity: .Severity, purl: .PkgIdentifier.PURL,
        class: $class, target: $target}]' trivy.json

# Critical + High gating queue
jq '.Results[].Vulnerabilities[]?
    | select(.Severity == "CRITICAL" or .Severity == "HIGH")
    | {id: .VulnerabilityID, purl: .PkgIdentifier.PURL, fix: .FixedVersion}' \
   trivy.json

# OS-package findings only (Grype-style Class A — base-image triage)
jq '.Results[] | select(.Class == "os-pkgs") | .Vulnerabilities[]
    | {id: .VulnerabilityID, pkg: .PkgName, fix: .FixedVersion,
       distro: .DataSource.Name}' trivy.json

# Language-ecosystem findings only (Grype-style Class B — SCA triage)
jq '.Results[] | select(.Class == "lang-pkgs") | .Vulnerabilities[]
    | {id: .VulnerabilityID, pkg: .PkgName, manifest: ($target // "n/a"),
       fix: .FixedVersion}' trivy.json

# Misconfig findings with the Resolution recipe (read before VEX-ing)
jq '.Results[] | select(.Misconfigurations) | .Misconfigurations[]
    | {id: .ID, avd: .AVDID, severity: .Severity, where: .CauseMetadata,
       fix: .Resolution}' trivy.json

# Secrets findings
jq '.Results[] | select(.Class == "secret") | {target: .Target,
    hits: [.Secrets[] | {rule: .RuleID, line: .StartLine, match: .Match}]}' \
   trivy.json

# Findings with no fix available (will_not_fix / fix_deferred / end_of_life)
jq '.Results[].Vulnerabilities[]?
    | select(.FixedVersion == null or .FixedVersion == "")
    | {id: .VulnerabilityID, pkg: .PkgName, status: .Status,
       severity: .Severity}' trivy.json
```

## From finding to root cause

The pivot depends on `Results[].Class`. Read it first; everything else flows from there.

### Class `os-pkgs` (Grype Class A — OS-package finding)

Trivy emitted a CVE against an OS package in the image (deb / apk / rpm). Triage is identical to [Grype's Class A](../grype/#class-a--os-package-finding-base-layer):

- **Option 1**: bump the `FROM` tag.
- **Option 2**: upgrade the specific package during build (`apt-get install foo=…`, `apk add 'foo>=…'`).
- **Option 3**: migrate to a maintained hardened base — see [Grype § Class A — fix mechanics](../grype/#class-a--fix-mechanics) for the UBI / Chainguard / distroless / Wolfi catalogue and rationale.

Pull Engineer Triage inputs from Vulnetix's VDB before deciding:

```bash
ID=$(jq -r '[.Results[] | select(.Class=="os-pkgs") | .Vulnerabilities[]]
            | .[0].VulnerabilityID' trivy.json)
vulnetix vdb vuln "$ID" --output json \
  | jq '.[0].containers.adp[0] | {coordinator: .x_ssvc.decision,
        exploitation: .x_exploitationMaturity.level,
        kev: .x_kev.knownRansomwareCampaignUse,
        routines: .x_affectedRoutines}'
```

### Class `lang-pkgs` (Grype Class B — language ecosystem)

Trivy reports the manifest path in `.Target` (e.g. `app/package-lock.json`). Fix in the source repo's manifest using the appropriate workflow in the [package managers appendix](../../appendices/package-managers/), then rebuild the image. False-pivot trap: don't try to upgrade the OS to fix an npm CVE.

### Class `config` (misconfig)

`Results[].Misconfigurations[].Resolution` is a one-line fix recipe — read it before reaching for a VEX. Trivy's IaC findings have direct remediation guidance that most SCA findings don't. For Dockerfile findings, the rule IDs are `DS001..DS031`; for Kubernetes manifests, `KSV001..KSV*`. Cross-reference Aqua's [trivy-checks catalogue](https://github.com/aquasecurity/trivy-checks) for the rule's intent. If the misconfig is intentional (a CI bastion host that legitimately runs as root), record it as an OpenVEX `not_affected` with `justification: "inline_mitigations_already_exist"`.

### Class `secret`

Rotate the credential first; *then* triage the leak. Trivy's bundled scanner finds secrets in the current tree only — it does **not** walk git history. For history coverage, pair with [GitHub Secret Scanning](../github-secrets/) (GitHub-hosted repos) or gitleaks. Once rotated, suppress with an OpenVEX statement using a non-PURL subject (the file path + line + rule ID) — there's no PURL for a secret.

### Class `license`

Run with `--scanners license` to surface license findings. Pivot to the [license-check](../vulnetix/) workflow if your policy needs an SBOM-style report.

## VEX loop

Trivy's `--vex` consumes **both** CycloneDX VEX and OpenVEX (Trivy auto-detects which one):

```bash
# Scan with both forms in scope
trivy image --vex ./.vulnetix/vex.cdx.json --vex ./.vulnetix/vex.openvex.json \
            -f json -o trivy.json <ref>
```

Findings whose subject + ID matches a VEX statement disappear from `Results[].Vulnerabilities[]` on the next run. The legacy alternative is `.trivyignore` — a flat file of CVE IDs to suppress unconditionally. **Prefer VEX over `.trivyignore`** for new work: VEX entries are auditable, scoped to a specific PURL, carry a justification, and travel with the SBOM to downstream consumers; `.trivyignore` is repo-local and opaque.

## Decision tree

{{< decision >}}
Trivy emits a PURL for every package finding and a path-based subject for misconfig / secret findings.

For Vulnerabilities[] (PURL-backed):
  → CycloneDX VEX entry referencing .PkgIdentifier.PURL
    (compact when you already maintain a CycloneDX SBOM next to the image)

For Misconfigurations[] (no PURL — file path + rule ID is the subject):
  → OpenVEX statement, subject is "<file>:<startLine>" or the AVD ID

For Secrets[] (no PURL):
  → OpenVEX statement, subject is "<file>:<startLine>:<RuleID>"
  → rotate the credential first; VEX records the triage decision, not the fix

Trivy consumes either format via --vex, so format choice is driven by what
downstream consumers expect, not by Trivy itself.

Need a WAF / IPS / SIEM mitigation while a fix is in flight?
  → vulnetix vdb traffic-filters <CVE> supplies the rule;
    record the workaround in the VEX action_statement
{{< /decision >}}

## Worked example: CVE-2023-50387 (KeyTrap DNSSEC) on `libbind9-9` in a Debian-based image

The same CVE that drives the [Grype worked example](../grype/#worked-example-cve-2023-50387-keytrap-dnssec-on-libbind9-in-a-debian-based-image), so the two outputs can be read side-by-side.

```bash
trivy image -f json --scanners vuln ghcr.io/library/postgres:16.2 > trivy.json
```

The match record:

```json
{
  "Results": [{
    "Target": "ghcr.io/library/postgres:16.2 (debian 12.5)",
    "Class": "os-pkgs",
    "Type": "debian",
    "Vulnerabilities": [{
      "VulnerabilityID": "CVE-2023-50387",
      "PkgName": "libbind9-9",
      "PkgIdentifier": {
        "PURL": "pkg:deb/debian/libbind9-9@1:9.18.19-1~deb12u1?distro=debian-12"
      },
      "InstalledVersion": "1:9.18.19-1~deb12u1",
      "FixedVersion": "1:9.18.28-1~deb12u2",
      "Status": "fixed",
      "Severity": "HIGH",
      "CVSS": {
        "nvd": { "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                 "V3Score": 7.5 }
      },
      "DataSource": { "Name": "Debian Security Tracker", "URL": "…" }
    }]
  }]
}
```

`Class: os-pkgs` + `Type: debian` says this is a base-image dpkg match. The reachability check is the same as Grype's — does any binary in the image actually link against `libbind9`?

```bash
LIB=$(jq -r '[.Results[].Vulnerabilities[]?
              | select(.VulnerabilityID=="CVE-2023-50387")][0].PkgName' \
       trivy.json)

docker run --rm --entrypoint sh ghcr.io/library/postgres:16.2 \
  -c "find / -type f -executable 2>/dev/null \
      | xargs -I{} sh -c 'ldd {} 2>/dev/null | grep -l \"$LIB\" && echo {}'" \
  | sort -u
```

No binary in the runtime image links against `libbind9` — PostgreSQL doesn't use BIND's resolver; the package was pulled in as a dpkg dependency of a tool that doesn't exercise the vulnerable code path. Engineer Triage: `Reachability: VERIFIED_UNREACHABLE`, `Remediation: PATCHABLE_DEPLOYMENT` (next base-image bump picks up the fix), `Priority: HIGH` — outcome `NIGHTLY_AUTO_PATCH`.

Because Trivy emits a PURL for every package finding, **CycloneDX VEX is the right format here** (contrast with Grype's worked example, which uses OpenVEX because Grype's `--vex` is OpenVEX-only). Trivy consumes either:

{{< outcome type="cyclonedx" >}}
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "vulnerabilities": [{
    "id": "CVE-2023-50387",
    "source": { "name": "NVD" },
    "affects": [{
      "ref": "pkg:deb/debian/libbind9-9@1:9.18.19-1~deb12u1?distro=debian-12",
      "versions": [{ "version": "1:9.18.19-1~deb12u1", "status": "affected" }]
    }],
    "analysis": {
      "state": "not_affected",
      "justification": "code_not_reachable",
      "detail": "Engineer Triage: BACKLOG (escalated to NIGHTLY_AUTO_PATCH at next base-image bump). libbind9-9 is in the postgres:16.2 base image as a transitive dpkg dependency but no binary in the image links against it — verified by walking executables under / with ldd, no result matched libbind9. Will pick up the fix automatically when the base image is bumped past 1:9.18.28."
    }
  }]
}
```
{{< /outcome >}}

Verification on the next scan:

```bash
trivy image --vex ./.vulnetix/vex.cdx.json -f json ghcr.io/library/postgres:16.2 \
  | jq '[.Results[].Vulnerabilities[]?
         | select(.VulnerabilityID == "CVE-2023-50387")] | length'
# → 0 (the finding is suppressed)
```

If you also need an OpenVEX form (for tools in your pipeline that consume that format):

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-trivy-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:00:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": { "name": "CVE-2023-50387" },
    "products": [{
      "@id": "pkg:deb/debian/libbind9-9@1:9.18.19-1~deb12u1?distro=debian-12"
    }],
    "status": "not_affected",
    "justification": "vulnerable_code_not_in_execute_path",
    "action_statement": "Engineer Triage: BACKLOG (NIGHTLY_AUTO_PATCH). Mirrors the CycloneDX VEX statement at vex.cdx.json — Trivy consumes either form."
  }]
}
```
{{< /outcome >}}

## All-modes triage notes

- **`image` / `fs`** — same finding classes as Grype (A/B/C/D in [Grype's taxonomy](../grype/#first-identify-the-finding-class)). `Results[].Class` does the discrimination for you. Always scan the **runtime** stage of a multi-stage build, not the build stage: `docker build --target=runtime -t myapp:runtime && trivy image myapp:runtime`.
- **`config`** — every misconfig finding has a `Resolution` field; read it before VEX-ing. Dockerfile rule IDs are `DS001..DS031`, k8s are `KSV001..KSV*`. Override or extend with custom Rego policies — see the next section.
- **`k8s`** — collates findings cluster-wide. Expect heavy noise from `kube-system` and other operator-owned namespaces; filter with `--include-namespaces` / `--exclude-namespaces` early.
- **`secret`** — current-tree only; **not** a git-history scanner. Pair with [GitHub Secret Scanning](../github-secrets/) (GitHub-hosted) or gitleaks for history. False-positive rate is non-trivial on test fixtures and example files — Trivy honours an inline `# trivy:ignore` comment for genuine fixtures.
- **`sbom`** — the VEX-aware path. Re-scan the SBOM you already trust without re-resolving the dependency tree from the lockfile.
- **`vm`** / **`aws`** — out of scope for the typical app-team triage workflow; mentioned for completeness. The `aws` mode requires an authenticated session (env vars / `~/.aws/credentials`) and reads live cloud config — expect long scans on large accounts.

## Vulnetix `opa-aquasecurity-trivy` rule set

[vulnetix/opa-aquasecurity-trivy](https://github.com/vulnetix/opa-aquasecurity-trivy) (Apache-2.0) is a Vulnetix-compatible OPA/Rego bundle that re-implements the *intent* of Aqua Security's [trivy-checks](https://github.com/aquasecurity/trivy-checks) inside the Vulnetix pipeline. It is not a plugin loaded into Trivy itself — it is consumed by `vulnetix scan`:

```bash
# Run alongside Vulnetix's default rules
vulnetix scan --rule Vulnetix/opa-aquasecurity-trivy

# Or as the sole rule set (replaces Vulnetix's defaults)
vulnetix scan --rule Vulnetix/opa-aquasecurity-trivy --disable-default-rules
```

What it ships:

- **28 Dockerfile rules** under the `vulnetix.rules.trivy_docker_*` namespace, IDs `TRIVY-DS-001..028` — covering `ADD` vs `COPY`, root-user containers, package pinning, embedded secrets in `RUN` lines, and the rest of Trivy's Dockerfile catalogue.
- **79 Kubernetes-manifest rules** under `vulnetix.rules.trivy_k8s_*`, IDs `TRIVY-KSV-001..079` — pod / container security, dropped capabilities, RBAC scope, Pod Security Standards controls.

**Why use it**: a team that has standardised on Vulnetix as the merge-gate scanner but wants Trivy's Dockerfile / k8s rule *coverage* without running two scanners gets the rule intent inside the Vulnetix workflow — same `.vulnetix/memory.yaml` triage history, same VEX emit path, same CWSS scoring as every other Vulnetix finding. Conversely, a team running Trivy as their primary container scanner can still use Aqua's upstream `trivy-checks` (the canonical Rego bundle) directly via `trivy config --policy …` — the two are complementary, not competing.

## Producing a VEX

For PURL-backed findings — `Results[].Vulnerabilities[]` regardless of class — **CycloneDX VEX** is the natural fit because every record carries a `PkgIdentifier.PURL`. For non-PURL findings (`Misconfigurations[]`, `Secrets[]`), **OpenVEX** with a file-path-based subject is the right choice. Trivy consumes either via `--vex`, so the format choice is driven by what your downstream pipeline already speaks (Vulnetix consumes both; Grype is OpenVEX-only; CycloneDX-only consumers exist too — maintain both forms when the audience is mixed).

## Capability snapshot

See the [capability matrix](../#capability-matrix) for the full comparison. Trivy's row in summary:

- **Coverage**: SCA (lockfile + container OS pkgs), IaC, Dockerfile, k8s, secrets, license — broader than Grype, narrower than Vulnetix on enrichment.
- **[Database quality](../#database-quality-tiers)**: NVD + GHSA + GitLab Advisory DB + Debian Security Tracker + Ubuntu USN + Alpine secdb + RedHat OVAL + Amazon ALAS + Wolfi + Chainguard + OSV. Comparable to osv-scanner's feed breadth; broader than Grype on ecosystem aggregation.
- **[Reachability](../../appendices/reachability-deep-dive/)**: **[Tier 1](../../appendices/reachability-deep-dive/#tier-1)** (package-level only). The `ldd | grep <lib>` recipe is a Tier-1.5 manual technique. For Tier-2/3 evidence, cross-reference [Vulnetix](../vulnetix/) or run a SAST tool ([CodeQL](../github-codeql/), [Snyk SAST](../snyk-sast/)) against the application code.
- **Exploit maturity**: severity label only; no EPSS / KEV / sightings / weaponisation indicators. Cross-reference Vulnetix VDB for risk-signal depth.
- **[EOL](../../appendices/eol/)**: not native; inferred when no fix is available in the feed. For runtime / package / base-image EOL, cross-reference [endoflife.date](https://endoflife.date/) or [Vulnetix](../vulnetix/).
- **[Supply-chain threats](../../appendices/supply-chain-threats/)**: reactive only (via OSV `MAL-` records). No proactive typosquat or maintainer-health.
- **Outputs**: JSON (rich, native), [SARIF](../../appendices/sarif/) (flat), CycloneDX 1.4 / 1.5 / 1.6, SPDX 2.2 / 2.3, HTML / Markdown / JUnit XML via templates. **VEX consumption** via `--vex` — *both* CycloneDX VEX and OpenVEX. No native VEX emission.

## See also

- [Capability matrix](../#capability-matrix) — Trivy's column in context.
- [Grype](../grype/) — closest peer; the finding-class taxonomy (A / B / C / D) on Grype's page applies identically to Trivy's `os-pkgs` / `lang-pkgs` output.
- [vulnetix/opa-aquasecurity-trivy](https://github.com/vulnetix/opa-aquasecurity-trivy) — Vulnetix-compatible Rego bundle re-implementing the intent of Trivy's Dockerfile and k8s checks.
- [Reachability deep-dive](../../appendices/reachability-deep-dive/) — what Tier-1 evidence supports, and when you need Tier 2/3.
- [EOL appendix](../../appendices/eol/) — for the "should I bump or migrate this base image?" decision.
- [Supply-chain threats](../../appendices/supply-chain-threats/) — for `MAL-` records Trivy's OSV feed surfaces.
- [Glossary](../../appendices/glossary/) — definitions for the terms used above.
