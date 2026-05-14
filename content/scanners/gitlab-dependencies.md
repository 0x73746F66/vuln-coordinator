---
title: "GitLab Dependency Scanning"
description: "GitLab's first-party dep scanner — runs on every pipeline, JSON artefact with CVE / GHSA cross-references."
weight: 30
---

GitLab's Dependency Scanning job (part of the Secure stage) walks manifest files in your repository, queries the GitLab Advisory Database, and writes a `gl-dependency-scanning-report.json` artefact. Findings surface in the merge-request Security widget, the project's vulnerability report, and the security dashboard at the group level. The JSON artefact is the canonical source for triage work — the UI widgets are summaries on top of the same data.

The job is auto-included when you `include` the Secure template in your `.gitlab-ci.yml`. No extra config needed for the common ecosystems.

## What GitLab Dep Scanning finds in the JSON

```bash
# In CI the artefact is uploaded automatically; locally:
cat gl-dependency-scanning-report.json
```

The top-level shape:

```json
{
  "version": "15.0.7",
  "vulnerabilities": [ /* ... */ ],
  "remediations": [ /* ... */ ],
  "dependency_files": [ /* manifest paths */ ],
  "scan": { /* metadata */ }
}
```

Per-finding fields in `vulnerabilities[]`:

| Field | Purpose |
|---|---|
| `id` | GitLab's stable finding ID (a UUID) — used for tracking across pipelines |
| `category` | `"dependency_scanning"` — distinguishes from secret-detection / SAST findings if you merge reports |
| `cve` | The CVE reference if available; sometimes empty for newer or vendor-specific advisories |
| `identifiers[]` | Cross-references with `type`: `cve`, `ghsa`, `gemnasium`, `osvdb`, `snyk` |
| `location.dependency.package.name` + `.version` | The affected component |
| `location.file` | The manifest file the dep was resolved from |
| `severity` | `Critical` / `High` / `Medium` / `Low` / `Info` / `Unknown` (note the capitalisation) |
| `solution` | Free-text upgrade recommendation, typically "Upgrade to X.Y.Z" |
| `links[]` | URLs to upstream advisories |

## Querying with jq

```bash
# Every finding flattened
jq '.vulnerabilities[] | {
      id,
      cve,
      severity,
      package: .location.dependency.package.name,
      version: .location.dependency.package.version,
      file: .location.file,
      solution
    }' gl-dependency-scanning-report.json

# Critical + High only — the gating triage queue
jq '.vulnerabilities[]
    | select(.severity == "Critical" or .severity == "High")
    | {id, cve, severity, package: .location.dependency.package.name}' \
   gl-dependency-scanning-report.json

# Group by manifest file — split the work across maintainers
jq '[.vulnerabilities[] | {file: .location.file}]
    | group_by(.file)
    | map({file: .[0].file, count: length})' \
   gl-dependency-scanning-report.json

# All CVE identifiers — feed into vulnetix vdb in a loop
jq -r '.vulnerabilities[]
       | .identifiers[]?
       | select(.type == "cve") | .value' \
   gl-dependency-scanning-report.json | sort -u

# Pivot: GHSA where CVE is missing
jq '.vulnerabilities[]
    | select(.cve == "" or .cve == null)
    | .identifiers[]? | select(.type == "ghsa") | .value' \
   gl-dependency-scanning-report.json
```

## From finding to root cause

GitLab's `identifiers[]` is your bridge to Vulnetix's richer data. Pivot to a CVE (or GHSA) and call `vdb vuln`:

```bash
# Extract every CVE from the report, then pull SSVC + affected routines for each
jq -r '.vulnerabilities[].identifiers[]?
       | select(.type == "cve") | .value' \
   gl-dependency-scanning-report.json | sort -u | while read cve; do
  echo "=== $cve ==="
  vulnetix vdb vuln "$cve" --output json | jq '.[0].containers.adp[0] | {
    coordinator: .x_ssvc.decision,
    exploitation: .x_exploitationMaturity.level,
    kev: .x_kev.knownRansomwareCampaignUse,
    routines: .x_affectedRoutines
  }'
done
```

Engineer Triage inputs map from the GitLab finding as follows:

- **Reachability** — apply the ecosystem-specific reachability tool from the [package managers appendix](../appendices/package-managers/) against the function names from `x_affectedRoutines`.
- **Remediation Option** — read your lockfile constraint for `location.dependency.package.name`. If it allows the version in `solution`, it's `PATCHABLE_DEPLOYMENT`; if pinned, `PATCHABLE_VERSION_LOCKED`.
- **Mitigation Option** — typically `AUTOMATION` (Dependabot equivalent on GitLab is the dependency-update merge requests opened by the `Auto-Merge` workflow).
- **Priority** — GitLab `severity` plus Vulnetix `coordinator` + `exploitation`.

See [SSVC Engineer Triage](../appendices/ssvc/) for the framework.

## Patching mechanics

The [package managers appendix](../appendices/package-managers/) covers every supported ecosystem with the lockfile edit, transitive-coercion mechanism, integrity verification, and reachability tooling — JavaScript, Python, Java/Kotlin/Scala (JVM), .NET, Go, Rust, Ruby, PHP, Swift, and others.

## Decision tree

{{< decision >}}
Is the vulnerable package declared in your SBOM?
  ├─ Yes → CycloneDX VEX entry referencing the PURL from the SBOM
  └─ No  → OpenVEX statement (transitive not declared, or dev-only)

Is the risk mitigated by a WAF / IPS / SIEM rule from `vulnetix vdb traffic-filters <CVE>`?
  └─ If yes, status is `affected` with `workaround_available` and the rule reference
{{< /decision >}}

## Worked example: CVE-2022-1471 (SnakeYaml deserialization in a Spring Boot project)

GitLab Dep Scanning flags `org.yaml:snakeyaml@1.30` in `pom.xml`. The JSON entry:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "category": "dependency_scanning",
  "name": "Improper deserialization of YAML input in SnakeYaml",
  "severity": "High",
  "cve": "CVE-2022-1471",
  "identifiers": [
    { "type": "cve", "value": "CVE-2022-1471", "name": "CVE-2022-1471" },
    { "type": "ghsa", "value": "GHSA-mjmj-j48q-9wg2", "name": "GHSA-mjmj-j48q-9wg2" }
  ],
  "location": {
    "file": "pom.xml",
    "dependency": {
      "package": { "name": "org.yaml:snakeyaml" },
      "version": "1.30"
    }
  },
  "solution": "Upgrade org.yaml:snakeyaml to 2.0 or later."
}
```

SnakeYaml 1.x's `Yaml.load()` instantiates Ruby/Java objects from YAML — exploitable if your application calls it on untrusted input. The reachability question is whether you do.

Pull `x_affectedRoutines` to confirm the function names:

```bash
vulnetix vdb vuln CVE-2022-1471 --output json \
  | jq -r '.[0].containers.adp[0].x_affectedRoutines[]?
           | select(.kind == "function") | .name'
# → org.yaml.snakeyaml.Yaml.load
#   org.yaml.snakeyaml.Yaml.loadAll
```

Grep the codebase:

```bash
git grep -nE '\bYaml\.(load|loadAll)\b' src/main/java/
```

If `Yaml.load` is called on a request body or a user-uploaded file, the finding is reachable and exploitable — Engineer Triage moves toward `DROP_TOOLS` for a critical-priority deployment. If it's only called on a bundled config file the user can't influence, `Reachability: VERIFIED_REACHABLE` but `Priority` drops because the input is constant.

The patch is non-trivial — SnakeYaml 2.0 changes the default loader to `SafeConstructor`, which breaks code that relied on automatic class instantiation. From the [JVM appendix](../appendices/package-managers/jvm/):

```xml
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.yaml</groupId>
      <artifactId>snakeyaml</artifactId>
      <version>2.2</version>
    </dependency>
  </dependencies>
</dependencyManagement>
```

Spring Boot 3.1+ already brings SnakeYaml ≥ 2.0 transitively, so bumping Spring Boot resolves it. Spring Boot 2.x users coerce via `dependencyManagement`. Engineer Triage: `Remediation: PATCHABLE_VERSION_LOCKED` (the bump may break custom YAML loaders), `Mitigation: CODE_CHANGE` (audit all `Yaml.load` call sites), `Priority: HIGH` — outcome `SPIKE_EFFORT`.

{{< outcome type="cyclonedx" >}}
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "vulnerabilities": [{
    "id": "CVE-2022-1471",
    "source": { "name": "GitLab Advisory DB", "url": "https://advisories.gitlab.com/" },
    "ratings": [{ "source": { "name": "NVD" }, "severity": "high", "method": "CVSSv3" }],
    "affects": [{
      "ref": "pkg:maven/org.yaml/snakeyaml@2.2",
      "versions": [
        { "version": "1.30", "status": "affected" },
        { "version": "2.2", "status": "unaffected" }
      ]
    }],
    "analysis": {
      "state": "resolved",
      "detail": "Engineer Triage: SPIKE_EFFORT. Inputs: reachability=VERIFIED_REACHABLE (Yaml.load called in com.example.config.AppConfig.parseConfig), remediation=PATCHABLE_VERSION_LOCKED (default loader changed in 2.0; required audit of 3 call sites), mitigation=CODE_CHANGE (switched 1 site to SafeConstructor explicitly, the other 2 only load bundled resources), priority=HIGH. Pinned snakeyaml to 2.2 via pom.xml's <dependencyManagement>. mvn dependency:tree confirms no transitive resolves a 1.x version. See MR !154."
    }
  }]
}
```
{{< /outcome >}}

## Producing an OpenVEX

For findings against dev-only or build-time deps (rare for `dependency_scanning` since GitLab scopes are usually production), the subject is the repo:

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://gitlab.com/yourorg/yourrepo/-/vex/2026-05-14-gldeps-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:00:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": {
      "name": "CVE-2022-1471",
      "description": "Improper deserialization in SnakeYaml. See https://nvd.nist.gov/vuln/detail/CVE-2022-1471"
    },
    "products": [{
      "@id": "https://gitlab.com/yourorg/yourrepo",
      "identifiers": { "purl": "pkg:gitlab/yourorg/yourrepo@abc1234" }
    }],
    "status": "not_affected",
    "justification": "component_not_present",
    "action_statement": "snakeyaml@1.30 is in test scope only via the spring-boot-starter-test BOM. The production artefact is built with mvn package -DskipTests and does not include the test classpath. Verified with mvn dependency:tree -Dscope=runtime showing no snakeyaml. Engineer Triage: NIGHTLY_AUTO_PATCH — Spring Boot bumps will pick up SnakeYaml 2.x transitively in due course."
  }]
}
```
{{< /outcome >}}
