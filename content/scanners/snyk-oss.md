---
title: "Snyk OSS"
description: "Snyk's dependency vulnerability scanner — JSON or SARIF output, SNYK-* identifiers cross-referenced to CVE / GHSA."
weight: 10
---

> **Commercial** (Snyk Ltd) · [Docs](https://docs.snyk.io/scan-using-snyk/snyk-open-source) · CLI source: [snyk/cli](https://github.com/snyk/cli) (Apache-2.0) · Free tier with monthly test caps; paid plans for full features.

Snyk OSS (Open Source) resolves the declared dependency tree from your manifest files — `package-lock.json`, `requirements.txt`, `pom.xml`, `go.sum`, `Cargo.lock`, and the other locks you'd expect across 30+ ecosystems — and matches each component against the Snyk vulnerability database. You'll see it as a CI step (`snyk test`), as IDE squiggles, as merge-request decoration when integrated with the platform's bot, or as the `snyk monitor` dashboard for continuous tracking after a release.

For triage work the JSON output is the source of truth; the dashboard and the MR comment are UI summaries on top.

## What Snyk OSS finds in JSON

```bash
snyk test --json > snyk-results.json
# or for SARIF:
snyk test --sarif-file-output=snyk-results.sarif
```

The top-level shape carries one entry per project / lockfile. The `vulnerabilities[]` array is where everything you'll touch lives.

| Field | Purpose |
|---|---|
| `vulnerabilities[].id` | Snyk's identifier — `SNYK-JS-LODASH-1018905` or similar. Cross-referenced to CVE / GHSA below |
| `vulnerabilities[].severity` | `critical` / `high` / `medium` / `low` |
| `vulnerabilities[].packageName` + `.version` | The specific component version that's flagged |
| `vulnerabilities[].from[]` | The dependency path as a list — index 0 is your project, last is the vulnerable component |
| `vulnerabilities[].upgradePath[]` | Which top-level bump fixes it. `false` at index 0 means no top-level upgrade resolves it; later indices give the chain |
| `vulnerabilities[].isPatchable` | Whether Snyk has a patch file (not always available) |
| `vulnerabilities[].fixedIn[]` | The first version that includes the fix |
| `vulnerabilities[].identifiers.CVE[]` | The CVE cross-reference — what you'd use to call `vulnetix vdb vuln` |
| `vulnerabilities[].identifiers.CWE[]` | CWE classification |
| `vulnerabilities[].exploit` | Snyk's exploit-maturity rating (`Mature` / `Proof of Concept` / `No Known Exploit`) |

## Querying with jq

```bash
# Every finding as {id, cve, severity, package, version}
jq '.vulnerabilities[] | {
      id,
      cve: .identifiers.CVE[0],
      severity,
      package: .packageName,
      version,
      fix: .fixedIn[0]
    }' snyk-results.json

# Filter to high + critical
jq '.vulnerabilities[]
    | select(.severity == "high" or .severity == "critical")
    | {id, severity, package: .packageName}' snyk-results.json

# Group by package — which deps account for most findings?
jq '[.vulnerabilities[] | {package: .packageName}]
    | group_by(.package)
    | map({package: .[0].package, count: length})
    | sort_by(-.count)' snyk-results.json

# Walk the dependency path for one finding
jq '.vulnerabilities[]
    | select(.id == "SNYK-JS-LODASH-1018905")
    | .from' snyk-results.json

# All upgradePaths — the bumps that would resolve findings
jq '.vulnerabilities[] | {
      id,
      from: .from[1],
      upgradeTo: .upgradePath[1]
    }' snyk-results.json
```

## From finding to root cause

```bash
# 1. Read the CVE for one finding (or all of them)
CVE=$(jq -r '.vulnerabilities[0].identifiers.CVE[0]' snyk-results.json)

# 2. Pull SSVC + KEV + EPSS from Vulnetix for the priority input
vulnetix vdb vuln "$CVE" --output json \
  | jq '.[0].containers.adp[0] | {
          coordinator: .x_ssvc.decision,
          exploitation: .x_exploitationMaturity.level,
          kev: .x_kev.knownRansomwareCampaignUse,
          epss: .x_exploitationMaturity.factors.epss
        }'

# 3. The affected functions/files — feed into reachability grep
vulnetix vdb vuln "$CVE" --output json \
  | jq -r '.[0].containers.adp[0].x_affectedRoutines[]?
           | select(.kind == "function") | .name'

# 4. Snyk's own upgrade suggestion
jq '.vulnerabilities[]
    | select(.identifiers.CVE[0] == env.CVE)
    | .upgradePath' snyk-results.json
```

Apply the Engineer Triage inputs:

- **Reachability** — `VERIFIED_REACHABLE` if the affected function name is referenced from your code; `VERIFIED_UNREACHABLE` if you can prove the call site is dead; `UNKNOWN` otherwise.
- **Remediation Option** — read your lockfile's constraint for the affected component. Caret-range = `PATCHABLE_DEPLOYMENT`; exact pin = `PATCHABLE_VERSION_LOCKED`; no fixed version = `PATCH_UNAVAILABLE`.
- **Mitigation Option** — usually `AUTOMATION` for SCA (let Dependabot / Renovate open the PR after the appendix-prescribed coercion).
- **Priority** — Snyk's `severity` plus the Vulnetix `coordinator` + `exploitation` reads.

See [SSVC Engineer Triage](../appendices/ssvc/) for the full decision tree.

## Verify-affected and direct-vs-transitive

Before picking a fix, prove the finding is real for *your* build and decide whether the artefact is direct or transitive — the mechanism is the same as for any SCA finding, captured in detail in the [Vulnetix SCA guide](../vulnetix/sca/#verify-affected---is-the-finding-real-for-your-build) and the [direct-vs-transitive triage section](../vulnetix/sca/#direct-vs-transitive-triage--which-knob-do-you-turn).

Snyk's JSON makes this fast:

- `vulnerabilities[].from[]` is the resolved path from your project root to the affected component. Length 2 (`[myapp, lodash]`) → direct dep. Length 3+ → transitive; the middle entries are the parents to consider bumping.
- `vulnerabilities[].upgradePath[]` aligns 1:1 with `from[]`. `upgradePath[0] === false` means no top-level bump fixes it — you must coerce the transitive. Any later index that's a string is a viable parent-bump target (`upgradePath[1]` is the closest-to-root remediation).
- `vulnerabilities[].fixedIn[]` is the minimum version that drops the finding. Compare against your lockfile's constraint for `PATCHABLE_DEPLOYMENT` vs `PATCHABLE_VERSION_LOCKED`.

## Patching mechanics

Lockfile editing, transitive coercion, and integrity verification are in the **[package managers appendix](../appendices/package-managers/)** — one page per ecosystem (`npm` lives under [JavaScript](../appendices/package-managers/javascript/), `pip` under [Python](../appendices/package-managers/python/), and so on). For Java findings, the [JVM appendix](../appendices/package-managers/jvm/) covers the dozen-plus Maven and Gradle mechanisms (BOM property override, `<dependencyManagement>`, Gradle `constraints { }` / `strictly` / `dependencySubstitution`, etc.) and which one to pick based on whether Snyk reports a direct or transitive finding.

## Decision tree

{{< decision >}}
Is the vulnerable package declared in your SBOM?
  ├─ Yes → CycloneDX VEX entry referencing the PURL
  └─ No  → OpenVEX statement (transitive dep not declared, or build-time-only tool)

Is the risk mitigated by a WAF / IPS / SIEM rule from `vulnetix vdb traffic-filters <CVE>`?
  └─ If yes, status is `affected` with `workaround_available` and the rule reference
{{< /decision >}}

## Worked example: SNYK-JS-LODASH-1018905 (CVE-2021-23337)

Snyk flags `lodash@4.17.20` with a command-injection finding in `template`. The relevant slice of the JSON:

```json
{
  "vulnerabilities": [{
    "id": "SNYK-JS-LODASH-1018905",
    "severity": "high",
    "packageName": "lodash",
    "version": "4.17.20",
    "from": ["myapp@1.0.0", "express-templating@2.3.0", "lodash@4.17.20"],
    "upgradePath": [false, "express-templating@2.3.0", "lodash@4.17.21"],
    "fixedIn": ["4.17.21"],
    "identifiers": {
      "CVE": ["CVE-2021-23337"],
      "CWE": ["CWE-77"]
    },
    "exploit": "Proof of Concept"
  }]
}
```

`upgradePath[0] = false` means there's no top-level upgrade of `myapp` itself that resolves it; the chain shows `express-templating` doesn't get upgraded but `lodash` jumps from 4.17.20 to 4.17.21. Translation: coerce the transitive directly. From the [JavaScript appendix](../appendices/package-managers/javascript/#npm-package-lockjson):

```json
{
  "overrides": {
    "lodash": "^4.17.21"
  }
}
```

```bash
npm install
npm ls lodash    # confirm every path resolves 4.17.21
```

Reachability: drive the grep from Snyk's own `functions[]` field (Snyk's reachability-enabled output carries the affected class+function names per finding); fall back to vulnetix `x_affectedRoutines` when `functions[]` is absent for the advisory.

```bash
# Primary — Snyk-native, names come from the same JSON that flagged the vuln
SYMBOLS=$(jq -r '.vulnerabilities[]
                  | select(.id=="SNYK-JS-LODASH-1018905")
                  | .functions[]?.functionId.functionName' snyk-results.json \
            | sort -u)

# Fallback if `.functions` is empty for this advisory
[ -z "$SYMBOLS" ] && SYMBOLS=$(vulnetix vdb vuln CVE-2021-23337 --output json \
  | jq -r '.[0].containers.adp[0].x_affectedRoutines[]?
           | select(.kind=="function") | .name')

printf '%s\n' "$SYMBOLS" | xargs -I{} git grep -nE "\b{}\b|lodash/{}|require\\([\"']lodash/{}" src/
```

If `template` isn't called, Engineer Triage → `Reachability: VERIFIED_UNREACHABLE` → with `PATCHABLE_DEPLOYMENT` (caret range) → `NIGHTLY_AUTO_PATCH`. If it is called, the override still resolves the finding — `Remediation: PATCHABLE_DEPLOYMENT`, outcome: `NIGHTLY_AUTO_PATCH`.

{{< outcome type="cyclonedx" >}}
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "vulnerabilities": [{
    "id": "CVE-2021-23337",
    "source": { "name": "NVD" },
    "ratings": [{ "source": { "name": "Snyk", "url": "https://security.snyk.io/vuln/SNYK-JS-LODASH-1018905" }, "severity": "high" }],
    "affects": [{
      "ref": "pkg:npm/lodash@4.17.21",
      "versions": [
        { "version": "4.17.20", "status": "affected" },
        { "version": "4.17.21", "status": "unaffected" }
      ]
    }],
    "analysis": {
      "state": "resolved",
      "detail": "Engineer Triage: NIGHTLY_AUTO_PATCH. Inputs: reachability=VERIFIED_REACHABLE (lodash.template is called in src/render/email.js:42), remediation=PATCHABLE_DEPLOYMENT (transitive coerced via package.json overrides to ^4.17.21), mitigation=AUTOMATION (Renovate PR), priority=HIGH (Snyk severity + CVSS 7.2). Verified with npm ls lodash. Merged in MR !88."
    }
  }]
}
```
{{< /outcome >}}

## Producing an OpenVEX

For the rare case where the Snyk-flagged package isn't in your shipped artefact — a build-time tool, a dev dep, a transitive that an `npm prune --omit=dev` would strip — the subject is the repo at the scanned commit, not a packaged component.

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-snyk-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:00:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": {
      "name": "SNYK-JS-LODASH-1018905",
      "description": "Command injection in lodash.template (CVE-2021-23337). See https://security.snyk.io/vuln/SNYK-JS-LODASH-1018905"
    },
    "products": [{
      "@id": "https://github.com/yourorg/yourrepo",
      "identifiers": { "purl": "pkg:github/yourorg/yourrepo@abc1234" }
    }],
    "status": "not_affected",
    "justification": "component_not_present",
    "action_statement": "lodash@4.17.20 is in devDependencies only — used by the test-fixture generator. The production Docker image is built from a multi-stage Dockerfile in which the runtime stage runs npm ci --omit=dev. Verified with docker run --rm app:test sh -c 'ls node_modules/lodash' returning no such directory."
  }]
}
```
{{< /outcome >}}

## Capability snapshot

See the [capability matrix](../#capability-matrix) for the full comparison. Snyk OSS's row in summary:

- **Coverage**: SCA (deps), license. Container scanning + IaC available on commercial tiers. No SAST in OSS (that's [Snyk SAST / Code](../snyk-sast/)).
- **[Database quality](../#database-quality-tiers)**: CVE + GHSA + Snyk's curated DB. Between *minimal* and *sufficient* — Snyk's commercial DB adds advisories not in GHSA, but isn't OSV-equivalent.
- **[Reachability](../../appendices/reachability-deep-dive/)**: **[Tier 1](../../appendices/reachability-deep-dive/#tier-1)** by default. **[Tier 2 partial](../../appendices/reachability-deep-dive/#tier-2)** via the reachability-enabled Deep Test (commercial) — `vulnerabilities[].functions[]` carries affected class+function names per finding.
- **Exploit maturity**: string label only (`Mature` / `Proof of Concept` / `No Known Exploit`). [EPSS](../../appendices/glossary/#epss-exploit-prediction-scoring-system) + KEV available in commercial tiers. No sightings or weaponisation indicators — cross-reference Vulnetix VDB.
- **[EOL](../../appendices/eol/)**: commercial-tier signal only.
- **[Supply-chain threats](../../appendices/supply-chain-threats/)**: commercial Malicious Packages advisory channel for `MAL-` coverage; no proactive typosquat detection.
- **Outputs**: JSON, [SARIF](../../appendices/sarif/) (flat). No native VEX emission or consumption.

## See also

- [Capability matrix](../#capability-matrix) — Snyk OSS's column in context.
- [Reachability deep-dive](../../appendices/reachability-deep-dive/) — what `functions[]` Deep Test gives you vs the SCA default.
- [Supply-chain threats](../../appendices/supply-chain-threats/) — what Snyk OSS detects vs requires cross-referencing.
- [EOL appendix](../../appendices/eol/) — commercial-tier feature outside of Snyk OSS free.
- [Glossary](../../appendices/glossary/).
