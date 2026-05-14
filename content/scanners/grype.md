---
title: "Grype"
description: "Anchore's vulnerability scanner — JSON / SARIF output, native OpenVEX consumption via `--vex`."
weight: 90
---

Grype matches components against several vulnerability databases (NVD, GitHub Advisory, GitLab Advisory, OS-distribution feeds — Ubuntu USN, Alpine secdb, RedHat, Amazon ALAS, Wolfi) and runs against three input types: a container image, a directory tree, or an existing SBOM. For triage work the most useful mode is the third: `grype sbom:./sbom.cdx.json` re-scans the SBOM you already trust, with no re-resolution.

The single feature that makes Grype distinct from the other SCA tools is **native OpenVEX consumption** via `--vex` — write an OpenVEX statement once, point Grype at it, and the affected finding stops appearing in every subsequent scan. The feedback loop makes Grype the tool where OpenVEX investment pays back fastest. Note the format: `--vex` reads **OpenVEX**, not CycloneDX VEX. If you also keep a CycloneDX VEX (for tools that consume that format), maintain both.

## What Grype finds in JSON

```bash
# Scan an SBOM (the recommended path for VEX-aware triage)
grype sbom:./.vulnetix/sbom.cdx.json -o json > grype.json

# Or scan an image directly
grype ghcr.io/yourorg/myapp:2.3.0 -o json > grype.json

# Or a directory
grype dir:. -o json > grype.json
```

Top-level shape:

```json
{
  "matches": [ /* one per finding */ ],
  "ignoredMatches": [ /* suppressed by config or --vex */ ],
  "source": { /* what was scanned */ },
  "distro": { /* OS identification, if applicable */ },
  "descriptor": { /* Grype version, DB version */ }
}
```

Per-match fields:

| Field | Purpose |
|---|---|
| `matches[].vulnerability.id` | CVE / GHSA / OS-vendor advisory ID |
| `matches[].vulnerability.severity` | `Critical` / `High` / `Medium` / `Low` / `Negligible` / `Unknown` |
| `matches[].vulnerability.fix.versions[]` | Versions that include the fix |
| `matches[].vulnerability.fix.state` | `fixed` / `not-fixed` / `wont-fix` / `unknown` |
| `matches[].artifact.name` + `.version` | The matched component |
| `matches[].artifact.purl` | The PURL — direct input to a CycloneDX VEX entry |
| `matches[].artifact.locations[]` | Where the component lives in the source (file path for filesystem scans; layer digest for images) |
| `matches[].matchDetails[]` | Why Grype thinks the match is real. `matcher` is one of `javascript-matcher`, `python-matcher`, `java-matcher`, `dpkg-matcher`, `rpm-matcher`, `apk-matcher`, `go-module-matcher`, `rust-matcher`, `ruby-gem-matcher`, `dotnet-matcher`, `stock-matcher` (CPE fallback). `type` is `exact-direct-match`, `exact-indirect-match`, or `cpe-match` |
| `matches[].vulnerability.cvss[]` | CVSS vectors (`type: "Primary"` or `"Secondary"`, plus the vector string) |
| `matches[].vulnerability.epss[]` | EPSS score per scoring date |
| `matches[].relatedVulnerabilities[]` | Cross-feed aliases — typically the NVD CVE for a GHSA-flagged finding |

The `matchDetails[].type` distinguishes `exact-direct-match` (high confidence — the PURL matches an advisory's affected range exactly) from `cpe-match` (lower confidence — the match goes through a CPE lookup, sometimes producing false positives on CPE collisions).

## Querying with jq

```bash
# Every match flattened
jq '.matches[] | {
      id: .vulnerability.id,
      severity: .vulnerability.severity,
      purl: .artifact.purl,
      fix: .vulnerability.fix.versions[0],
      matcher: .matchDetails[0].matcher
    }' grype.json

# Critical + High only — the gating triage queue
jq '.matches[]
    | select(.vulnerability.severity == "Critical" or .vulnerability.severity == "High")
    | {id: .vulnerability.id, purl: .artifact.purl}' grype.json

# Distinguish CPE matches (lower confidence) from PURL matches
jq '.matches[]
    | select(.matchDetails[0].matcher | test("cpe"))
    | {id: .vulnerability.id, purl: .artifact.purl, type: "cpe-match"}' \
   grype.json

# Group by component — which deps generate most noise?
jq '[.matches[] | {purl: .artifact.purl}]
    | group_by(.purl)
    | map({purl: .[0].purl, count: length})
    | sort_by(-.count)' grype.json

# All findings the VEX already suppresses (run with --vex first)
jq '.ignoredMatches[] | {
      id: .match.vulnerability.id,
      purl: .match.artifact.purl,
      reason: .appliedIgnoreRules[0].reason
    }' grype.json
```

## From finding to root cause

Grype is the tool where the triage workflow most rewards OpenVEX investment. The loop:

```bash
# 1. Scan with the OpenVEX file already in place
grype sbom:./.vulnetix/sbom.cdx.json \
  --vex ./.vulnetix/vex.openvex.json \
  -o json > grype.json

# 2. Findings to triage are everything NOT in ignoredMatches
jq '.matches[] | {id: .vulnerability.id, purl: .artifact.purl}' grype.json

# 3. For each, pull Vulnetix's data for Engineer Triage
ID=$(jq -r '.matches[0].vulnerability.id' grype.json)   # GHSA-* or CVE-*
vulnetix vdb vuln "$ID" --output json \
  | jq '.[0].containers.adp[0] | {
          coordinator: .x_ssvc.decision,
          exploitation: .x_exploitationMaturity.level,
          kev: .x_kev.knownRansomwareCampaignUse,
          routines: .x_affectedRoutines
        }'

# 4. Decide. If not_affected, append an OpenVEX statement; Grype will suppress
#    the finding on the next scan. The match moves to ignoredMatches[].
```

Engineer Triage inputs from Grype:

- **Reachability** — for application deps, use the language-specific tool from the [package managers appendix](../appendices/package-managers/) against the names in `x_affectedRoutines`. For OS-layer findings in an image, check whether any binary in the image links against the affected library: `find / -type f -executable | xargs ldd 2>/dev/null | grep <lib>`.
- **Remediation Option** — read `matches[].vulnerability.fix.state`. `fixed` + your version ≤ a fixed version → `PATCHABLE_DEPLOYMENT` if your manifest allows the bump. `wont-fix` → `NO_PATCH`. `not-fixed` → `PATCH_UNAVAILABLE`.
- **Mitigation Option** — typically `AUTOMATION` for app deps (rebuild with the upgrade), `INFRASTRUCTURE` for OS-layer issues you can't yet patch (WAF rule in front of the service).
- **Priority** — Grype `severity` + Vulnetix `coordinator` + `exploitation`.

See [SSVC Engineer Triage](../appendices/ssvc/) for the decision tree.

## Patching mechanics

Application-dependency findings → the [package managers appendix](../appendices/package-managers/) for the lockfile edit. OS-layer findings → rebuild the image off a newer base.

## Decision tree

{{< decision >}}
Grype scans against an SBOM (or extracts one from an image), so every finding has a PURL.

For the suppression loop:
  → OpenVEX statement referencing the PURL from .artifact.purl
    (this is what Grype's --vex consumes — NOT CycloneDX VEX)

For tools that consume CycloneDX VEX (Vulnetix, others):
  → CycloneDX VEX entry referencing the same PURL

When you append the OpenVEX statement, Grype's --vex consumes it on subsequent scans:

  grype sbom:./sbom.cdx.json --vex ./vex.openvex.json -o json

The finding moves from matches[] to ignoredMatches[] — no more triage noise.

Need a WAF / IPS / SIEM mitigation while the upgrade is in flight?
  → vulnetix vdb traffic-filters <CVE> supplies the rule;
    status is `affected` + `workaround_available` and the rule reference
{{< /decision >}}

## Worked example: CVE-2023-50387 (KeyTrap DNSSEC) on `libbind9` in a Debian-based image

Grype flags `libbind9-9@1:9.18.19-1~deb12u1` in the `ghcr.io/library/postgres:16.2` base image. The match record:

```json
{
  "matches": [{
    "vulnerability": {
      "id": "CVE-2023-50387",
      "severity": "High",
      "fix": { "state": "fixed", "versions": ["1:9.18.28-1~deb12u2"] }
    },
    "artifact": {
      "name": "libbind9-9",
      "version": "1:9.18.19-1~deb12u1",
      "purl": "pkg:deb/debian/libbind9-9@1%3A9.18.19-1~deb12u1?distro=debian-12",
      "locations": [{ "path": "/var/lib/dpkg/status" }]
    },
    "matchDetails": [{
      "matcher": "dpkg-matcher",
      "type": "exact-direct-match"
    }]
  }]
}
```

The finding is an exact-direct dpkg match (high confidence) on a Debian package. Reachability check — does anything in the image link against libbind9?

```bash
# Pull a copy of the image and inspect linkage
docker run --rm --entrypoint sh ghcr.io/library/postgres:16.2 \
  -c 'find / -type f -executable 2>/dev/null \
      | xargs -I{} sh -c "ldd {} 2>/dev/null | grep -l bind9 && echo {}"' \
  | sort -u
```

If no binary in the image links against `libbind9` (PostgreSQL doesn't use BIND's resolver; the package was installed as a dpkg dependency of something that doesn't actually exercise the vulnerable code), `Reachability: VERIFIED_UNREACHABLE` is honest. Engineer Triage: `Remediation: PATCHABLE_DEPLOYMENT` (next base-image bump picks up the fix), `Mitigation: AUTOMATION`, `Priority: HIGH` (CVSS 7.5) — outcome `NIGHTLY_AUTO_PATCH`.

Write the OpenVEX statement (this is what Grype's `--vex` reads). From the next scan onward, Grype suppresses this finding:

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-grype-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:00:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": { "name": "CVE-2023-50387" },
    "products": [{
      "@id": "pkg:deb/debian/libbind9-9@1%3A9.18.19-1~deb12u1?distro=debian-12"
    }],
    "status": "not_affected",
    "justification": "vulnerable_code_not_in_execute_path",
    "action_statement": "Engineer Triage: BACKLOG (escalated to NIGHTLY_AUTO_PATCH at next base-image bump). libbind9-9 is in the postgres:16.2 base image as a transitive dpkg dependency but no binary in the image links against it — verified by walking /var/lib/dpkg/info/*.list for files, then ldd against every executable, no result matched libbind9. Will pick up the fix automatically when the base image is bumped past 1:9.18.28."
  }]
}
```
{{< /outcome >}}

Confirm on the next scan:

```bash
grype sbom:./.vulnetix/sbom.cdx.json --vex ./vex.openvex.json -o json \
  | jq '.ignoredMatches[]
        | select(.match.vulnerability.id == "CVE-2023-50387")
        | { id: .match.vulnerability.id, rules: .appliedIgnoreRules }'
# → returns the entry, with appliedIgnoreRules[].vex-status = "not_affected"
```

If you also need a CycloneDX VEX entry (for other tools in your pipeline that consume that format — Vulnetix's vdb workflow, audit consumers), maintain it in parallel:

{{< outcome type="cyclonedx" >}}
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "vulnerabilities": [{
    "id": "CVE-2023-50387",
    "source": { "name": "NVD" },
    "affects": [{
      "ref": "pkg:deb/debian/libbind9-9@1%3A9.18.19-1~deb12u1?distro=debian-12",
      "versions": [{ "version": "1:9.18.19-1~deb12u1", "status": "affected" }]
    }],
    "analysis": {
      "state": "not_affected",
      "justification": "code_not_reachable",
      "detail": "Engineer Triage: BACKLOG. Mirrors the OpenVEX statement at vex.openvex.json — Grype consumes the OpenVEX form."
    }
  }]
}
```
{{< /outcome >}}

## Producing an OpenVEX

For Dockerfile-pattern findings (Grype doesn't emit these — they come from Vulnetix or hadolint), OpenVEX would apply. For Grype's package-level matches, CycloneDX VEX is the right format because every match has a PURL.

The exception: if Grype is scanning a binary directory (`grype dir:./build/`) and the matched component lacks a manifest-derived PURL (rare — usually a CPE fallback match), use OpenVEX with the binary path as the subject identifier.
