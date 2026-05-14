---
title: "Vulnetix Code Scanner"
description: "Unified SCA / SAST / secrets / containers / IaC scanner — emits CycloneDX 1.7 and SARIF 2.1 natively."
weight: 5
layout: single
---

## What Vulnetix does

The Vulnetix CLI is a single binary that runs five evaluators against the same source tree in one invocation: **SCA** (dependency vulnerabilities), **SAST** (300+ built-in Rego rules across 20+ languages, plus external rule packs via `--rule org/repo`), **secrets**, **containers** (Dockerfile / Containerfile), **IaC** (Terraform, Nix flakes), and **licence** compliance. It produces a CycloneDX 1.7 SBOM, a SARIF 2.1 findings report, and a state file — all in one run, in the same `.vulnetix/` directory. The CLI also embeds a vulnerability-database client (`vulnetix vdb`) for ad-hoc CVE lookups, fix suggestions, and remediation-plan generation against MITRE, NVD, CISA KEV, EPSS, OSV, GHSA, OS-distribution advisories, and 70+ other sources.

## Reading the output

Three artefacts in `.vulnetix/`:

- **`sbom.cdx.json`** — CycloneDX 1.7 SBOM. The canonical input to **CycloneDX VEX**. Each entry under `components[]` has a `purl`, `version`, `hashes[]`, and licensing metadata; `dependencies[]` carries the resolved graph (top-level → transitive). SCA findings appear as `vulnerabilities[]` entries cross-referencing component `bom-ref`s.
- **`sast.sarif`** — SARIF 2.1.0. The canonical input to **OpenVEX**. Each `runs[].results[]` entry carries `ruleId` (under the `VNX-*` namespace), `level`, `locations[].physicalLocation` (file path and line), `message`, and a CWE mapping. SAST, secrets, IaC, and Dockerfile findings all land here.
- **`memory.yaml`** — scan metadata: timestamps, finding counts, git context, scan version. Used by `--from-memory` to reconstruct a previous run without hitting the API.

## What you can act on

Every field below is greppable with `jq` against the artefact. The recipes here are the ones you'll keep reaching for during triage.

### From the SBOM (`.vulnetix/sbom.cdx.json`)

- `components[].purl` — the canonical identity of a component. Use this as `affects[].ref` in CycloneDX VEX.
- `components[].version`, `components[].hashes[]` — for pinning and integrity.
- `dependencies[]` — the resolved dependency graph as `{ref, dependsOn[]}` records. Walk it backwards to find the top-level dep that pulled in a transitive.
- `vulnerabilities[]` (when present inline) — Vulnetix-resolved advisory metadata: `id`, `source`, `ratings[]`, `affects[]`, `analysis`.

```bash
# List every component as {purl, version, name}
jq '.components[] | {purl, version, name}' .vulnetix/sbom.cdx.json

# Find one specific component by name
jq '.components[] | select(.name == "log4j-core")' .vulnetix/sbom.cdx.json

# Find every component matching a PURL prefix (e.g. all npm packages)
jq '.components[] | select(.purl | startswith("pkg:npm/")) | .purl' .vulnetix/sbom.cdx.json

# Walk the dep graph forward — what does X depend on?
jq --arg ref "log4j-core@2.14.1" \
   '.dependencies[] | select(.ref == $ref) | .dependsOn' \
   .vulnetix/sbom.cdx.json

# Walk the dep graph BACKWARD — what pulled X in? (the triage query)
jq --arg target "log4j-core@2.14.1" \
   '.dependencies[] | select(.dependsOn | index($target)) | .ref' \
   .vulnetix/sbom.cdx.json

# List every vulnerability with its severity and the PURLs it affects
jq '.vulnerabilities[] | {
      id,
      severity: .ratings[0].severity,
      affects: [.affects[].ref]
    }' .vulnetix/sbom.cdx.json

# Filter to critical only
jq '.vulnerabilities[] | select(.ratings[]?.severity == "critical")' \
   .vulnetix/sbom.cdx.json

# All PURLs affected by one specific CVE
jq --arg cve "CVE-2021-44228" \
   '.vulnerabilities[] | select(.id == $cve) | .affects[].ref' \
   .vulnetix/sbom.cdx.json
```

### From the SARIF (`.vulnetix/sast.sarif`)

- `runs[].results[].ruleId` — the `VNX-<lang>-<n>` identifier. The same ID resolves on [docs.cli.vulnetix.com](https://docs.cli.vulnetix.com/docs/sast-rules/) — the rule page is the source of truth for bad pattern, good pattern, and remediation.
- `runs[].results[].locations[].physicalLocation.artifactLocation.uri` + `region.startLine` — where in source.
- `runs[].results[].properties.cwe` — for cross-referencing classifications.

```bash
# Every finding flattened to {ruleId, level, file, line, message}
jq '.runs[].results[] | {
      ruleId,
      level,
      file: .locations[0].physicalLocation.artifactLocation.uri,
      line: .locations[0].physicalLocation.region.startLine,
      message: .message.text
    }' .vulnetix/sast.sarif

# Count findings per rule
jq '[.runs[].results[].ruleId]
    | group_by(.)
    | map({rule: .[0], count: length})
    | sort_by(-.count)' .vulnetix/sast.sarif

# Filter to one rule family (secrets, IaC, containers, language-specific)
jq '.runs[].results[]
    | select(.ruleId | startswith("VNX-SEC-"))' .vulnetix/sast.sarif

# Find a specific rule's findings
jq '.runs[].results[]
    | select(.ruleId == "VNX-JAVA-001")' .vulnetix/sast.sarif

# Pull CWE classification per finding
jq '.runs[].results[] | {
      ruleId,
      cwe: (.properties.cwe // [])
    }' .vulnetix/sast.sarif
```

## Decision tree

Vulnetix emits both an SBOM and SARIF in the same run, so the decision splits along the artefact line.

{{< decision >}}
For SCA findings (sourced from `sbom.cdx.json`):
  → CycloneDX VEX entry referencing the PURL from the SBOM

For SAST / secrets / IaC / Dockerfile findings (sourced from `sast.sarif`):
  → OpenVEX statement, subject is the repo at the scanned commit

Need a WAF / IPS / SIEM mitigation rather than a code fix?
  Vulnetix itself can supply the rule:
    vulnetix vdb traffic-filters <CVE-ID>   # Snort / Suricata IPS signatures per CVE
    vulnetix vdb snort-rules get <CVE-ID>   # idem, richer filtering on classtype / port / content
    vulnetix vdb nuclei get <CVE-ID>        # Nuclei templates for exploit verification
    vulnetix vdb iocs <CVE-ID>              # IOC pivots (IPs, ASNs, ATT&CK techniques)
  Then: status is `affected` with `workaround_available` and the rule reference
{{< /decision >}}

## Category guides

Each finding category has its own walkthrough — what the finding looks like, how to trace it to a root cause, the exact fix patterns, and the VEX statement to produce afterwards.

- **[SCA — dependency vulnerabilities](sca/)** — every package manager, lockfile mechanics during patching, transitive-dependency coercion, reachability analysis per language. Worked examples on Log4Shell, jsonwebtoken, and the xz-utils backdoor.
- **[SAST — static analysis](sast/)** — the `VNX-*` rule namespace, per-language worked examples (Java, Python, Node.js, Go, PHP, Ruby, C#, Rust), plus the cross-cutting `VNX-CRYPTO-*`, `VNX-JWT-*`, `VNX-LLM-*` rules.
- **[Secrets](secrets/)** — all 32 `VNX-SEC-*` rules, the five-step rotation playbook, worked examples for AWS keys, GitHub PATs, and private keys.
- **[Containers](containers/)** — all 8 `VNX-DOCKER-*` rules, plus image-layer scanning that crosses back into SCA.
- **[IaC](iac/)** — all 8 `VNX-TF-*` rules for Terraform, plus Nix flake support.
- **[Licence compliance](license/)** — the five finding types, the six-step resolution pipeline, allow-list configuration.

## CI invocation

{{< tabs >}}
{{< tab name="gitlab-ci.yml" >}}
```yaml
vulnetix:
  stage: test
  script:
    - vulnetix scan
        --output .vulnetix/sbom.cdx.json
        --output .vulnetix/sast.sarif
        --severity high
        --block-malware
  artifacts:
    paths:
      - .vulnetix/sbom.cdx.json
      - .vulnetix/sast.sarif
      - .vulnetix/memory.yaml
    expire_in: 90 days
```
{{< /tab >}}
{{< tab name="GitHub Actions" >}}
```yaml
- name: Vulnetix scan
  run: |
    vulnetix scan \
      --output .vulnetix/sbom.cdx.json \
      --output .vulnetix/sast.sarif \
      --severity high \
      --block-malware

- name: Upload scan artefacts
  uses: actions/upload-artifact@v4
  with:
    name: vulnetix
    path: .vulnetix/
    retention-days: 90
```
{{< /tab >}}
{{< tab name="local dev loop" >}}
```bash
# Validate which files would be scanned without touching the API
vulnetix scan --dry-run

# Full scan, all evaluators, quieter output
vulnetix scan --results-only

# Re-process a previous scan's SBOM without re-resolving
vulnetix scan --from-memory
```
{{< /tab >}}
{{< /tabs >}}

## Gating flags reference

Flags that turn a finding into a non-zero exit code, useful in CI to block merges.

| Flag | Behaviour |
|---|---|
| `--severity low\|medium\|high\|critical` | Exit 1 if any finding meets or exceeds the threshold |
| `--block-malware` | Exit 1 if a known malicious package is in the dependency graph |
| `--block-eol` | Exit 1 if a runtime or package is past end-of-life |
| `--block-unpinned` | Exit 1 if any direct dependency uses a version range rather than a pin |
| `--exploits poc\|active\|weaponized` | Exit 1 if any finding has exploit maturity at or above the level |
| `--version-lag N` | Exit 1 if a dependency is N or more releases behind the latest |
| `--cooldown N` | Exit 1 if a dependency was published within the last N days (mitigation for typosquats) |

## Producing a CycloneDX VEX

SCA findings tie cleanly to SBOM components, so the VEX can be embedded inside the same CycloneDX document or shipped alongside, referencing the SBOM by `serialNumber`. Example for the Log4Shell finding once it's been resolved by upgrading:

{{< outcome type="cyclonedx" >}}
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:c2b7e9c1-1a44-4f1f-bf3a-1b9e02f76d61",
  "vulnerabilities": [
    {
      "id": "CVE-2021-44228",
      "source": { "name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" },
      "ratings": [{ "source": { "name": "NVD" }, "severity": "critical", "method": "CVSSv3" }],
      "affects": [
        {
          "ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1",
          "versions": [
            { "version": "2.14.1", "status": "affected" },
            { "version": "2.17.1", "status": "unaffected" }
          ]
        }
      ],
      "analysis": {
        "state": "resolved",
        "detail": "Pinned log4j-core to 2.17.1 in pom.xml's <dependencyManagement>. Confirmed via mvn dependency:tree that no transitive still resolves a vulnerable version. See MR !128."
      }
    }
  ]
}
```
{{< /outcome >}}

## Producing an OpenVEX

For SAST, secrets, IaC, and Dockerfile findings — the SARIF entries that don't tie back to an SBOM component. Subject is the repo at a specific commit; `vulnerability.name` combines the `VNX-` rule ID with the CWE.

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-sast-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "VNX-JAVA-001",
        "description": "Command injection via Runtime.exec() — CWE-78. See https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-001/"
      },
      "products": [
        {
          "@id": "https://github.com/yourorg/yourrepo",
          "identifiers": { "purl": "pkg:github/yourorg/yourrepo@abc1234" }
        }
      ],
      "status": "fixed",
      "action_statement": "Replaced Runtime.getRuntime().exec(\"convert \" + filename + \" output.png\") with ProcessBuilder(\"convert\", filename, \"output.png\") and added an allow-list validation on filename in MR !55."
    }
  ]
}
```
{{< /outcome >}}
