---
title: "CycloneDX SBOM"
description: "A machine-readable inventory of what your build actually contains — and the foundation everything else here rests on."
weight: 10
---

## What a CycloneDX SBOM is

A Software Bill of Materials is a machine-readable inventory of every component your software actually contains — declared libraries, their transitive closure, framework packages, OS-level packages, and anything else linked or copied in at build time. CycloneDX, maintained by OWASP, is the open standard that defines the format.

A CycloneDX SBOM is a JSON or XML document that records, for each component:

- **Identity** — name, version, package URL (PURL), and ecosystem
- **Dependency relationships** — which component pulled in which
- **Hashes** — SHA-256 or SHA-512 digests that pin the entry to a specific resolved artefact
- **Licences** — SPDX licence identifiers
- **Metadata** — when, by what tool, and against what build the SBOM was generated

## Why the format matters

CycloneDX is designed to be read by tools, not humans. When the scanner that finds a vulnerability, the cyber team's tooling that asks "do we use that?", and the VEX statement you write all refer to the same component identity (PURL + hash), every link in the chain resolves without ambiguity. The alternative — name-matching across each tool's preferred dialect — produces duplicates, false negatives, and missed fixes.

## How to generate one

Generate the SBOM from your build artefact or your resolved manifest, not from a text scan of your repository. Tools that walk the resolved dependency graph produce accurate inventories; tools that guess from file names produce inventories that *look* right and aren't.

{{< tabs >}}
{{< tab name="Syft (any)" >}}
```bash
# Install syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Generate CycloneDX SBOM from a directory
syft dir:. -o cyclonedx-json > sbom.cdx.json

# Or from a container image
syft ghcr.io/yourorg/yourimage:latest -o cyclonedx-json > sbom.cdx.json
```
{{< /tab >}}
{{< tab name="npm / Node" >}}
```bash
# cyclonedx-npm reads package-lock.json or yarn.lock
npx @cyclonedx/cyclonedx-npm --output-format JSON --output-file sbom.cdx.json
```
{{< /tab >}}
{{< tab name="Python / pip" >}}
```bash
pip install cyclonedx-bom
cyclonedx-py environment --output-format JSON > sbom.cdx.json
```
{{< /tab >}}
{{< tab name="Go" >}}
```bash
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
cyclonedx-gomod app -json -output sbom.cdx.json
```
{{< /tab >}}
{{< tab name="Rust / Cargo" >}}
```bash
cargo install cyclonedx-bom
cyclonedx --format json --output sbom.cdx.json
```
{{< /tab >}}
{{< /tabs >}}

## Adding SBOM generation to CI

Generate the SBOM in the same pipeline that produces the deployed artefact, in the same step or one that uses the same resolved manifest. Anything else — a separate weekly job, a manual run on a developer's laptop — drifts from what's actually in production and stops being useful the moment dependencies change.

Store the SBOM as a build artefact on every merge to your default branch, and retain it long enough that incident responders can still reach the SBOM for a release that's been live for months.

{{< tabs >}}
{{< tab name="gitlab-ci.yml" >}}
```yaml
sbom:
  stage: build
  image: anchore/syft:latest
  script:
    - syft dir:. -o cyclonedx-json > sbom.cdx.json
  artifacts:
    paths:
      - sbom.cdx.json
    expire_in: 90 days
```
{{< /tab >}}
{{< tab name="GitHub Actions" >}}
```yaml
- name: Generate SBOM
  run: |
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
      | sh -s -- -b /usr/local/bin
    syft dir:. -o cyclonedx-json > sbom.cdx.json

- name: Upload SBOM
  uses: actions/upload-artifact@v4
  with:
    name: sbom
    path: sbom.cdx.json
    retention-days: 90
```
{{< /tab >}}
{{< /tabs >}}

## Why this matters for a developer

The shortest version: an SBOM converts a class of questions you currently answer in person into questions other people can answer themselves.

**Security teams stop interrupting you.** When a new CVE is announced, the question "do we use this?" is answered by querying the SBOM, not by filing a ticket against your team. The SBOM is the contract that lets cyber go and find their own answer without breaking your flow.

**Incident response gets faster.** When a zero-day drops at three in the morning, the on-caller queries SBOMs to identify every service that uses the affected library, in the order of seconds. Without an SBOM that question is a manual triage that takes hours.

**Compliance becomes a file you already have.** SBOMs are referenced (sometimes required) by NIST SP 800-218, EO 14028, and the EU Cyber Resilience Act. Generate them automatically in CI and the compliance artefact exists before someone asks for it. Skip them and you'll write one by hand under deadline pressure, with reduced accuracy.

**VEX statements need SBOMs.** A CycloneDX VEX document references specific SBOM components by PURL. Without a machine-readable SBOM, you can't produce a machine-readable VEX — see [VEX](../vex/).

**Licence audits become greppable.** The SBOM records the SPDX licence for every dependency. Legal can audit licence obligations from one file instead of trawling through every `package.json`, `go.mod`, and `Cargo.toml` in the repo.


## See also

- [Capability matrix](../../scanners/#capability-matrix) — which scanners emit SBOMs.
- [CycloneDX VEX](../cyclonedx-vex/) — the VEX format that references SBOM components.
- [Glossary](../glossary/).
