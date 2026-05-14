---
title: "CycloneDX SBOM"
description: "What a CycloneDX SBOM is, why it exists, and why producing one is worthwhile for a developer."
weight: 10
---

## What is a CycloneDX SBOM?

A Software Bill of Materials (SBOM) is a machine-readable inventory of every component in a piece of software — libraries, frameworks, operating system packages, and their transitive dependencies. CycloneDX is an open standard (maintained by OWASP) that defines the format for that inventory.

A CycloneDX SBOM is a JSON or XML document that lists:

- **Component identity** — name, version, package URL (PURL), and ecosystem (npm, PyPI, Maven, etc.)
- **Dependency relationships** — which component depends on which
- **Hashes** — SHA-256 or SHA-512 digests that prove the listed version matches what is actually installed
- **Licences** — the licence identifier for each component
- **Metadata** — when the SBOM was generated, by what tool, and for which build artefact

## Why the format matters

CycloneDX is designed to be consumed by tools, not humans. When your scanner, your cyber team's tooling, and your attestation documents all use the same component identity (package URL + version hash), every tool in the chain can resolve "is this finding about the component in this build?" without ambiguity.

The alternative — ad-hoc package-name matching across scanner outputs — leads to duplicates, missed components, and missed fixes.

## How to generate one

Generate the SBOM from your build artefact or source tree, not from a text scan of your repository. Tools that work from the resolved dependency graph produce accurate SBOMs; tools that scan file names produce guesses.

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

Generate and store the SBOM as a build artefact on every merge to your default branch. The SBOM should be generated from the same build context that produces your deployed artefact — ideally from the same pipeline step.

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

**Cyber teams can answer their own questions.** When a new CVE is announced, your organisation's security team can check the SBOM to determine whether the affected component is present in your build — without interrupting you. Without an SBOM, that question becomes a ticket.

**Faster incident response.** If a zero-day drops at 3 am, the incident responder can query the SBOM to identify every service that uses the affected library in under a minute. Without an SBOM, the same question takes hours of manual triage.

**Compliance artefacts are generated, not written.** Many compliance frameworks (NIST SP 800-218, EU Cyber Resilience Act, Executive Order 14028) now require SBOMs. If you generate one automatically in CI, you already have it. If you don't, you will write it by hand under deadline pressure.

**VEX statements link to SBOM entries.** A CycloneDX VEX document references specific SBOM components by PURL. Without a machine-readable SBOM, you cannot produce a machine-readable VEX. See [VEX](../vex/) for detail.

**Licence compliance.** The SBOM records the licence of every dependency. Legal teams can audit licence obligations without reading every `package.json` or `go.mod` by hand.
