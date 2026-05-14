---
title: "Vulnetix Code Scanner"
description: "Unified SCA / SAST / secrets / containers / IaC scanner — emits CycloneDX 1.7 and SARIF 2.1 natively."
weight: 5
---

## What Vulnetix does

<!-- TODO: One paragraph. The Vulnetix CLI is a single binary that runs five scanner modes against the same source tree in one invocation: SCA (dependency vulns), SAST (300+ built-in `VNX-` rules across 20+ languages, plus external rule packs via `--rule org/repo`), secrets, container files, and IaC (Terraform / Kubernetes / CloudFormation). Triggered by `vulnetix scan` in CI or locally. Output goes to `.vulnetix/sbom.cdx.json` (CycloneDX 1.7), `.vulnetix/sast.sarif` (SARIF 2.1), and `.vulnetix/memory.yaml` (state). -->

## Reading the output

<!-- TODO: For VEX work, the canonical sources are the two artefact files. The SBOM (`sbom.cdx.json`) carries every resolved SCA component with PURLs and hashes — drop these straight into CycloneDX VEX `affects[].ref`. The SARIF file (`sast.sarif`) carries every SAST, secrets, and IaC finding with `ruleId`, location, and CWE — use these as the subject of OpenVEX statements. Show what one component entry and one SARIF result look like. -->

## What you can act on

<!-- TODO: From the SBOM: `components[].purl`, `components[].version`, `components[].hashes[]`, `dependencies[]` for transitive paths. From the SARIF: `runs[].results[].ruleId` (VNX-XXX for built-in, or external rule ID), `level`, `locations[].physicalLocation`, `properties.cwe`. The `.vulnetix/memory.yaml` carries scan metadata + state across runs so you can correlate findings across CI executions. -->

## Decision tree

Vulnetix emits both an SBOM and SARIF in the same run, so the decision splits cleanly along the artefact line.

{{< decision >}}
For SCA findings (sourced from `sbom.cdx.json`):
  → CycloneDX VEX entry referencing the PURL from the SBOM

For SAST / secrets / IaC findings (sourced from `sast.sarif`):
  → OpenVEX statement, subject is the repo at the scanned commit

For container findings (image layers):
  → CycloneDX VEX against the layer's PURL when present,
     OpenVEX when the component lacks a manifest

Is the risk mitigated by a WAF, IPS, or SIEM rule?
  └─ If yes, status is `affected` with `workaround_available` and the rule reference
{{< /decision >}}

## Producing a CycloneDX VEX

<!-- TODO: Vulnetix's SBOM is already CycloneDX 1.7, so the VEX block can be embedded in the same document or shipped alongside referencing the SBOM's `serialNumber`. Show a worked example with `vulnerabilities[]` entries referencing the SBOM components by PURL. -->

## Producing an OpenVEX

<!-- TODO: For everything that isn't an SBOM-component finding. Subject is the repo at the commit (or the IaC manifest path); vulnerability identifier is the VNX rule ID combined with the CWE; action_statement records the reasoning. Worked example using a real `VNX-` rule. -->

## CI invocation

<!-- TODO: Single-step shell invocation that runs all evaluators and writes both artefacts. -->

{{< tabs >}}
{{< tab name="gitlab-ci.yml" >}}
```yaml
vulnetix:
  stage: test
  script:
    - vulnetix scan --output .vulnetix/sbom.cdx.json --output .vulnetix/sast.sarif --severity high
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
      --severity high

- name: Upload scan artefacts
  uses: actions/upload-artifact@v4
  with:
    name: vulnetix
    path: .vulnetix/
    retention-days: 90
```
{{< /tab >}}
{{< /tabs >}}
