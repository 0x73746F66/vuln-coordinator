---
title: "Licence — compliance findings"
description: "Triaging unknown / deprecated / copyleft / conflict / not-in-allowlist findings: the six-step resolution pipeline, the five finding types, allow-list configuration."
weight: 60
---

Licence compliance isn't a security finding in the CVE sense, but it sits in the same triage flow and produces the same VEX statements. The Vulnetix licence evaluator gives you a structured way to know what's in your dependency graph, what licences they're under, and which of those licences you can or can't live with given your distribution model.

## What the licence evaluator finds

Findings merge into `.vulnetix/sbom.cdx.json` under the `vulnerabilities[]` array, with `source.name: "vulnetix-license-analyzer"` distinguishing them from CVE findings.

```bash
# Every licence finding
jq '.vulnerabilities[]
    | select(.source.name == "vulnetix-license-analyzer")' \
   .vulnetix/sbom.cdx.json

# Group by finding type (unknown / deprecated / copyleft / conflict / not-in-allowlist)
jq '[.vulnerabilities[]
     | select(.source.name == "vulnetix-license-analyzer")
     | .id]
    | group_by(.)
    | map({finding: .[0], count: length})
    | sort_by(-.count)' .vulnetix/sbom.cdx.json

# Components flagged as copyleft-in-production with their PURLs
jq '.vulnerabilities[]
    | select(.source.name == "vulnetix-license-analyzer")
    | select(.id == "copyleft-in-production")
    | {id, affects: [.affects[].ref]}' .vulnetix/sbom.cdx.json

# Components with no detected licence
jq '.components[]
    | select(.licenses == null or (.licenses | length == 0))
    | {purl, name, version}' .vulnetix/sbom.cdx.json

# Licence distribution across the dependency graph
jq '[.components[]
     | .licenses[]?.license.id // .licenses[]?.expression // "unknown"]
    | group_by(.)
    | map({licence: .[0], count: length})
    | sort_by(-.count)' .vulnetix/sbom.cdx.json
```

Five finding types:

| Finding | Severity | Trigger |
|---|---|---|
| `unknown-license` | Medium | No licence detected after the full resolution pipeline |
| `deprecated-license` | Low | SPDX-deprecated identifier (e.g. `GPL-2.0` instead of `GPL-2.0-only`) |
| `copyleft-in-production` | High | Strong-copyleft licence on a runtime-scope dep |
| `license-conflict` | Critical / High | Incompatible licences in the same product (e.g. GPL-3.0 + proprietary) |
| `not-in-allowlist` | High | Licence isn't in your configured `--allow` list |

Components fall into five categories that determine compatibility:

| Category | Examples | Default disposition |
|---|---|---|
| Permissive | MIT, Apache-2.0, BSD-2/3-Clause, ISC | Allowed everywhere |
| Weak copyleft | LGPL-3.0-only, MPL-2.0, EPL-2.0 | File-level copyleft; usable in proprietary if linked dynamically |
| Strong copyleft | GPL-3.0-only, AGPL-3.0-only | Forces the combined work to be released under the same terms |
| Proprietary | BUSL-1.1, PolyForm-Noncommercial | Per-licence terms; usually time-limited or use-restricted |
| Public domain | CC0-1.0, Unlicense | Allowed everywhere; sometimes legally awkward in jurisdictions that don't recognise public domain |

## The six-step resolution pipeline

Quoting from the [Vulnetix docs](https://docs.cli.vulnetix.com/docs/cli-reference/license/), licences are resolved through six sequential sources, each processed once per package:

1. **Manifest files** — license fields in `package.json`, `Cargo.toml`, `pyproject.toml`, `composer.json`, etc.
2. **Filesystem** — `LICENSE` / `LICENCE` / `COPYING` files in the Go module cache, classified by text content.
3. **Container / IaC** — OCI image labels, Dockerfile metadata, Terraform Registry.
4. **Embedded database** — Vulnetix's curated mapping for popular packages.
5. **deps.dev** — Google's Open Source Insights API for package version metadata.
6. **GitHub** — repository licence via `gh` CLI or REST API.

If all six come up empty, you get an `unknown-license` finding. The single most common cause is a package that publishes without an SPDX identifier in its manifest — typically resolvable upstream.

## From finding to root cause — per finding type

### `unknown-license`

The licence might be present but unstructured, or it might genuinely be missing. Three actions in priority order:

1. **Check the repo manually.** Search for `LICENSE` / `LICENCE` / `COPYING` / `README` at the source. The licence is usually there in text form even when the manifest field is missing.
2. **Open a PR upstream** adding an SPDX identifier to the manifest. One PR benefits everyone who depends on the package. This is the highest-leverage fix in licence compliance.
3. **Override locally** in `.vulnetix/license-allow.yaml` if upstream is unresponsive. Use a sparingly-applied override; better still: pin the package's version so the resolved licence doesn't drift later.

### `deprecated-license`

SPDX retires identifiers occasionally to distinguish between versions (`GPL-2.0` → `GPL-2.0-only` vs `GPL-2.0-or-later`). The finding is informational — the licence is still valid, but the metadata is unclear. Action: notify the maintainer to update; mark `not_affected` in VEX with justification noting the legal effect is unchanged.

### `copyleft-in-production`

A strong-copyleft licence (GPL, AGPL) on a runtime dep means your distributed product inherits the same licence terms — anyone you ship to has the right to the corresponding source and to relicense their modifications under the same terms.

Three actions:

1. **Replace** with a permissive alternative. The most common case — find an MIT/Apache-2.0 equivalent.
2. **Accept and comply** — publish source, embed the licence text in the distribution, honour the rights you've granted recipients. For a SaaS product (where the distribution boundary is "you don't ship binaries") this is sometimes invisible to customers.
3. **Restructure** — move the copyleft dep behind a service boundary so the network call is the distribution edge.

AGPL is the strictest of the three: it considers network use as distribution, so accepting it without publishing source isn't an option.

### `license-conflict`

Two licences in the same artefact that aren't compatible. The classic case is GPL-3.0 + proprietary: the GPL infects the combined work, so you can't legally distribute it as proprietary.

The fix is always one of:

1. Replace the GPL dep with a permissive one.
2. Re-licence your own work under GPL.
3. Pull the GPL dep behind a process boundary that breaks the linking-counts-as-distribution argument (a separate binary invoked as a subprocess, communicating over IPC).

Option 3 is legally murky; option 1 or 2 is the safer answer.

### `not-in-allowlist`

The licence is valid but isn't in your configured allow-list. Two actions:

1. **Legal review** — add to the allow-list if approved.
2. **Replace** — if legal won't approve, find an alternative dep.

The allow-list is the policy mechanism; the finding type is the enforcement mechanism. Add licences deliberately rather than reactively.

## Allow-list configuration

Two equivalent forms — inline flag for quick tests, YAML file for the canonical config.

### Inline

```bash
vulnetix license --allow MIT,Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC
```

Useful for ad-hoc runs. Not the canonical config because it doesn't live with the repo.

### YAML file

```yaml
# .vulnetix/license-allow.yaml
licenses:
  - MIT
  - Apache-2.0
  - BSD-2-Clause
  - BSD-3-Clause
  - ISC
  - 0BSD
  - CC0-1.0
  - MPL-2.0          # weak copyleft, allowed for our use
  - LGPL-3.0-or-later
```

Commit this file. It becomes the source of truth for "what licences this product is allowed to depend on" — auditable, reviewable in MRs, versioned.

### Modes

`--mode inclusive` (default) treats the whole package set as one unit when checking for conflicts. `--mode individual` runs the conflict check per manifest — useful in monorepos where different packages have different licensing models (an internal-only service can use AGPL deps the public-facing service can't).

## Worked example: GPL-3.0 leaking into a permissive product

The scan flags `pkg:npm/some-gpl-pkg@1.2.3` with `copyleft-in-production` (High) — the package is GPL-3.0-only and pulled in transitively by a logging library.

**Reachability check first:** is the GPL package actually used in the runtime, or is it a build-time tool that doesn't ship?

```bash
# Where is it pulled in?
npm ls some-gpl-pkg

# yourapp@1.0.0
# └─┬ noisy-logger@4.1.0
#   └── some-gpl-pkg@1.2.3
```

`noisy-logger` is a runtime dep. The GPL transitive ships.

**Decision tree:**

{{< decision >}}
Can you replace some-gpl-pkg with a permissive alternative?
  ├─ Yes → replace, attest with OpenVEX status=fixed
  └─ No  ↓

Can you replace noisy-logger with a logger that doesn't pull in some-gpl-pkg?
  ├─ Yes → replace, attest with OpenVEX status=fixed
  └─ No  ↓

Can the GPL component be moved behind a process boundary (separate service, IPC)?
  ├─ Yes → restructure, attest with OpenVEX status=fixed
  └─ No  ↓

Business decision: accept the GPL terms?
  ├─ Yes → publish source, embed licence, attest with OpenVEX status=affected
  │        with inline_mitigations_already_exist
  └─ No  → product can't ship until one of the above resolves
{{< /decision >}}

**Two outcomes:**

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-license-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T14:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "copyleft-in-production",
        "description": "GPL-3.0-only transitive (some-gpl-pkg via noisy-logger) in a production-scope dependency."
      },
      "products": [{
        "@id": "https://github.com/yourorg/yourrepo",
        "identifiers": { "purl": "pkg:github/yourorg/yourrepo@abc1234" }
      }],
      "status": "fixed",
      "action_statement": "Replaced noisy-logger@4.1.0 with pino@9.2.0 (MIT-licensed). pino has no GPL transitives. Verified with npm ls and a fresh vulnetix license --mode individual run. See MR !205."
    }
  ]
}
```
{{< /outcome >}}

For the "accept and comply" path:

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-license-002.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T14:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "copyleft-in-production",
        "description": "GPL-3.0-only transitive in production scope — accepted with compliance measures."
      },
      "products": [{
        "@id": "https://github.com/yourorg/yourrepo",
        "identifiers": { "purl": "pkg:github/yourorg/yourrepo@abc1234" }
      }],
      "status": "affected",
      "justification": "inline_mitigations_already_exist",
      "action_statement": "GPL-3.0 acceptance approved by legal (LEG-2026-018). Compliance measures: (1) Corresponding source published at https://github.com/yourorg/yourrepo. (2) GPL-3.0 licence text bundled in /LICENSES/GPL-3.0.txt and surfaced in the application's About screen. (3) Build artefacts include a NOTICES file generated from the SBOM. (4) Customers given written offer of source on request. Reviewed annually."
    }
  ]
}
```
{{< /outcome >}}

## Compliance-as-VEX

A `not_affected` licence finding is uncommon but valid in one case: the flagged dep is `dev-only` and never ships. Example: a copyleft test runner in `devDependencies` that's bundled into a Docker image only at test stage.

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-license-003.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T14:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "copyleft-in-production",
        "description": "AGPL-3.0 dep flagged in production scope."
      },
      "products": [{
        "@id": "https://github.com/yourorg/yourrepo",
        "identifiers": { "purl": "pkg:github/yourorg/yourrepo@abc1234" }
      }],
      "status": "not_affected",
      "justification": "component_not_present",
      "action_statement": "The AGPL-3.0 dep is in devDependencies only — used by the test runner. The production Docker image is built from a multi-stage Dockerfile in which the runtime stage copies only built artefacts, not the test runner. Verified by inspecting the final image with docker history and confirming no AGPL files are present."
    }
  ]
}
```
{{< /outcome >}}

The justification `component_not_present` is the honest answer because the licence finding *would* apply if the test-runner shipped, but it doesn't.

## See also

- [Capability matrix](../#capability-matrix) — Vulnetix license vs Snyk / GitLab Dependencies / Grype-via-syft.
- [Glossary](../../../appendices/glossary/).
