---
title: "Supply-chain threats beyond CVEs"
description: "Typosquatting, dependency confusion, namespace squatting, maintainer takeover, protestware, install-script abuse. CVE-shaped triage doesn't fit any of them; OpenVEX against a MAL- record does."
weight: 28
---

Most of this site assumes the threat is a CVE — a published vulnerability in a known component, with a version range and (usually) a fixed-in version. Supply-chain threats break that assumption. The package itself is hostile; there is no "fixed" version, just "remove it." The triage workflow is different, the VEX statement is different, and most scanners have weaker coverage here than they do for CVEs.

This page covers the seven flavours of supply-chain threat you'll actually encounter, the signals each scanner can and can't surface, and the OpenVEX shape that matches a malicious-package finding.

For terminology used here, see the [Glossary](glossary/).

## The seven flavours

### 1. Typosquatting

An attacker publishes a package with a name that's a near-miss of a popular one — `colors` vs `colers`, `cross-env` vs `crossenv`, `event-source-polyfill` vs `event-source-polifyll`. Developers `npm install <typo>`, the malicious package's `postinstall` script runs, attacker has shell on the dev machine and a foothold in CI.

**Detection signals**:
- Edit-distance against top-N popular packages in the ecosystem.
- Package age (days since first publish) — typosquats are usually new.
- Maintainer's other publications — a maintainer with one package, this one, days old, is suspicious.
- Download count vs the target package — a typosquat sees a tiny fraction.
- AI-malware family signatures (post-install crypto-miners, env-exfil scripts).

**Native coverage**:
- [Vulnetix](../../scanners/vulnetix/) — `typosquat-check` skill cross-references the [VDB](glossary/#vulnetix-vdb)'s AI-malware family intelligence + maintainer-health signals + name-similarity. The `dep-add-guard` skill is the pre-install gate.
- [OSV-Scanner](../../scanners/osv-scanner/) — surfaces typosquats published with `MAL-` OSV records, but no proactive name-similarity heuristic.
- Snyk — commercial "Malicious Packages" advisory channel covers known typosquats; no proactive name-similarity.
- Dependabot — surfaces some malicious-package advisories via GHSA-MAL- IDs; reactive only.
- Other tools (Grype, Semgrep, GitLab Deps, etc.) — concept-applicability only: no native typosquat detection; cross-reference Vulnetix or OSV.

### 2. Dependency confusion

Birsan-style attack: an organisation has an internal package `internal-utils` registered to their private registry. An attacker publishes a public package with the same name and a high version number. If a build is misconfigured (registry preference wrong, scope missing, fallback to public registry), the build pulls the attacker's public package instead of the private one.

**Detection signals**:
- Package name claimed by both a public registry and a private one.
- Package version mismatch (public version higher than internal's expected version).
- Unscoped package whose name resembles internal naming conventions.

**Native coverage**:
- [Vulnetix](../../scanners/vulnetix/) — `dep-add-guard` flags name-collision when adding new deps; `package-search` surfaces vulnerability counts and signals across 7 ecosystems including dual-registry presence.
- npm — `npm config get registry` returns the active registry; `.npmrc` `@yourscope:registry=` plus scoped package names is the standard mitigation. Detection of an attack-in-progress requires a custom check.
- pip — `--index-url` plus `--extra-index-url` order matters; `pip install --index-url https://internal/` ignores PyPI. Attack detection isn't native.
- Maven — `<repositories>` and `<distributionManagement>` in the POM; `mvn dependency:tree -X` shows which repo each artefact came from. Attack detection requires monitoring resolution sources.
- Other ecosystems — broadly the same: registry preference is the mitigation; attack detection isn't native to most scanners.

### 3. Namespace squatting / brandjacking

An attacker registers names like `microsoft-azure-helpers`, `aws-cli-utils`, `kubernetes-toolkit` on a public registry where the brand owner has no presence. Targets developers who assume the package is official.

**Detection signals**:
- Brand-name prefix on a package without an official-account claim.
- Publisher account that doesn't match the brand.
- Low download count for a "this should be the official one" name.

**Native coverage**:
- Vulnetix `dep-add-guard` flags brand-prefix names with low maintainer-health.
- Most other tools: no native check. Reactive — surfaces only after the package is `MAL-`-classified.

### 4. Maintainer takeover

A legitimate maintainer's account is compromised (credential phishing, abandoned npm 2FA, GitHub account theft). The attacker publishes a malicious version of a real, popular package. The xz-utils backdoor (CVE-2024-3094) was the high-profile variant where a long-game social-engineering attack established maintainer trust, then introduced the backdoor in `xz-utils@5.6.0`.

**Detection signals**:
- New maintainer account on a long-running package.
- Sudden change in commit patterns / publish cadence.
- Unsigned or out-of-band commits.
- OpenSSF Scorecard score drop.

**Native coverage**:
- Vulnetix — `package-search` surfaces maintainer-health (`scorecardScore`, account age, 2FA enrolment) + AI-malware family detection; `dep-add-guard` is the pre-add gate.
- OSV — `MAL-` records cover known takeovers (xz-utils is `MAL-2024-2879`).
- Dependabot — reactive only; surfaces `GHSA-MAL-` IDs once advisories publish.
- Snyk — commercial Malicious Packages channel.
- Most other tools: reactive only.

### 5. Protestware

A maintainer modifies a package to make a political statement — `node-ipc` deleting files on Russian/Belarusian IPs (March 2022), `peacenotwar` printing a message. Not necessarily *malicious* in the traditional sense — sometimes purely informational — but disruptive and a trust violation.

**Detection signals**:
- Geo-targeted runtime behaviour.
- Recent version bump from a long-stable package with no functional changelog rationale.
- Maintainer's public statements aligning with the behaviour.

**Native coverage**:
- Vulnetix's AI-malware family detection covers known protestware families (`node-ipc`-pattern).
- OSV `MAL-` records cover the well-publicised cases.
- Most scanners: no proactive detection; reactive via advisory.

Triage is awkward because protestware doesn't fit "malicious" but doesn't fit "safe" either. Pin to a known-good version; consider migrating to an alternative; record the decision in [OpenVEX](openvex/) with `affected` + `workaround_available` rather than `not_affected`.

### 6. Post-install / install-script abuse

`npm postinstall`, `pip setup.py install`, `composer install` scripts, NuGet `tools/install.ps1`, Maven Plugin classloader injection. Any package-manager hook that runs code on install is an execution boundary. A package that's safe to *read* may execute hostile code on `install`.

**Detection signals**:
- Package's `package.json` `scripts.postinstall` invokes anything network- or filesystem-touching.
- Python `setup.py` containing `exec` / `eval` / network calls.
- Composer `scripts` entries.
- NuGet `install.ps1` / `init.ps1` content.

**Mitigations**:
- npm: `npm ci --ignore-scripts` in CI. `npm config set ignore-scripts true` on dev machines for high-risk projects.
- pip: `pip install --no-deps` then audit; pip 22+ also supports `--no-build-isolation`.
- Sandbox the build (`docker build` with restricted egress).
- Audit `node_modules/<pkg>/package.json` `scripts` after a fresh install of a new dep.

**Native coverage**:
- Vulnetix's container/IaC scanning flags suspicious `RUN npm install` patterns without `--ignore-scripts`.
- Most scanners: no proactive detection of install-script abuse; reactive via `MAL-` advisories once the abusive package is identified.

### 7. Subresource hijack / build-asset poisoning

A non-package supply-chain attack: a build pulls a CDN-hosted script or a remote build asset (`curl https://... | sh`, GitHub Actions referencing `@v1` mutable tags). The remote is changed by the attacker; your build pulls the malicious version.

**Detection signals**:
- Build commands fetching remote scripts without integrity check.
- GitHub Actions referencing branch / mutable-tag (`@main`, `@v1`) rather than a pinned SHA.
- Docker base images on `:latest` or floating tags.

**Mitigations**:
- Pin GitHub Actions to a SHA (Dependabot can auto-pin and update).
- Use SRI (subresource integrity) for CDN-hosted scripts.
- Pin base image tags by digest, not name.

**Native coverage**:
- Vulnetix container/IaC rules flag floating-tag patterns.
- GitHub's Dependabot can auto-suggest SHA pinning for Actions.
- Most SCA tools don't see Actions or shell scripts as deps.

## Database coverage for supply-chain threats

Supply-chain threats live in the `MAL-` record space, which is a relatively recent addition to several vulnerability databases. See [database quality tiers](../../scanners/#capability-matrix) for the full feed-coverage comparison; the short version for this domain:

- **CVE/NVD only**: doesn't cover `MAL-` at all. NVD's scope is CVE-shaped vulnerabilities, not malicious packages.
- **CVE + GHSA**: GHSA-MAL- covers some takeovers and confirmed malicious packages, mostly post-incident.
- **CVE + OSV**: full `MAL-` coverage via the OSV aggregator (every published malicious-package advisory).
- **CVE + OSV + GCVE**: no scanner reaches this tier today.
- **Vulnetix VDB**: full coverage *plus* proactive signals — AI-malware family detection, maintainer-health scoring, typosquat similarity, dep-add-guard pre-publication scoring.

## Worked example — writing an OpenVEX for a MAL- record

Suppose `osv-scanner` flags `xz-utils@5.6.0` against `MAL-2024-2879`:

```json
{
  "results": [{
    "source": { "path": "Dockerfile", "type": "dockerfile" },
    "packages": [{
      "package": { "name": "xz-utils", "version": "5.6.0", "ecosystem": "Debian:12" },
      "vulnerabilities": [{
        "id": "MAL-2024-2879",
        "summary": "Backdoor in xz-utils 5.6.0 / 5.6.1",
        "aliases": ["CVE-2024-3094"],
        "affected": [{
          "package": { "ecosystem": "Debian:12", "name": "xz-utils" },
          "versions": ["5.6.0", "5.6.1"]
        }]
      }]
    }]
  }]
}
```

This isn't a CVE-shaped triage decision — the answer is always "remove it" or "downgrade to a clean version." But you still want to record the decision in a [VEX](glossary/#vex) so future scans don't re-flag it once you've moved off the affected version. OpenVEX is the cleanest format because it doesn't depend on an SBOM-resident PURL:

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-malicious-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:00:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": {
      "name": "MAL-2024-2879",
      "description": "Backdoor in xz-utils 5.6.0 / 5.6.1. Aliased to CVE-2024-3094."
    },
    "products": [{
      "@id": "pkg:deb/debian/xz-utils@5.6.0?distro=debian-12"
    }],
    "status": "fixed",
    "action_statement": "Engineer Triage: DROP_TOOLS. Container base image rebuilt off debian:12.5-slim (xz-utils 5.4.1) in MR !231. Re-scanned with osv-scanner against the new image; MAL-2024-2879 no longer fires. The vulnerable versions (5.6.0, 5.6.1) are blocked at the CI gate via vulnetix --block-malicious."
  }]
}
```
{{< /outcome >}}

Notes on the shape:
- `vulnerability.name` is the `MAL-` ID, not a CVE — the malicious-package finding's primary identifier.
- `aliases` (if recorded) include the related CVE (`CVE-2024-3094`).
- `status: "fixed"` because you removed the bad version. `not_affected` only applies if the version was never in your build.
- `action_statement` carries the [Engineer Triage](ssvc/) outcome — `DROP_TOOLS` is typical for malicious packages (an active emergency).

## VEX status mapping for supply-chain threats

| Situation | VEX `status` | Justification |
|---|---|---|
| Bad version was in your build; you removed it | `fixed` | (none — fix is recorded in `action_statement`) |
| Bad version flagged but never resolved in your lockfile (false-positive PURL match) | `not_affected` | `component_not_present` |
| Bad version is in your dep graph but your code never imports / executes the malicious module | `not_affected` | `vulnerable_code_not_in_execute_path` (rare for supply-chain — `vulnerable_code_not_present` is more often right) |
| Bad version is in your build, no fix available yet (vendor hasn't published a clean release) | `affected` + `under_investigation` or `affected` + `workaround_available` | Document the workaround (registry override, downgrade, alternative package) |

## Per-tool applicability summary

| Tool | Typosquat | Dep-confusion | Namespace-squat | Maintainer-takeover | Protestware | Install-script abuse |
|---|---|---|---|---|---|---|
| [Vulnetix](../../scanners/vulnetix/) | ✅ `typosquat-check` + AI-malware | ✅ `dep-add-guard` + `package-search` | ✅ `dep-add-guard` | ✅ Maintainer-health + `MAL-` + AI-malware | ✅ AI-malware family detection | 🟡 IaC rule on `RUN npm install` without `--ignore-scripts` |
| [OSV-Scanner](../../scanners/osv-scanner/) | 🟡 Reactive (`MAL-` after publication) | ❌ | ❌ | 🟡 Reactive | 🟡 Reactive | ❌ |
| [Snyk OSS](../../scanners/snyk-oss/) | 🟡 Commercial Malicious Packages | ❌ | ❌ | 🟡 Commercial | 🟡 Commercial | ❌ |
| [Dependabot](../../scanners/github-dependabot/) | 🟡 GHSA-MAL- reactive | ❌ | ❌ | 🟡 Reactive | 🟡 Reactive | ❌ |
| [Grype](../../scanners/grype/) | ❌ Concept only | ❌ | ❌ | 🟡 Reactive via feed | 🟡 Reactive via feed | ❌ |
| [GitLab Dependencies](../../scanners/gitlab-dependencies/) | 🟡 Reactive via feed | ❌ | ❌ | 🟡 Reactive | ❌ | ❌ |
| [Semgrep/Opengrep](../../scanners/semgrep-opengrep/) | ❌ (SAST, not SCA) | ❌ | ❌ | ❌ | ❌ | 🟡 Custom rules on `postinstall` patterns |
| [CodeQL](../../scanners/github-codeql/) | ❌ (SAST, not SCA) | ❌ | ❌ | ❌ | ❌ | ❌ |

`✅` native + proactive; `🟡` reactive (only after the advisory publishes) or commercial-tier-only; `❌` not covered.

## See also

- [VEX overview](vex/) and [OpenVEX](openvex/) — recording the decision.
- [SSVC Engineer Triage](ssvc/) — `DROP_TOOLS` is the usual outcome for active malicious-package findings.
- [Reachability deep-dive](reachability-deep-dive/) — most supply-chain findings use `vulnerable_code_not_present` (the package is removed), not reachability-based justifications.
- [Capability matrix](../../scanners/#capability-matrix) — see the supply-chain threat detection column.
- [Glossary](glossary/) — `MAL-`, typosquatting, dependency-confusion, protestware, maintainer-takeover entries.
- [OSV Schema (MAL- spec)](https://ossf.github.io/osv-schema/) — the standard the `MAL-` ID format follows.
