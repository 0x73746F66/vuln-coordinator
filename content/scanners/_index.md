---
title: "Scanner guides"
description: "Translate scanner output into a CycloneDX VEX or OpenVEX statement, one tool at a time."
weight: 10
---

Each scanner has its own dialect. Snyk's JSON looks nothing like Grype's, CodeQL's SARIF is its own thing, and Dependabot is a UI rather than a file you can grep. These guides cover what each scanner actually produces, which fields drive a triage decision, and how to translate the output into a VEX statement that records what you decided.

Pick the scanner that matches your pipeline. Every guide ends in the same place — either a [CycloneDX VEX](../appendices/cyclonedx-vex/) entry, when the finding ties back to an SBOM component, or an [OpenVEX](../appendices/openvex/) statement, for everything else.

For terminology used on these pages, see the [Glossary](../appendices/glossary/). If you'd rather not invoke `vulnetix vdb` and write `jq` pipelines by hand, the [AI Coding Agent](../appendices/ai-coding-agent/) plugin wraps every CLI call on this site into slash commands across Claude Code, Cursor, Windsurf, Copilot, Gemini, and a dozen other editors.

## Capability matrix

A side-by-side comparison of every scanner on this site against a common feature set, using [Vulnetix](vulnetix/) as the baseline. The matrix surfaces where each tool is stronger or weaker — feature breadth, data depth, and database coverage — so you can pick the right tool for the question you're asking (or stack two tools when no single one is enough).

**Reading the matrix**:
- ✅ Native, first-class support.
- 🟡 Partial — limited, commercial-tier-only, inferred from a weaker signal, or via a sibling tool.
- ❌ Not covered — fall back to a different tool, often via [Vulnetix VDB](../appendices/glossary/#vulnetix-vdb).
- N/A — feature doesn't apply (e.g. SAST tools have no vulnerability-database column).

**Vulnetix's drawbacks** (called out so the baseline is honest, not a sales pitch):
- **Reachability** is **semantic / intent-to-use** ([Tier 3](../appendices/reachability-deep-dive/#tier-3)), not call-graph. Where the question is genuinely a precise-call-edge question, [CodeQL](github-codeql/) and [Snyk SAST](snyk-sast/) (Tier 2 call-graph + taint) are more precise. Vulnetix's strength is catching reflection / DI / framework-wiring patterns Tier 2 misses; Vulnetix's weakness is precision on traditional code paths.
- **Container scanning** is **unpacked-layer + packages-inside the container**, not binary-image analysis. A scanner reading the binary image layout (Trivy, some commercial tools) can catch artefacts Vulnetix's layer-walk misses; conversely Vulnetix's package-level read is friendlier to per-language pivots ([Grype's Class B](grype/#class-b--language-ecosystem-finding-inside-the-container) pattern).

### Coverage

| Feature | [Dependabot](github-dependabot/) | [CodeQL](github-codeql/) | [GH Secrets](github-secrets/) | [GL Deps](gitlab-dependencies/) | [GL SAST](gitlab-dependencies/) | [GL Secrets](gitlab-secrets/) | [GL DAST](gitlab-dast/) | [Snyk OSS](snyk-oss/) | [Snyk SAST](snyk-sast/) | [Semgrep](semgrep-opengrep/) | [osv-scanner](osv-scanner/) | [Grype](grype/) | **[Vulnetix](vulnetix/)** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| SCA (deps) | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ |
| SAST (code) | ❌ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| Container | ❌ | ❌ | ❌ | 🟡 | ❌ | ❌ | ❌ | 🟡 commercial | ❌ | ❌ | ❌ | ✅ image-binary | ✅ unpacked-layer |
| IaC | ❌ | 🟡 via queries | ❌ | ❌ | ❌ | ❌ | ❌ | 🟡 commercial | ❌ | 🟡 via rules | ❌ | ❌ | ✅ |
| Secrets | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | 🟡 via rules | ❌ | 🟡 file matcher | ✅ |
| License | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | 🟡 via SBOM | ✅ |
| DAST | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

### Vulnerability intelligence depth

The richer the data behind a finding, the better the SSVC priority decision. Vulnetix's [VDB](../appendices/glossary/#vulnetix-vdb) is the baseline; other tools have narrower data.

| Feature | Dependabot | CodeQL | GH Secrets | GL Deps | GL SAST | GL Secrets | GL DAST | Snyk OSS | Snyk SAST | Semgrep | osv-scanner | Grype | **Vulnetix** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| [Database quality](../appendices/glossary/#nvd-national-vulnerability-database) (see tiers below) | CVE + GHSA | N/A | N/A | CVE + GitLab DB | N/A | N/A | N/A | CVE + GHSA + Snyk DB | N/A | N/A | CVE + OSV | CVE + GHSA + distro feeds | **Vulnetix VDB** |
| [Reachability tier](../appendices/reachability-deep-dive/) | Tier 1 | Tier 2 (call-graph + taint) | N/A | Tier 1 | Tier 1-2 (depends on analyser) | N/A | N/A | Tier 1 (Tier 2 via Deep Test 🟡) | Tier 2 (codeFlow) | Tier 1 OSS / Tier 2 Pro | Tier 1 | Tier 1 | **Tier 3 (semantic + intent-to-use)** |
| Exploit maturity | 🟡 GHSA flag only | ❌ | ❌ | 🟡 GitLab DB level | ❌ | ❌ | ❌ | 🟡 string label (`Mature`/`PoC`) | ❌ | ❌ | 🟡 OSV `database_specific` | 🟡 severity only | ✅ `ACTIVE`/`POC`/`WEAPONISED` + sightings + IOCs |
| [CISA KEV](../appendices/glossary/#kev-known-exploited-vulnerabilities) | 🟡 surfaced in some advisories | ❌ | ❌ | 🟡 | ❌ | ❌ | ❌ | 🟡 commercial | ❌ | ❌ | 🟡 via aliases | 🟡 via aliases | ✅ Native `x_kev` |
| [EPSS](../appendices/glossary/#epss-exploit-prediction-scoring-system) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 🟡 commercial | ❌ | ❌ | 🟡 from feeds | 🟡 from feeds | ✅ Native `x_epss` |
| [SSVC Coordinator](../appendices/glossary/#cisa-coordinator-decision) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Native `x_ssvc.decision` |
| [SSVC Engineer Triage](../appendices/ssvc/) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Inputs auto-surfaced |
| [`x_affectedRoutines`](../appendices/glossary/#x_affectedroutines) | ❌ | 🟡 codeFlow location | ❌ | ❌ | 🟡 codeFlow | ❌ | ❌ | 🟡 `functions[]` commercial | 🟡 codeFlow | 🟡 metavars | ❌ | ❌ | ✅ Native + AI-derived |
| [ATT&CK attack paths](../appendices/glossary/#attack) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Native `x_attackPaths` |
| [EOL / lifecycle](../appendices/eol/) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 🟡 commercial | ❌ | ❌ | ❌ | 🟡 inferred from feed | ✅ Native `lifecycleStage` |
| [Safe-harbour](../appendices/glossary/#safe-harbour) recommended version | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 🟡 `upgradePath[]` | ❌ | ❌ | ❌ | ❌ | ✅ Native `safe-version` |
| Maintainer-health / scorecard | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 🟡 commercial | ❌ | ❌ | ❌ | ❌ | ✅ Native (scorecard + account age + 2FA) |
| [Supply-chain threats](../appendices/supply-chain-threats/) (typosquat, malicious) | 🟡 GHSA-MAL- reactive | ❌ | ❌ | 🟡 reactive | ❌ | ❌ | ❌ | 🟡 commercial Malicious Packages | ❌ | ❌ | 🟡 MAL- records | 🟡 from feeds | ✅ Native + proactive typosquat-check + AI-malware |
| [Sightings / IOCs](../appendices/glossary/#sightings) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Honeypot + CrowdSec + IP/ASN/geo |
| [CWSS / multi-axis scoring](../appendices/glossary/#cwss-common-weakness-scoring-system) | 🟡 severity label only | ❌ | ❌ | 🟡 severity | ❌ | ❌ | ❌ | 🟡 `priorityScore` | 🟡 `priorityScore` | 🟡 severity | 🟡 severity | 🟡 severity | ✅ CWSS-shaped composite |

### Output & ecosystem

| Feature | Dependabot | CodeQL | GH Secrets | GL Deps | GL SAST | GL Secrets | GL DAST | Snyk OSS | Snyk SAST | Semgrep | osv-scanner | Grype | **Vulnetix** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| [SARIF](../appendices/sarif/) emit | 🟡 via API | ✅ rich (codeFlows) | 🟡 via API | ✅ via analyser | ✅ via analyser | 🟡 limited | 🟡 limited | ✅ flat | ✅ codeFlow | ✅ flat OSS / codeFlow Pro | ✅ flat | ✅ flat | ✅ rich |
| CycloneDX SBOM | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 🟡 via syft | ✅ |
| SPDX SBOM | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 🟡 via syft | ✅ |
| [CycloneDX VEX](../appendices/cyclonedx-vex/) emit | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ `vex-publish` |
| [OpenVEX](../appendices/openvex/) emit | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ `vex-publish` |
| VEX consumption (suppression loop) | ❌ | 🟡 via dismissal API | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ `--vex` (OpenVEX) | ✅ `memory.yaml` |
| Triage memory / persistence | 🟡 alert state | 🟡 alert state | 🟡 alert state | 🟡 dashboard | 🟡 dashboard | 🟡 dashboard | 🟡 dashboard | 🟡 monitor dashboard | 🟡 dashboard | ❌ | ❌ | ❌ | ✅ `.vulnetix/memory.yaml` |
| Detection rules generation | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Snort, YARA, Nuclei, Sigma |

## Database quality tiers

The matrix's "Database quality" row uses a five-tier scale. Tiers below shape what your scanner *can* detect — a scanner reading CVE/NVD only is missing half the ecosystem advisories.

| Tier | Coverage | Verdict | Tools |
|---|---|---|---|
| **CVE/NVD only** | NIST-curated CVE records, often weeks behind ecosystem advisories | **Insufficient** | (Tools at this tier are increasingly rare; most modern scanners aggregate at least GHSA.) |
| **CVE + GHSA** | + npm, pip, Maven, NuGet, RubyGems, Composer, Go via GitHub Advisory DB | **Minimal** | Dependabot |
| **CVE + OSV** | + RUSTSEC, PYSEC, GO, MAL, and broader ecosystem coverage via the [OSV aggregator](https://osv.dev/) | **Sufficient** | osv-scanner |
| **CVE + OSV + GCVE** | + Community-curated GCVE entries | **Good coverage** | **No scanner currently ships this tier.** |
| **[Vulnetix VDB](../appendices/glossary/#vulnetix-vdb)** | Every feed above plus first-party AI-derived enrichment: `x_affectedFunctions`, sightings (honeypot + CrowdSec), weaponisation indicators, [`x_attackPaths`](../appendices/glossary/#x_attackpaths), maintainer-health (OpenSSF Scorecard + account age + 2FA), AI-malware families, traffic-filters (Snort/Suricata/Nuclei) | **Full coverage** | Vulnetix |

Snyk's commercial database is a curated catalogue that augments GHSA — broader than CVE+GHSA-only, narrower than OSV. GitLab's Advisory Database is a similar shape. Both sit between "Minimal" and "Sufficient" depending on advisory.

## How to use the matrix

- **Pick a single scanner for a single feature**: read the column for that feature, take the leftmost ✅ that fits your budget.
- **Stack two scanners for breadth**: a typical stack is [Grype](grype/) (container/OS-package SCA) + [Semgrep](semgrep-opengrep/) (SAST) + [Vulnetix](vulnetix/) (enrichment + reachability + VEX). Each covers what the others can't.
- **Identify gaps your stack leaves uncovered**: any row in the matrix where your stack has no ✅ is a triage decision you're making on partial information. The fallback is usually [Vulnetix VDB](../appendices/glossary/#vulnetix-vdb) — which is why most pages on this site reference `vulnetix vdb` even when a different scanner originated the finding.

## See also

- [VEX overview](../appendices/vex/) — the format every scanner page's worked example produces.
- [SSVC Engineer Triage](../appendices/ssvc/) — the decision framework that consumes the scanner's data depth.
- [Reachability deep-dive](../appendices/reachability-deep-dive/) — the three-tier model the Reachability row above is graded against.
- [SARIF appendix](../appendices/sarif/) — the format the SARIF row's dialects are compared against.
- [Supply-chain threats](../appendices/supply-chain-threats/) — what the supply-chain row's tools can and can't detect.
- [EOL appendix](../appendices/eol/) — what the EOL row's tools can and can't detect.
- [Glossary](../appendices/glossary/) — definitions for every term used in the matrix.
