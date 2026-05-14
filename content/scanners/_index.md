---
title: "Scanner guides"
description: "Translate scanner output into a CycloneDX VEX or OpenVEX statement, one tool at a time."
weight: 10
---

Each scanner has its own dialect. Snyk's JSON looks nothing like Grype's, CodeQL's SARIF is its own thing, and Dependabot is a UI rather than a file you can grep. These guides cover what each scanner actually produces, which fields drive a triage decision, and how to translate the output into a VEX statement that records what you decided.

Pick the scanner that matches your pipeline. Every guide ends in the same place — either a [CycloneDX VEX](../appendices/cyclonedx-vex/) entry, when the finding ties back to an SBOM component, or an [OpenVEX](../appendices/openvex/) statement, for everything else.

For terminology used on these pages, see the [Glossary](../appendices/glossary/). If you'd rather not invoke `vulnetix vdb` and write `jq` pipelines by hand, the [AI Coding Agent](../appendices/ai-coding-agent/) plugin wraps every CLI call on this site into slash commands across Claude Code, Cursor, Windsurf, Copilot, Gemini, and a dozen other editors.

## Capability matrix

A side-by-side qualitative comparison of every scanner on this site, using [Vulnetix](vulnetix/) as the baseline. The matrix is **exhaustive** — every distinguishing capability gets a row, even ones only one tool has, because the gap is the comparison.

**Reading the cells**: cells carry short prose rather than ticks. "Native — `x_kev.knownRansomwareCampaignUse` + `x_kev.dueDate`" tells you *how* a capability is implemented; "String label only (`Mature`/`PoC`)" tells you *what's missing*. Where a fallback exists, the cell names it (e.g. "Not native — cross-reference `vulnetix:eol-check` or [endoflife.date](https://endoflife.date/)"). `N/A` means the capability doesn't apply (a SAST tool has no vulnerability-DB row).

**Vulnetix's drawbacks** (called out so the baseline is honest, not a sales pitch):

- **Reachability is semantic / intent-to-use** ([Tier 3](../appendices/reachability-deep-dive/#tier-3)), *not* call-graph. [CodeQL](github-codeql/) and [Snyk SAST](snyk-sast/) (Tier 2 call-graph + taint) are more precise on traditional call-edge questions. Vulnetix's strength is catching reflection / DI / framework-wiring patterns Tier 2 misses; Vulnetix's weakness is precision on traditional code paths. The Reachability table below puts both sides of this contrast in one place.
- **Container scanning** reads the **OCI manifest's package list** or an **unpacked filesystem** — *not* the binary image, *not* a runtime probe. [Grype](grype/) and Trivy read the image-binary directly via the OCI layers. Snyk Container (commercial) does likewise. The Container scanning depth table shows where each model wins and loses.

Column header pattern is identical across every section so you can pick a tool's column and read straight down:

`| Capability | Dependabot | CodeQL | GH Secrets | GL Deps | GL SAST | GL Secrets | GL DAST | Snyk OSS | Snyk SAST | Semgrep | osv-scanner | Grype | Vulnetix |`

### 1. Coverage

What scope each scanner covers — the broad question of "can this tool see findings of class X at all?"

| Capability | [Dependabot](github-dependabot/) | [CodeQL](github-codeql/) | [GH Secrets](github-secrets/) | [GL Deps](gitlab-dependencies/) | [GL SAST](gitlab-dependencies/) | [GL Secrets](gitlab-secrets/) | [GL DAST](gitlab-dast/) | [Snyk OSS](snyk-oss/) | [Snyk SAST](snyk-sast/) | [Semgrep](semgrep-opengrep/) | [osv-scanner](osv-scanner/) | [Grype](grype/) | **[Vulnetix](vulnetix/)** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| SCA (deps) | Native — lockfile + GHSA matching | N/A | N/A | Native — gemnasium analyser | N/A | N/A | N/A | Native — flagship product | N/A | N/A | Native — lockfile + OSV API | Native — SBOM + container OS packages | **Native — every ecosystem + VDB enrichment** |
| SAST (code) | N/A | Native — flagship; call-graph + taint | N/A | N/A | Native — per-language analysers (Semgrep + bandit + gosec) | N/A | N/A | N/A | Native — Snyk Code; taint flow | Native — pattern-match (OSS) / taint (Pro) | N/A | N/A | **Native — pattern-match + semantic** |
| Container scanning | Not native | Not native | Not native | Adjacent product (GitLab Container Scanning, Trivy-backed) | Not native | Not native | Not native | Commercial tier — Snyk Container | Not native | Not native | Not native | **Native — image-binary via syft** | **_Native — OCI-manifest packages OR unpacked filesystem; not image-binary, not runtime_** |
| Container scan model | — | — | — | Image-binary | — | — | — | Image-binary | — | — | — | **Image-binary** (OCI layer extraction, then filesystem walk) | **Unpacked-layer / OCI-manifest** (reads the manifest's package list, or operates on a pre-extracted filesystem; cannot scan a binary OCI image directly) |
| IaC scanning | Not native | Custom queries possible | Not native | Adjacent product (GitLab SAST-IaC) | Not native | Not native | Not native | Commercial tier — Snyk IaC | Not native | Via community rule packs | Not native | Not native | **Native — Terraform / OpenTofu / Nix / k8s / Helm rules** |
| Secrets scanning | Not native | Not native | Native — GitHub Secret Scanning | Not native | Not native | Native — gitleaks analyser | Not native | Not native | Not native | Via community rule packs | Not native | File-pattern matcher (CPE-style) | **Native — AWS / GitHub / Slack / Stripe / generic entropy** |
| License compliance | Not native | Not native | Not native | Native — SPDX licence per dep | Not native | Not native | Not native | Native — license advisor | Not native | Not native | Not native | Indirect — via syft SBOM | **Native — copyleft conflict + allowlist + 6-step pipeline** |
| DAST | Not native | Not native | Not native | Not native | Not native | Not native | **Native — ZAP-based** | Not native | Not native | Not native | Not native | Not native | Not native — DAST is out of scope for the platform |
| Dockerfile static analysis | Not native | Custom queries | Not native | Via GitLab Container Scanning | Not native | Not native | Not native | Commercial | Not native | Via community rule packs (hadolint-style) | Not native | Not native | **Native — 8 Dockerfile rules (`VNX-DOCKER-001..008`)** |
| Mobile (APK / IPA) | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Commercial — Snyk Mobile (limited) | Not native | Via Mobile rule packs | Not native | Indirect — APK/IPA file-walk | Not native (out of scope) |
| API security (live) | Not native | Not native | Not native | Not native | Not native | Not native | Partial — via DAST | Not native | Not native | Not native | Not native | Not native | Not native (out of scope) |
| Kubernetes / cloud-config | Not native | Custom queries | Not native | Via GitLab IaC | Not native | Not native | Not native | Commercial — Snyk Cloud | Not native | Via Kubernetes rule packs | Not native | Not native | **Native — k8s manifests + Nix flakes via IaC** |

### 2. Database & feed quality

The breadth of vulnerability data the scanner consumes shapes everything downstream — see the [database quality tiers](#database-quality-tiers) section for the five-tier scale.

| Capability | Dependabot | CodeQL | GH Secrets | GL Deps | GL SAST | GL Secrets | GL DAST | Snyk OSS | Snyk SAST | Semgrep | osv-scanner | Grype | **Vulnetix** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Primary feed | GHSA + curated GitHub Advisory DB | N/A (first-party query packs) | N/A (signatures) | GitLab Advisory DB (GHSA + curated entries) | N/A (rule packs) | N/A (signatures) | N/A (runtime probes) | Snyk Vulnerability DB (curated, augments GHSA) | N/A (first-party rules) | N/A (rule packs) | OSV.dev aggregator | NVD + GHSA + GitLab DB + distro feeds (USN/Alpine/RedHat/ALAS/Wolfi) | **Vulnetix VDB — every above feed + first-party enrichment** |
| [Database quality tier](#database-quality-tiers) | **CVE + GHSA** (minimal) | N/A | N/A | CVE + GitLab DB (minimal-to-sufficient) | N/A | N/A | N/A | CVE + GHSA + Snyk DB (minimal-plus) | N/A | N/A | **CVE + OSV** (sufficient) | CVE + GHSA + distro feeds (sufficient for OS, minimal for ecosystem) | **Vulnetix VDB** (full coverage) |
| OS-distro feeds covered | — | — | — | Via container-scanning analyser | — | — | — | Commercial container | — | — | Limited (OSV doesn't aggregate distros) | **Ubuntu USN, Alpine secdb, RedHat, Amazon ALAS, Wolfi, Debian, SUSE** | **Every above + Debian LTS / ELTS, RHEL ELS, Ubuntu ESM** |
| Cross-feed aliases | GHSA + CVE | — | — | CVE + GHSA + Snyk + OSVDB | — | — | — | CVE + CWE + GHSA + OSV + Snyk | — | — | OSV `aliases[]` (every cross-reference) | NVD `relatedVulnerabilities[]` | **Vulnetix `aliases[]` — 78+ ID formats incl. RHSA, MSCVE, EUVD, ZDI, KEV** |
| Update cadence | Real-time (GHSA push) | Standard query pack release | Real-time | Daily | Weekly rule-pack | Real-time | N/A | Daily | Weekly | Weekly | Daily (OSV API) | Daily | **Hourly enrichment cycles + real-time KEV / honeypot ingestion** |
| First-party enrichment | None — passthrough of GHSA | Query-pack metadata | None | Minimal — severity blend | Rule-pack metadata | None | None | Snyk-curated severity / `priorityScore` / `upgradePath[]` | Snyk-curated rule properties | Rule-pack metadata | None — verbatim OSV | None — verbatim feed | **`x_threatExposure`, `x_attackSurface`, `x_ssvc`, `x_kev`, `x_epss`, `x_exploitationMaturity`, `x_remediationTimeline`, `x_affectedRoutines`, `x_attackPaths`, `x_purls`** |

### 3. Vulnerability intelligence — risk signals

How rich is the data attached to each finding? Most of the SSVC `Priority` input comes from the rows below — a string label gives you less than an integrated multi-source signal.

| Capability | Dependabot | CodeQL | GH Secrets | GL Deps | GL SAST | GL Secrets | GL DAST | Snyk OSS | Snyk SAST | Semgrep | osv-scanner | Grype | **Vulnetix** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| CVSS v3.1 vector | Severity label (no vector) | N/A | N/A | Vector when available | N/A | N/A | N/A | Vector + score | Severity label | N/A | Via OSV `severity[]` | Via NVD `cvss[]` | **Vector + score + version-specific re-scoring** |
| CVSS v4.0 vector | Not surfaced | N/A | N/A | Not surfaced | N/A | N/A | N/A | Partial (rolling out) | Not surfaced | N/A | When OSV carries it | When NVD carries it | **Native — v3.1 + v4.0 in parallel** |
| EPSS percentile | Not surfaced | N/A | N/A | Not surfaced | N/A | N/A | N/A | Commercial tier | N/A | N/A | Per-feed when available | Per-feed when available | **Native — `x_epss.score` + `x_epss.percentile` + `x_epss.date`** |
| CISA KEV | Surfaced in some advisories | N/A | N/A | Partial — via cross-reference | N/A | N/A | N/A | Commercial tier | N/A | N/A | Via OSV aliases | Via NVD aliases | **Native — `x_kev.knownRansomwareCampaignUse`, `x_kev.dueDate`, `x_kev.requiredAction`, `x_kev.vendorProject`** |
| EU-KEV | Not surfaced | N/A | N/A | Not surfaced | N/A | N/A | N/A | Not surfaced | N/A | N/A | Not surfaced | Not surfaced | **Native — EUVD + ENISA KEV ingestion** |
| [SSVC Coordinator](../appendices/glossary/#cisa-coordinator-decision) decision | Not surfaced | N/A | N/A | Not surfaced | N/A | N/A | N/A | Not surfaced | N/A | N/A | Not surfaced | Not surfaced | **Native — `x_ssvc.decision` ∈ {`Act`, `Attend`, `Track*`, `Track`} + `x_ssvc.priority` + `x_ssvc.inputs` + `x_ssvc.methodology`** |
| [SSVC Engineer Triage](../appendices/ssvc/) inputs | Not surfaced | N/A | N/A | Not surfaced | N/A | N/A | N/A | Not surfaced | N/A | N/A | Not surfaced | Not surfaced | **Native — `Reachability`/`Remediation`/`Mitigation`/`Priority` auto-surfaced; written to `.vulnetix/memory.yaml`** |
| Exploit maturity depth | Boolean — GHSA flag only | N/A | N/A | GitLab DB severity bucket | N/A | N/A | N/A | String label (`Mature`/`Proof of Concept`/`No Known Exploit`) | N/A | N/A | OSV `database_specific.severity` bucket | Severity bucket | **Native categorical — `x_exploitationMaturity.level` ∈ {`ACTIVE`, `POC`, `WEAPONISED`, `NONE`} + sub-factors (EPSS, KEV, CESS, sightings)** |
| Weaponisation indicator | Not surfaced | N/A | N/A | Not surfaced | N/A | N/A | N/A | Not surfaced | N/A | N/A | Not surfaced | Not surfaced | **Native — Metasploit module presence + Nuclei template + autonomous-attack-tool detection** |
| Honeypot sightings | Not surfaced | N/A | N/A | Not surfaced | N/A | N/A | N/A | Not surfaced | N/A | N/A | Not surfaced | Not surfaced | **Native — `x_sightings` per CVE (1d / 7d / 30d / 90d averages)** |
| CrowdSec community sightings | Not surfaced | N/A | N/A | Not surfaced | N/A | N/A | N/A | Not surfaced | N/A | N/A | Not surfaced | Not surfaced | **Native — CrowdSec partner feed** |
| Shadowserver scan counts | Not surfaced | N/A | N/A | Not surfaced | N/A | N/A | N/A | Not surfaced | N/A | N/A | Not surfaced | Not surfaced | **Native — global-scan-volume signal** |
| IOC pivots (IPs / ASNs / geo) | Not surfaced | N/A | N/A | Not surfaced | N/A | N/A | N/A | Not surfaced | N/A | N/A | Not surfaced | Not surfaced | **Native — `vulnetix:ioc-pivot` skill returns top IPs, ASNs, geo distribution, STIX 2.1 bundle export** |
| ATT&CK technique mapping (per-CVE) | Not surfaced | N/A | N/A | Not surfaced | N/A | N/A | N/A | Not surfaced | N/A | N/A | Not surfaced | Not surfaced | **Native — `x_attackPaths[]` carries tactic → technique chain per CVE** |
| [`x_affectedRoutines`](../appendices/glossary/#x_affectedroutines) (function-level affected list) | Not surfaced | Indirect — codeFlow location | N/A | Not surfaced | Indirect — codeFlow location | N/A | N/A | `functions[]` (commercial Deep Test) | Indirect — codeFlow location | Metavar capture in rule | Not surfaced | Not surfaced | **Native — deduplicated programRoutines + programFiles + AI-derived `x_affectedFunctions`** |
| [`x_attackPaths`](../appendices/glossary/#x_attackpaths) (tactic → technique) | Not surfaced | N/A | N/A | Not surfaced | N/A | N/A | N/A | Not surfaced | N/A | N/A | Not surfaced | Not surfaced | **Native — drives detection-rule selection (Snort / Nuclei / YARA / Sigma)** |
| Multi-axis (CWSS-shaped) scoring | Severity label only | N/A | N/A | Severity label only | N/A | N/A | N/A | `priorityScore` (single composite, 0–1000) | `priorityScore` (single composite) | Severity + likelihood + impact strings | Severity label | Severity label | **CWSS composite — technical-impact + exploitability + exposure + complexity + repo-relevance, each 0–100, weighted blend** |
| AI-discovered vulnerabilities (researcher leaderboard) | Not surfaced | N/A | N/A | Not surfaced | N/A | N/A | N/A | Not surfaced | N/A | N/A | Not surfaced | Not surfaced | **Native — AI-researcher discovery feed, leaderboard, novel-CVE tracking** |
| AI-in-the-wild exploitation observations | Not surfaced | N/A | N/A | Not surfaced | N/A | N/A | N/A | Not surfaced | N/A | N/A | Not surfaced | Not surfaced | **Native — `vdb ai-in-wild`, AI-authored exploit observations** |
| Vendor-trend month-over-month deltas | Not surfaced | N/A | N/A | Not surfaced | N/A | N/A | N/A | Limited dashboards | N/A | N/A | Not surfaced | Not surfaced | **Native — `vdb vendor-trends` per vendor MoM** |
| Exploit-trend rollup | Not surfaced | N/A | N/A | Not surfaced | N/A | N/A | N/A | Limited dashboards | N/A | N/A | Not surfaced | Not surfaced | **Native — `vdb exploit-trends`** |
| CWE classification | Surfaced when in GHSA | Native — `external/cwe/...` tags | N/A | Surfaced when in feed | Native — `metadata.cwe[]` | N/A | Native — ZAP CWE mapping | Native — `identifiers.CWE[]` | Native — `properties.tags` | Native — `metadata.cwe` | Indirect — via OSV | Surfaced when in feed | **Native — `x_kev.cwes[]` + per-finding CWE + D3FEND countermeasure mapping** |

### 4. Reachability — tier and mechanism

The three-tier model from the [reachability deep-dive](../appendices/reachability-deep-dive/). The "Tier achieved" row is the headline; the rows below decompose *how* the tool gets there.

| Capability | Dependabot | CodeQL | GH Secrets | GL Deps | GL SAST | GL Secrets | GL DAST | Snyk OSS | Snyk SAST | Semgrep | osv-scanner | Grype | **Vulnetix** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| [Tier achieved](../appendices/reachability-deep-dive/) | **Tier 1** — package-level | **Tier 2** — call-graph + taint | N/A | **Tier 1** — package-level | **Tier 1–2** — depends on analyser | N/A | Runtime (orthogonal) | **Tier 1** default / **Tier 2 partial** via Deep Test (commercial) | **Tier 2** — taint codeFlow | **Tier 1** pattern-match (OSS) / **Tier 2** taint (Pro) | **Tier 1** — package-level | **Tier 1** — package-level (linkage check is Tier-1.5 manual) | **_Tier 3_ — semantic / intent-to-use; _not Tier 2 call-graph_** |
| Static call-graph (CHA / RTA / VTA / pointer) | Not native | Native — CodeQL's data-flow library builds the graph | N/A | Not native | Per-analyser (some use Semgrep flat) | N/A | N/A | `functions[]` (commercial) | Native — Snyk Code's interprocedural graph | Pro mode only | Not native | Not native | **_Not native — pair with [CodeQL](github-codeql/) or [Snyk SAST](snyk-sast/) for precise call-edge questions_** |
| Taint / dataflow ([codeFlow](../appendices/sarif/#codeflow--the-taint-trace)) | Not native | Native — `codeFlows[]` in SARIF | N/A | Not native | Pro / Semgrep-based analysers | N/A | N/A | Limited via `functions[]` | Native — `codeFlow` in SARIF | Pro mode — `codeFlows[]` | Not native | Not native | **Inferred from `x_affectedRoutines` + framework heuristics; no codeFlow-style trace** |
| Semantic / intent-to-use (reflection / DI / ServiceLoader / framework auto-config) | Not native | Misses by default; needs hand-written queries per framework | N/A | Not native | Not native | N/A | N/A | Not native | Not native | Not native | Not native | Not native | **Native — captures Spring auto-config, Java SPI, .NET DI, Rails autoload, plugin-system wiring that call-graph tools miss** |
| Runtime coverage integration | Not native | Not native | N/A | Not native | Not native | N/A | DAST is itself runtime evidence | Not native | Not native | Not native | Not native | Not native | Indirect — pair with JaCoCo / coverage.py / c8 + memory.yaml |

### 5. Supply-chain threat detection

Most scanners are reactive (`MAL-` records arrive after the advisory publishes). Vulnetix is the only tool below with proactive detection. See [supply-chain threats appendix](../appendices/supply-chain-threats/) for the full taxonomy.

| Capability | Dependabot | CodeQL | GH Secrets | GL Deps | GL SAST | GL Secrets | GL DAST | Snyk OSS | Snyk SAST | Semgrep | osv-scanner | Grype | **Vulnetix** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Typosquat similarity scoring | Not native | N/A | N/A | Not native | N/A | N/A | N/A | Commercial — limited | N/A | Not native | Not native | Not native | **Native — `vulnetix:typosquat-check` + edit-distance + maintainer-health blend** |
| Dependency-confusion detection | Not native | N/A | N/A | Not native | N/A | N/A | N/A | Commercial — limited | N/A | Not native | Not native | Not native | **Native — `dep-add-guard` flags dual-registry presence** |
| Namespace squatting / brandjacking | Not native | N/A | N/A | Not native | N/A | N/A | N/A | Not native | N/A | Not native | Not native | Not native | **Native — brand-prefix detection + low-maintainer-health combination** |
| Maintainer-takeover (`MAL-` records) | Reactive — `GHSA-MAL-` after publication | N/A | N/A | Reactive — via feed | N/A | N/A | N/A | Reactive — Snyk Malicious Packages (commercial) | N/A | Not native | **Native — OSV `MAL-` records first-class** | Via OSV / NVD aliases | **Native + proactive — AI-malware family signatures + maintainer-health drop detection** |
| Protestware | Reactive — `MAL-` after publication | N/A | N/A | Reactive | N/A | N/A | N/A | Reactive — commercial | N/A | Not native | Reactive — via `MAL-` | Via feed | **Native — AI-malware family detection (`node-ipc`-pattern, geo-targeted behaviour signals)** |
| Post-install / build-script abuse | Not native | N/A | N/A | Not native | N/A | N/A | N/A | Not native | N/A | Via custom rule packs | Not native | Not native | **Native — IaC rule on `RUN npm install` without `--ignore-scripts`; `dep-add-guard` flags suspect scripts** |
| AI-malware family signatures | Not native | N/A | N/A | Not native | N/A | N/A | N/A | Not native | N/A | Not native | Not native | Not native | **Native — `vdb ai-malware` — multi-family classifier on package contents** |
| AI-authored malware detection | Not native | N/A | N/A | Not native | N/A | N/A | N/A | Not native | N/A | Not native | Not native | Not native | **Native — `vdb ai-discoveries` and `ai-in-wild` ingestion** |
| Subresource hijack / build-asset poisoning | Not native | Custom queries possible | N/A | Not native | N/A | N/A | N/A | Not native | N/A | Via custom rule packs | Not native | Not native | **Native — IaC rules on floating-tag `FROM` + mutable Action SHAs** |

### 6. Maintainer health & provenance

Per-package signals about who maintains it. Most scanners surface zero of these; Vulnetix surfaces them as inputs to `dep-add-guard`'s composite ALLOW/WARN/BLOCK verdict.

| Capability | Dependabot | CodeQL | GH Secrets | GL Deps | GL SAST | GL Secrets | GL DAST | Snyk OSS | Snyk SAST | Semgrep | osv-scanner | Grype | **Vulnetix** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| OpenSSF Scorecard score | Not surfaced | N/A | N/A | Not surfaced | N/A | N/A | N/A | Commercial — limited | N/A | N/A | Not surfaced | Not surfaced | **Native — `vdb scorecard` per dep** |
| Account age (maintainer's registry account) | Not surfaced | N/A | N/A | Not surfaced | N/A | N/A | N/A | Not surfaced | N/A | N/A | Not surfaced | Not surfaced | **Native — sub-input to `package-search` + `dep-add-guard`** |
| 2FA enrolment check | Not surfaced | N/A | N/A | Not surfaced | N/A | N/A | N/A | Not surfaced | N/A | N/A | Not surfaced | Not surfaced | **Native — registry-2FA verification per maintainer** |
| Prior-commits / publish-history signal | Not surfaced | N/A | N/A | Not surfaced | N/A | N/A | N/A | Not surfaced | N/A | N/A | Not surfaced | Not surfaced | **Native — abandonment / cadence-anomaly detection** |
| Cosign verification of upstream artefact | Not surfaced | N/A | N/A | Not surfaced | N/A | N/A | N/A | Not surfaced | N/A | N/A | Not surfaced | Not surfaced | **Native — verifies registry-signed packages where signing exists** |
| Pre-add risk gate (composite ALLOW / WARN / BLOCK) | Auto-MR is a *post*-add gate | N/A | N/A | Not native | N/A | N/A | N/A | Not native | N/A | N/A | Not native | Not native | **Native — `vulnetix:dep-add-guard` composes vuln history + AI-malware + license + EOL + maintainer-health + version-lag into one verdict** |

### 7. Lifecycle / EOL

See the [EOL appendix](../appendices/eol/) for the SSVC mapping (EOL → `NO_PATCH` → `SPIKE_EFFORT` migration).

| Capability | Dependabot | CodeQL | GH Secrets | GL Deps | GL SAST | GL Secrets | GL DAST | Snyk OSS | Snyk SAST | Semgrep | osv-scanner | Grype | **Vulnetix** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Per-dep EOL | Not native — cross-reference [endoflife.date](https://endoflife.date/) | N/A | N/A | Not native | N/A | N/A | N/A | Commercial tier signal | N/A | N/A | Not native | Inferred — "no fix in feed" is a weak signal | **Native — `lifecycleStage` per dep in VDB; `vulnetix:eol-check` skill** |
| Per-runtime EOL (Python / Node / Java / Go / .NET) | Not native | N/A | N/A | Not native | N/A | N/A | N/A | Commercial | N/A | N/A | Not native | Not native | **Native — runtime EOL data + `--block-eol` CI gate** |
| Per-container-base-image EOL | Not native | N/A | N/A | Indirect — via container scanner | N/A | N/A | N/A | Commercial — Snyk Container | N/A | N/A | Not native | Inferred — distro feed signals when patches stop | **Native — base-image lifecycle + migration recommendation (UBI / Chainguard / distroless)** |
| Safe-harbour recommended version | Implicit in auto-MR target | N/A | N/A | Implicit in `solution` | N/A | N/A | N/A | `upgradePath[]` | N/A | N/A | Not native | Not native | **Native — `vulnetix:safe-version` returns CVE-free newest version honouring `--max-major-bump`** |
| `--max-major-bump` policy | Not native | N/A | N/A | Not native | N/A | N/A | N/A | Not native | N/A | N/A | Not native | Not native | **Native — bump-budget enforcement** |

### 8. Patching & remediation depth

Auto-MR generation is table-stakes for SCA tools; everything below is the depth beyond it.

| Capability | Dependabot | CodeQL | GH Secrets | GL Deps | GL SAST | GL Secrets | GL DAST | Snyk OSS | Snyk SAST | Semgrep | osv-scanner | Grype | **Vulnetix** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Auto-MR / Auto-PR | **Native — flagship feature** | Not native (SAST findings don't auto-PR) | Push-protection (blocks the secret) | GitLab Auto-Merge MRs | Not native | Not native | Not native | Commercial — Snyk Fix PRs | Not native | Not native | Not native | Not native | **Native — `/vulnetix:fix` + sub-agent `dep-upgrade-orchestrator`** |
| Upgrade-path data | `firstPatchedVersion.identifier` | N/A | N/A | `solution` free-text | N/A | N/A | N/A | `upgradePath[]` with index alignment to `from[]` | N/A | N/A | OSV `affected.ranges.events.fixed` | `vulnerability.fix.versions[]` | **Native — `vdb fixes` + `vdb remediation plan` with per-registry / upstream / distro / workaround tracks** |
| Conflict-resolution multi-strategy | Not native (single-bump attempt) | N/A | N/A | Not native | N/A | N/A | N/A | Limited | N/A | N/A | Not native | Not native | **Native — sub-agent `safe-harbor-resolver`: single bump → override → safe-harbour inline → workaround + detection** |
| Inline-as-first-party-code (safe-harbour inline) | Not native | N/A | N/A | Not native | N/A | N/A | N/A | Not native | N/A | N/A | Not native | Not native | **Native — inline-source option in `vulnetix:fix`** |
| Workaround / mitigation recommendation | Not surfaced | N/A | N/A | Not surfaced | N/A | N/A | N/A | Commercial — partial | N/A | N/A | Not surfaced | Not surfaced | **Native — `vdb workarounds` + `vdb remediation` returns CWE-specific defensive strategies** |
| Per-package-manager verification commands | Not native | N/A | N/A | Not native | N/A | N/A | N/A | Not native | N/A | N/A | Not native | Not native | **Native — `vulnetix:remediation` emits per-ecosystem verify commands** |
| Patch path data (registry / upstream commit / distro patch) | Registry only | N/A | N/A | Registry only | N/A | N/A | N/A | Registry + commercial upstream | N/A | N/A | Registry + distro | Distro (OS layer) + registry | **All three — registry + upstream commit URLs + distro patch metadata** |

### 9. Container scanning depth

Where the two scanning models matter most. Vulnetix's drawback is explicit on the "Image-binary scanning" row.

| Capability | Dependabot | CodeQL | GH Secrets | GL Deps | GL SAST | GL Secrets | GL DAST | Snyk OSS | Snyk SAST | Semgrep | osv-scanner | Grype | **Vulnetix** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Image-binary scanning (extract OCI layers, walk filesystem) | Not native | Not native | Not native | Via separate GitLab Container Scanning analyser | Not native | Not native | Not native | Commercial — Snyk Container | Not native | Not native | Not native | **Native — flagship via syft** | **_Not native — reads OCI manifest's package list, or operates on a pre-extracted filesystem; pair with [Grype](grype/) for image-binary scans_** |
| Unpacked-layer scanning (filesystem walk on extracted image) | Not native | Not native | Not native | Indirect | Not native | Not native | Not native | Commercial — partial | Not native | Not native | Indirect — `dir:` mode | Native — `dir:` mode | **Native — primary container model** |
| Runtime scanning (live container monitoring) | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Commercial — Snyk Runtime | Not native | Not native | Not native | Not native | Not native — orthogonal domain (Falco / Tetragon territory) |
| OCI-manifest package list (read manifest's content list, not its layers) | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | **Native — Vulnetix's primary container ingest path** |
| Multi-stage build awareness | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Commercial — partial | Not native | Not native | Not native | **Native — runtime-image distinction, `--target=runtime` recommendation** | **Native — Class-C leakage detection + pivot to SCA workflow** |
| [Class A](grype/#class-a--os-package-finding-base-layer) (OS-package) identification | Not native | Not native | Not native | Via container analyser | Not native | Not native | Not native | Commercial | Not native | Not native | Not native | **Native — `dpkg-matcher`/`apk-matcher`/`rpm-matcher`** | **Native — distro-feed cross-reference** |
| [Class B](grype/#class-b--language-ecosystem-finding-inside-the-container) (language-ecosystem) identification | N/A | Not native | Not native | Via container analyser | N/A | Not native | Not native | Commercial | N/A | N/A | Not native | **Native — `javascript-matcher`/`python-matcher`/`java-matcher`** | **Native — pivots to SCA workflow with the manifest path** |
| [Class C](grype/#class-c--multi-stage-build-artefact-leakage) (multi-stage leakage) detection | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Commercial — partial | Not native | Not native | Not native | **Native — recommends `--target=runtime` builds** | **Native — pivots to SCA on the source manifest** |
| [Class D](grype/#class-d--copied-in-os-package-files) (vendored OS-package) detection | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | **Native — via `docker history` archaeology** | **Native — IaC + Dockerfile rule on `COPY *.deb`** |
| Dockerfile static rules count | Not native | Custom queries | Not native | Via container analyser | Not native | Not native | Not native | Commercial — partial | Not native | Via hadolint-style rule packs | Not native | Not native | **Native — 8 first-party rules (`VNX-DOCKER-001..008`)** |
| Multi-architecture (amd64 / arm64) handling | Not native | Not native | Not native | Per-platform scan | Not native | Not native | Not native | Commercial — per-platform | Not native | Not native | Not native | **Native — per-architecture index entry** | **Native — manifest list awareness** |
| Distroless / scratch handling | Not native | Not native | Not native | Limited — no OS feed | Not native | Not native | Not native | Commercial — distroless catalogue | Not native | Not native | Not native | **Native — file-walk works on distroless** | **Native — VDB has Google distroless / Chainguard Wolfi / RH UBI catalogues** |

### 10. SAST / IaC / Secrets depth

| Capability | Dependabot | CodeQL | GH Secrets | GL Deps | GL SAST | GL Secrets | GL DAST | Snyk OSS | Snyk SAST | Semgrep | osv-scanner | Grype | **Vulnetix** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| SAST engine type | N/A | **Call-graph + taint (data-flow library)** | N/A | N/A | Multi-analyser (Semgrep + bandit + gosec + brakeman + spotbugs) | N/A | N/A | N/A | **Taint (Snyk Code intermediate representation)** | Pattern-match (OSS) / **Taint (Pro)** | N/A | N/A | Pattern-match + semantic enrichment |
| SAST language coverage | N/A | C/C++, C#, Go, Java/Kotlin, JS/TS, Python, Ruby, Swift, GitHub Actions | N/A | N/A | Per-analyser breadth; ~25 languages combined | N/A | N/A | N/A | C/C++, C#, Go, Java/Kotlin, JS/TS, Python, PHP, Ruby, Scala, Swift, Apex | ~30+ languages via rule packs | N/A | N/A | Java, Python, Go, Node.js, PHP, Ruby, .NET (representative rules) |
| SAST custom-rule authoring | N/A | CodeQL query language (Datalog-derived) | N/A | N/A | Via Semgrep rules | N/A | N/A | N/A | Limited — closed engine | YAML pattern rules | N/A | N/A | Limited — rule additions via VDB |
| IaC formats covered | N/A | Limited — via custom queries | N/A | N/A | Limited — Semgrep IaC packs | N/A | N/A | Commercial — Terraform, CloudFormation, Kubernetes, Helm, Pulumi | N/A | Terraform, Kubernetes, Dockerfile via rule packs | N/A | N/A | **Native — Terraform / OpenTofu / Nix / k8s / Helm / Dockerfile** |
| IaC rules count | N/A | Custom | N/A | N/A | Per-pack | N/A | N/A | Commercial — hundreds | N/A | 1000s via Semgrep registry | N/A | N/A | **8 first-party Terraform rules (`VNX-TF-001..008`) + Nix flake handling** |
| Secrets signature breadth | N/A | N/A | Native — GitHub Secret Scanning catalogue (300+ providers) | N/A | N/A | **gitleaks ruleset (~100 providers)** | N/A | N/A | N/A | Custom rule packs | N/A | File-pattern matcher only | **Native — AWS / GitHub PAT / Slack / Stripe / GCP / Azure / Twilio / SendGrid / JWT / generic entropy** |
| Secrets git-history scanning | N/A | N/A | **Native — scans entire repo history on enrolment** | N/A | N/A | Native — gitleaks scans history | N/A | N/A | N/A | Custom | N/A | Not native | **Native — `vulnetix:secret-scan --staged-only` for pre-commit, full repo otherwise** |
| Secrets validation (live token check) | N/A | N/A | **Native — `validity: active/inactive/unknown` for major providers** | N/A | N/A | Not native | N/A | N/A | N/A | Not native | N/A | Not native | **Native — token-validity probe** |
| Secrets custom-rule support | N/A | N/A | Limited — partner-program providers | N/A | N/A | Via custom gitleaks config | N/A | N/A | N/A | Native — rule packs | N/A | Not native | **Native — VDB pattern registry** |

### 11. Output formats

| Capability | Dependabot | CodeQL | GH Secrets | GL Deps | GL SAST | GL Secrets | GL DAST | Snyk OSS | Snyk SAST | Semgrep | osv-scanner | Grype | **Vulnetix** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| JSON | REST / GraphQL via `gh api` | SARIF (JSON encoding) | REST | gemnasium Security Report JSON | Per-analyser JSON + SARIF | gitleaks JSON | ZAP JSON | Native | Native | Native | Native | **Native — rich** | **Native — rich, multi-tool aggregation** |
| [SARIF](../appendices/sarif/) dialect | Via Code Scanning API (flat) | **Rich — `codeFlows[]` + `partialFingerprints` + `security-severity` numeric** | Via Code Scanning API (limited) | Native — via analyser | Native — varies per analyser | Limited | Limited | Flat (SCA) | **codeFlow + `properties.snyk`** | OSS flat / **Pro codeFlow** | Flat | Flat (`-o sarif`) | **Rich — `properties.security-severity` numeric + Vulnetix rule metadata** |
| CycloneDX SBOM | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Via syft companion (1.4 / 1.5 / 1.6) | **Native — 1.4 / 1.5 / 1.6 / 1.7** |
| SPDX SBOM | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Via syft companion (2.2 / 2.3) | **Native — 2.2 / 2.3 / 3.0** |
| [CycloneDX VEX](../appendices/cyclonedx-vex/) emit | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | **Native — `vulnetix:vex-publish` (auto-picks for PURL-backed findings)** |
| [OpenVEX](../appendices/openvex/) emit | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | **Native — `vulnetix:vex-publish` (auto-picks for non-PURL findings)** |
| HTML / Markdown / PDF report | Via UI only | Via UI only | Via UI only | Via UI / pipeline artefact | Via UI | Via UI | Via UI | Via UI + CLI HTML | Via UI + CLI HTML | Markdown / SARIF | Table / Markdown | Table / Markdown | **Native — Markdown summaries + compliance bundle** |
| GitLab gemnasium JSON | Not native | Not native | Not native | **Native — flagship format** | Native — per analyser | Native — per analyser | Native — per analyser | Not native | Not native | Not native | Not native | Not native | Not native — emit via SARIF pivot |
| GitHub Code Scanning ingest | **Native — primary surface** | **Native — primary surface** | **Native — secret-scanning surface** | Not native (GitHub-only) | Not native | Not native | Not native | Via SARIF upload | Via SARIF upload | Via SARIF upload | Via SARIF upload | Via SARIF upload | Via SARIF upload |
| JUnit XML (CI ingestion) | Not native | Not native | Not native | Native — per analyser | Native — per analyser | Native | Native | CLI option | CLI option | Native | Not native | Not native | **Native — for `--exit-code` gating** |
| STIX 2.1 IOC export | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | **Native — `vulnetix:ioc-pivot --format=stix`** |
| Mermaid threat-model graphs | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | **Native — `vulnetix:exploits` flowcharts** |

### 12. VEX, triage memory & detection-rule generation

Where the triage decision *lives* once you've made it, plus what non-code mitigation the tool can synthesise.

| Capability | Dependabot | CodeQL | GH Secrets | GL Deps | GL SAST | GL Secrets | GL DAST | Snyk OSS | Snyk SAST | Semgrep | osv-scanner | Grype | **Vulnetix** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| VEX consumption (suppression loop) | Not native | Via dismissal API (orthogonal) | Via resolution status | Via dashboard dismissal | Via dashboard dismissal | Via dashboard dismissal | Via dashboard dismissal | Not native | Not native | Inline `nosemgrep:` suppression | Not native | **Native — `--vex` flag** | **Native — `.vulnetix/memory.yaml` + re-scan suppression** |
| VEX consumption format | — | — | — | Proprietary (dashboard state) | Proprietary | Proprietary | Proprietary | — | — | Inline comments | — | **OpenVEX only** | **OpenVEX + CycloneDX VEX + memory.yaml** |
| Triage memory mechanism | GitHub alert state (per-repo) | GitHub alert state | GitHub alert state | GitLab Vulnerability Dashboard (per-project) | GitLab dashboard | GitLab dashboard | GitLab dashboard | Snyk Monitor SaaS dashboard | Snyk Monitor SaaS dashboard | Inline source comments | None (re-resolves each run) | None | **`.vulnetix/memory.yaml` — file-based, committed to repo, append-only `history[]`** |
| Cross-scan deduplication | Alert number stability | SARIF `partialFingerprints` | Alert number | Dashboard finding-ID UUID | Per-analyser fingerprints | Fingerprints | Fingerprints | Snyk finding fingerprint | Snyk finding fingerprint | `extra.fingerprint` | Per-vuln ID | Per-match purl+id | **Stable `aliases[]` + memory.yaml row identity** |
| Engineer Triage outcome recording | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | **Native — `decision.choice` ∈ {`fix-applied`, `risk-accepted`, `deferred`, `mitigated`, `inlined`, `risk-avoided`, `not-affected`, `risk-transferred`}** |
| Coordinator decision recording | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | **Native — surfaced from VDB into memory.yaml** |
| Snort / Suricata signature generation | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | **Native — `vdb snort-rules get <CVE>` + `vulnetix:detection-rules`** |
| YARA rule generation | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | **Native — `vdb yara-rules`** |
| Nuclei template generation | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | **Native — `vdb nuclei get <CVE>`** |
| Sigma rule generation | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | **Native — see [Sigma rules guide](../rules/sigma/)** |
| ModSecurity / WAF rule generation | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | **Native — see [ModSecurity rules guide](../rules/modsecurity/)** |
| Traffic-filters | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | **Native — `vdb traffic-filters <CVE>`** |
| IOC export (STIX 2.1 / SIEM-ready) | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | **Native — for Splunk / Sentinel / Cortex / Tines ingestion** |

### 13. Compliance, integration & licensing

| Capability | Dependabot | CodeQL | GH Secrets | GL Deps | GL SAST | GL Secrets | GL DAST | Snyk OSS | Snyk SAST | Semgrep | osv-scanner | Grype | **Vulnetix** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Cosign signing of outputs | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | **Native — `compliance-bundler` sub-agent signs SBOM + SARIF + VEX bundles** |
| in-toto attestations | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | **Native — SLSA-style provenance metadata in bundles** |
| SLSA provenance | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | **Native — bundle level satisfies SLSA Level 2/3 evidence shape** |
| Compliance bundle (SBOM + SPDX + SARIF + VEX + cosign + manifest) | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | **Native — `compliance-bundler` agent emits ZIP with `manifest.json` + SHA-256 sums + Markdown index** |
| GitHub Actions / GitLab CI / Jenkins integration | Native (GitHub) | Native (GitHub Actions; CI elsewhere via CLI) | Native (GitHub) | Native (GitLab CI) | Native (GitLab CI) | Native (GitLab CI) | Native (GitLab CI) | Native — all major CIs | Native — all major CIs | Native — all major CIs | Native — all major CIs | Native — all major CIs | **Native — all major CIs + per-step hook gates** |
| Pre-commit / git hooks | Not native | Not native | Push-protection blocks the commit | Not native | Not native | Push-protection (commercial) | Not native | CLI hook recipe (manual) | CLI hook recipe (manual) | Native — `semgrep --pre-commit` | CLI hook recipe (manual) | CLI hook recipe (manual) | **Native — `pre-commit-scan.sh`, `manifest-edit-scan.sh`, `dockerfile-edit-gate.sh`, `dep-install-gate.sh`, `git-push-gate.sh`** |
| IDE extensions | GitHub IDE plugins (limited) | Via GitHub IDE plugins + CodeQL CLI | Via GitHub IDE plugins | Via GitLab Workflow extension | Same | Same | Same | Native — Snyk plugins for VS Code / IntelliJ / Eclipse / Eclipse Theia / Visual Studio | Same as Snyk OSS | Native — Semgrep extension for VS Code / IntelliJ / Vim | None — CLI only | None — CLI only | **Via [AI Coding Agent](../appendices/ai-coding-agent/) — Claude Code / Cursor / Windsurf / Copilot / Gemini / Codex / Augment / Cline / Amazon Q / OpenHands / Codebuddy / Cortex / Qoder / Qwen / Kiro / iFlow** |
| AI Coding Agent slash-commands | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | Not native | **Native — 33+ skills + 7 sub-agents + 30+ hooks; see [AI Coding Agent](../appendices/ai-coding-agent/)** |
| REST / GraphQL API | REST + GraphQL via `gh api` | REST via `gh api` | REST via `gh api` | GitLab REST | GitLab REST | GitLab REST | GitLab REST | REST + Snyk API | REST + Snyk API | REST (commercial) + Semgrep app API | Not native (CLI only) | Not native (CLI only) | **REST API + CLI + AI Coding Agent skill wrappers** |
| Tool license | Closed (free for repos) | Free public / GHAS commercial private | Closed (free) | GitLab tiers (Free / Premium / Ultimate) | Same | Same | Same | Commercial — free tier with test caps | Commercial | LGPL-2.1 OSS / commercial Pro tier | Apache-2.0 OSS | Apache-2.0 OSS | Commercial — free / Vulnetix Pro / Enterprise tiers; AI Coding Agent plugin Apache-2.0 OSS |
| Free-tier feature set | Full SCA + auto-MRs (public + private) | Full on public repos; private requires GHAS | Full on public; partner program for org-wide | GitLab Free has dep scanning; SAST + DAST in higher tiers | Same | Same | Premium+ only | Monthly test caps + open-source projects | Same | Full OSS engine; cloud features behind login | Fully OSS | Fully OSS | **AI Coding Agent + CLI + most VDB queries free; advanced enrichment and bulk-triage in paid tier** |
| Self-host vs SaaS | SaaS only (GitHub.com / GHE) | SaaS — runs in Actions / GHE | SaaS only | Both — GitLab.com or self-host | Both | Both | Both | Both — Snyk SaaS or on-prem (commercial) | Both | Both — local CLI or Semgrep Cloud | Self-host (CLI binary) | Self-host (CLI binary) | **Both — local CLI / hosted VDB / on-prem deployment** |

## Database quality tiers

The matrix's "Database quality tier" row uses a five-tier scale. Tiers below shape what your scanner *can* detect — a scanner reading CVE/NVD only is missing half the ecosystem advisories.

| Tier | Coverage | Verdict | Tools |
|---|---|---|---|
| **CVE/NVD only** | NIST-curated CVE records, often weeks behind ecosystem advisories | **Insufficient** | (Tools at this tier are increasingly rare; most modern scanners aggregate at least GHSA.) |
| **CVE + GHSA** | + npm, pip, Maven, NuGet, RubyGems, Composer, Go via GitHub Advisory DB | **Minimal** | Dependabot |
| **CVE + OSV** | + RUSTSEC, PYSEC, GO, MAL, and broader ecosystem coverage via the [OSV aggregator](https://osv.dev/) | **Sufficient** | osv-scanner |
| **CVE + OSV + GCVE** | + Community-curated GCVE entries | **Good coverage** | **No scanner currently ships this tier.** |
| **[Vulnetix VDB](../appendices/glossary/#vulnetix-vdb)** | Every feed above plus first-party AI-derived enrichment: `x_affectedFunctions`, sightings (honeypot + CrowdSec), weaponisation indicators, [`x_attackPaths`](../appendices/glossary/#x_attackpaths), maintainer-health (OpenSSF Scorecard + account age + 2FA), AI-malware families, traffic-filters (Snort/Suricata/Nuclei) | **Full coverage** | Vulnetix |

Snyk's commercial database is a curated catalogue that augments GHSA — broader than CVE+GHSA-only, narrower than OSV. GitLab's Advisory Database is a similar shape. Both sit between "Minimal" and "Sufficient" depending on advisory.

## How to use the matrix

- **Pick a single scanner for a single feature**: read its column straight down; the cells tell you *how* it covers the row (not just whether).
- **Stack two scanners for breadth**: a typical OSS stack is [Grype](grype/) (container image-binary + OS-package SCA) + [Semgrep](semgrep-opengrep/) (SAST) + [Vulnetix](vulnetix/) (enrichment + reachability + VEX + supply-chain). Each covers the others' gaps.
- **Identify gaps your current stack leaves uncovered**: any row where your stack has no native cell is a triage decision being made on partial information. The usual fallback is [Vulnetix VDB](../appendices/glossary/#vulnetix-vdb) — which is why most pages on this site reference `vulnetix vdb` even when a different scanner originated the finding.
- **Vulnetix isn't best at everything.** The two drawback rows are explicit: Vulnetix's reachability is semantic (not call-graph) — pair with [CodeQL](github-codeql/) or [Snyk SAST](snyk-sast/) for precise call-edge questions. Vulnetix's container scanning is unpacked-layer / OCI-manifest (not image-binary) — pair with [Grype](grype/) or Trivy when the question is "what's in the binary OCI layers."

## See also

- [VEX overview](../appendices/vex/) — the format every scanner page's worked example produces.
- [SSVC Engineer Triage](../appendices/ssvc/) — the decision framework that consumes the scanner's data depth.
- [Reachability deep-dive](../appendices/reachability-deep-dive/) — the three-tier model the Reachability section is graded against.
- [SARIF appendix](../appendices/sarif/) — the format the SARIF row's dialects are compared against.
- [Supply-chain threats](../appendices/supply-chain-threats/) — what the supply-chain detection table's tools can and can't detect.
- [EOL appendix](../appendices/eol/) — what the lifecycle table's tools can and can't detect.
- [AI Coding Agent](../appendices/ai-coding-agent/) — the slash-command layer that wraps the Vulnetix CLI invocations across every IDE.
- [Glossary](../appendices/glossary/) — definitions for every term used in the matrix.
