---
title: "Glossary"
description: "A–Z reference for the jargon that lands cold on a first-time reader — PURL, SBOM, VEX, KEV, EPSS, SSVC, CWE, CWSS, SARIF, MAL-, EOL, safe-harbour, reachability tiers."
weight: 5
---

A lookup index for the abbreviations and concepts the rest of the site assumes. Each entry is two-to-four sentences plus a link to the page where the term is most fully developed.

If you find yourself on a scanner page and a term lands cold, scroll here.

## A

### ATT&CK
MITRE's Adversarial Tactics, Techniques, and Common Knowledge framework — a hierarchical catalogue of how attackers operate, indexed by *tactic* (e.g. Initial Access, Execution) and *technique* (e.g. T1190 Exploit Public-Facing Application). The Vulnetix VDB carries an `x_attackPaths` field per CVE that maps the vulnerability to ATT&CK tactics and techniques, driving detection-rule selection. See [Vulnetix SCA](../../scanners/vulnetix/sca/).

### Attack surface signal
Vulnetix's `x_attackSurface` field — a structured read of whether the vulnerability is remotely exploitable, what privileges it requires, whether user interaction is needed, etc. Distinct from CVSS in that it's narrative-shaped rather than vector-string-shaped. Used as an SSVC priority input.

### Attestation
A signed claim about an artefact — for example, "this container image was built by GitHub Actions workflow X at commit Y." Different from a signature: an attestation includes a *statement* alongside the signature. Tools: [cosign](https://docs.sigstore.dev/cosign/overview), in-toto, SLSA provenance.

## B

### BOM (Bill of Materials)
A list of components in a software artefact. The most common formats are [CycloneDX SBOM](cyclonedx-sbom/) and [SPDX](https://spdx.dev/). A `bom-ref` is a stable identifier for a component within a CycloneDX BOM. See [CycloneDX SBOM appendix](cyclonedx-sbom/).

## C

### Call graph
A directed graph whose nodes are functions/methods and whose edges are caller→callee relationships. Static call-graph analysis (CHA, RTA, VTA, pointer analysis) is the [Tier 2 reachability](reachability-deep-dive/) approach — it proves an edge from your code's entry points to the affected method exists.

### CHA (Class Hierarchy Analysis)
A coarse, fast call-graph algorithm: every virtual call is assumed to dispatch to every override in the class hierarchy. Over-approximates the real call set (you get false-positives for reachability). Used by SootUp's default analysis. See [reachability deep-dive](reachability-deep-dive/).

### CISA Coordinator decision
The output of the SSVC Coordinator-Triage methodology — one of `Act`, `Attend`, `Track*`, `Track`. Tells a *coordinator* (e.g. CISA, a vendor PSIRT) whether to issue an advisory. Distinct from [Engineer Triage](ssvc/) which tells a *developer* what action to take.

### codeFlow
A SARIF field that records the source-to-sink data-flow trace for a finding — used by CodeQL, Snyk SAST, and Semgrep Pro. A reader can step from the tainted source (e.g. `req.query.q`) through every transformation to the sink (e.g. `db.query`). See [SARIF appendix](sarif/).

### Coordinator decision
See [CISA Coordinator decision](#cisa-coordinator-decision).

### cosign
Sigstore's CLI for signing and verifying artefacts — container images, blobs, attestations. `cosign sign-blob`, `cosign verify-blob`, `cosign attest`. Reference: [sigstore docs](https://docs.sigstore.dev/cosign/overview).

### CVE (Common Vulnerabilities and Exposures)
MITRE's vulnerability identifier scheme — `CVE-YYYY-NNNN`. The CVE record describes one vulnerability; NVD enriches CVEs with CVSS scores and CPE matching, but NVD lags behind the actual advisory ecosystem (GHSA, RUSTSEC, PYSEC, etc.). See [database quality tiers](../scanners/#capability-matrix).

### CWE (Common Weakness Enumeration)
MITRE's catalogue of vulnerability classes — `CWE-89` (SQL Injection), `CWE-79` (XSS), `CWE-502` (Deserialization of Untrusted Data). A CVE is an *instance*; a CWE is the *class*. SAST rules typically target a CWE.

### CWSS (Common Weakness Scoring System)
MITRE's framework for scoring weakness severity. Vulnetix uses a CWSS-shaped composite score combining technical-impact, exploitability, exposure, complexity, and repo-relevance. See [Vulnetix SCA](../../scanners/vulnetix/sca/).

### CycloneDX
The OWASP-stewarded BOM standard. Comes in two flavours: [CycloneDX SBOM](cyclonedx-sbom/) (component inventory) and [CycloneDX VEX](cyclonedx-vex/) (vulnerability disposition statements). See [VEX overview](vex/) for the format split.

## D

### DAST (Dynamic Application Security Testing)
Black-box scanning that probes a running application. Distinct from SAST (which reads source). [GitLab DAST](../../scanners/gitlab-dast/) and ZAP are the common tooling.

### Dependency confusion
A supply-chain attack where an attacker publishes a public package with the same name as a private internal package, hoping the build pulls the public one. Birsan-style. See [supply-chain threats](supply-chain-threats/).

## E

### EOL (End of Life)
The point past which an upstream project stops shipping fixes — for runtimes (Python 2.7, Node 14), packages, or container base images. An EOL'd component's SSVC `Remediation Option` is `NO_PATCH`; the right outcome is migration, not per-CVE bumps. See [EOL appendix](eol/).

### EPSS (Exploit Prediction Scoring System)
FIRST.org's daily-updated probability score (0-1) that a CVE will be exploited in the wild in the next 30 days. Used as an SSVC priority input. Not the same as KEV — EPSS predicts; KEV records.

### Engineer Triage
The developer-side SSVC methodology — four inputs (Reachability, Remediation, Mitigation, Priority) producing one of four outcomes (`NIGHTLY_AUTO_PATCH`, `BACKLOG`, `SPIKE_EFFORT`, `DROP_TOOLS`). See [SSVC appendix](ssvc/).

### Exploitation maturity
Vulnetix's `x_exploitationMaturity.level` field — `ACTIVE` / `POC` / `WEAPONISED` / `NONE`. Richer than a boolean: combines EPSS, KEV, honeypot sightings, and observed-in-the-wild data. Other scanners typically expose only EPSS or a boolean "has exploit known".

## F

### Fingerprint
SARIF's `partialFingerprints` field — stable hashes for tracking a finding across commits even when line numbers change. Used by GitHub Code Scanning and GitLab Security Dashboard for deduplication. See [SARIF appendix](sarif/).

## G

### GCVE
A community-curated CVE-shaped feed proposed as a complement to NVD. **No current scanner consumes GCVE**; the only tier with full feed coverage is Vulnetix VDB. See [database quality tiers](../scanners/#capability-matrix).

### GHSA (GitHub Security Advisory)
GitHub's vulnerability identifier — `GHSA-xxxx-xxxx-xxxx`. Covers npm, pip, Maven, NuGet, RubyGems, Composer, Go. Used by Dependabot, Snyk (alongside others), and OSV (aggregated). Coverage is broader than NVD for ecosystem-native advisories.

## I

### IaC (Infrastructure as Code)
Terraform, CloudFormation, Pulumi, Kubernetes manifests, Helm charts. Scanned by [Vulnetix IaC](../../scanners/vulnetix/iac/), Checkov, tfsec, Snyk IaC.

### IOC (Indicator of Compromise)
Network/file/process artefacts associated with an attack — IPs, file hashes, registry keys. Vulnetix provides per-CVE IOC pivots via the `ioc-pivot` skill. See [Vulnetix SCA](../../scanners/vulnetix/sca/).

### Intent-to-use
[Tier 3 reachability](reachability-deep-dive/) — the symbol may not be in the static call graph but is effectively invoked at runtime via reflection, dependency injection, ServiceLoader, plugin systems, or framework auto-configuration. Vulnetix's reachability model captures this where call-graph tools miss it.

## J

### Justification
A controlled vocabulary in a VEX statement explaining *why* a finding is `not_affected`. Values include `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`. See [VEX overview](vex/).

## K

### KEV (Known Exploited Vulnerabilities)
CISA's catalogue of CVEs known to be actively exploited. Federal civilian agencies must remediate by specified deadlines; the catalogue is also a strong SSVC priority signal. Cross-referenced via the Vulnetix `x_kev` field. EU-KEV is the European equivalent.

## M

### MAL- record
OSV's identifier scheme for *malicious packages* (typosquats, dependency-confusion attacks, maintainer-takeover-publishes). Different from a CVE — there's no version range, just "this package version is malicious; remove it." See [supply-chain threats](supply-chain-threats/).

### Maintainer health
Signals about a package's maintainer team — account age, 2FA enrolment, prior commits, OpenSSF Scorecard score. Used as a supply-chain risk input by Vulnetix's `dep-add-guard` and `package-search` skills.

## N

### NVD (National Vulnerability Database)
NIST's CVE enrichment programme. Lags behind ecosystem-native feeds (GHSA, RUSTSEC, PYSEC) by weeks. CVE+NVD-only scanners are considered insufficient coverage; see [database quality tiers](../scanners/#capability-matrix).

## O

### OpenVEX
A Sigstore-stewarded VEX format. Lighter weight than CycloneDX VEX; standalone JSON statements. Consumed natively by Grype's `--vex` flag. See [OpenVEX appendix](openvex/).

### OSV (Open Source Vulnerabilities)
Google-stewarded vulnerability schema and database. Aggregates GHSA + RUSTSEC + PYSEC + GO + MAL + OSV-native entries. Consumed by [osv-scanner](../../scanners/osv-scanner/) and used as an enrichment feed by Vulnetix VDB.

## P

### PURL (Package URL)
A URI scheme for naming a software component, e.g. `pkg:npm/lodash@4.17.21`, `pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1`. The canonical identifier in CycloneDX SBOMs and CycloneDX VEX `affects[]` arrays. Reference: [purl spec](https://github.com/package-url/purl-spec).

### Protestware
A package that intentionally degrades or alters behaviour for political reasons rather than for malice in the conventional sense — `peacenotwar`, `node-ipc`. Still warrants triage even though it's not a CVE. See [supply-chain threats](supply-chain-threats/).

## R

### Reachability tier
The three-tier model used on this site for SSVC `Reachability` evidence:
- **[Tier 1 — Stated boolean](reachability-deep-dive/#tier-1)**: trust the manifest; the symbol is present in the build artefact.
- **[Tier 2 — Real call-graph evaluation](reachability-deep-dive/#tier-2)**: a static call graph proves an edge from your entry points to the affected method.
- **[Tier 3 — Semantic / intent-to-use](reachability-deep-dive/#tier-3)**: the symbol may be activated via reflection, DI, ServiceLoader, framework auto-configuration even when no static edge exists.

Each scanner sits at a tier — see the [capability matrix](../scanners/#capability-matrix).

## S

### Safe-harbour
A version (or family of versions) of a dep that is known to be free of CVEs *and* satisfies a `--max-major-bump` policy. Vulnetix's `safe-version` skill returns the safe-harbour recommendation; other scanners typically don't synthesise this signal.

### SARIF (Static Analysis Results Interchange Format)
OASIS-standard JSON format for static-analysis tool output. Emitted by CodeQL, Snyk SAST, Semgrep, Vulnetix SAST, GitLab analysers. See [SARIF appendix](sarif/).

### Sightings
Observations of an exploit in the wild — honeypot captures, CrowdSec community sightings, vendor telemetry. Vulnetix carries per-CVE sightings counts (1d/7d/30d/90d averages) and IP/ASN/geo distribution. Other scanners typically only carry EPSS as a proxy.

### SLSA (Supply-chain Levels for Software Artifacts)
Google-stewarded framework for build-provenance integrity, scored Level 1–4. Builds on attestations (in-toto). Reference: [slsa.dev](https://slsa.dev/).

### SSVC (Stakeholder-Specific Vulnerability Categorization)
CMU-developed decision framework for triage. Comes in two flavours: Coordinator-Triage (for advisory publishers) and Engineer Triage (for developers). See [SSVC appendix](ssvc/).

### SVO (Software Vulnerability Operational)
Less common term; sometimes used for operational-domain SSVC variants. Outside the scope of this site.

## T

### Taint flow
A static-analysis technique that traces data from a *source* (often user input) through transformations to a *sink* (a dangerous operation). The output is a [codeFlow](#codeflow) trace in SARIF. Used by CodeQL, Snyk SAST, Semgrep Pro.

### Typosquatting
A supply-chain attack: publishing a package whose name resembles a popular one (`colors` → `colers`, `event-source-polyfill` typo squat). Detected by Vulnetix's `typosquat-check` skill; not natively flagged by most scanners. See [supply-chain threats](supply-chain-threats/).

## V

### VEX (Vulnerability Exploitability eXchange)
A statement recording that a finding *has been triaged* and what the disposition is — `affected`, `not_affected`, `under_investigation`, `fixed`. Comes in [CycloneDX VEX](cyclonedx-vex/) (SBOM-coupled) and [OpenVEX](openvex/) (standalone) formats. See the [VEX overview](vex/).

### Vulnetix VDB
Vulnetix's first-party vulnerability database — full coverage tier including CVE + GHSA + OSV + RUSTSEC + PYSEC + GO + MAL plus first-party AI-derived enrichments (`x_affectedRoutines`, `x_attackPaths`, sightings, weaponisation indicators, safe-harbour, maintainer-health, AI-malware families, traffic-filters). See [Vulnetix SCA](../../scanners/vulnetix/sca/) and the [capability matrix](../scanners/#capability-matrix).

## W

### Weaponisation
An exploit that's gone past proof-of-concept into a ready-to-use form — Metasploit module, Nuclei template, autonomous attack tool. A Vulnetix `x_exploitationMaturity.level` of `WEAPONISED` is a sharp priority signal that EPSS-only scanners miss.

## X

### `x_affectedRoutines`
Vulnetix VDB enrichment field — the deduplicated list of affected functions and files for a CVE, aggregated from the CVE 5.x `programRoutines` / `programFiles` plus AI-derived `x_affectedFunctions`. The canonical "what to grep for" list. See [Vulnetix SCA](../../scanners/vulnetix/sca/).

### `x_attackPaths`
Vulnetix VDB enrichment field — per-CVE tactic→ATT&CK-technique mapping. Drives detection-rule selection (Snort, Nuclei, YARA, Sigma) rather than reachability. See [ATT&CK](#attack).

### `x_threatExposure`
Vulnetix VDB enrichment field — composite multiplier combining attack surface, exploitation maturity, KEV status, and repo relevance. Used as a scoring input.

---

Anything missing? File an issue against the docs and we'll add it.
