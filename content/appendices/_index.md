---
title: "Appendices"
description: "Reference reading on SBOMs, VEX, SSVC, SARIF, reachability tiers, supply-chain threats, EOL, and per-language package-manager mechanics."
weight: 30
---

Reference reading on the formats, frameworks, and mechanics the scanner and rules guides assume. Start here if any concept lands cold, or come back as reference when a scanner guide mentions a field the output doesn't explain.

**Cross-cutting reference**
- [AI Coding Agent](ai-coding-agent/) — the [Vulnetix plugin](https://ai-docs.vulnetix.com/docs) for Claude Code, Cursor, Windsurf, Copilot, Gemini, and a dozen other editors. Removes the burden of picking VEX formats, remediation strategies, and SSVC inputs by hand.
- [Glossary](glossary/) — A–Z lookup for PURL, SBOM, VEX, KEV, EPSS, SSVC, CWE, CWSS, SARIF, MAL-, EOL, safe-harbour, reachability tiers. Land here when a term lands cold.
- [SARIF — the SAST output format](sarif/) — the JSON shape every SAST tool emits, with the dialect differences that catch you out.
- [Reachability — the three-tier model](reachability-deep-dive/) — stated booleans vs real call-graph evaluation vs semantic intent-to-use. Where each scanner sits on the spectrum, and what evidence supports which VEX justification.
- [Supply-chain threats beyond CVEs](supply-chain-threats/) — typosquatting, dependency confusion, maintainer takeover, protestware, install-script abuse. The OpenVEX shape for a `MAL-` record.
- [EOL gating](eol/) — when a CVE means migrate, not patch. Per-runtime / per-package / per-container-base-image EOL data sources.

**Formats**
- [CycloneDX SBOM](cyclonedx-sbom/) — the component inventory every triage workflow on this site assumes you have.
- [VEX overview](vex/) — what a VEX statement is and which of the two formats below to pick.
- [CycloneDX VEX](cyclonedx-vex/) — SBOM-coupled VEX entries.
- [OpenVEX](openvex/) — standalone VEX statements (consumed natively by Grype's `--vex`).

**Frameworks**
- [SSVC Engineer Triage](ssvc/) — the developer-side decision framework: four inputs (Reachability, Remediation, Mitigation, Priority) → four outcomes (`NIGHTLY_AUTO_PATCH`, `BACKLOG`, `SPIKE_EFFORT`, `DROP_TOOLS`).

**Per-language patching mechanics**
- [Package managers](package-managers/) — lockfile mechanics, transitive coercion, integrity verification, reachability tooling for each ecosystem (JavaScript, Python, JVM, Go, Rust, Ruby, .NET, PHP, Swift/iOS, and others).
