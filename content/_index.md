---
title: "Vulnerability Management Guide"
description: "Decide each scanner finding once, record it as a CycloneDX VEX or OpenVEX attestation, and stop re-litigating the same CVEs."
---

Decide each scanner finding once, record the decision as a [CycloneDX VEX](appendices/cyclonedx-vex/) or [OpenVEX](appendices/openvex/) attestation, and stop re-litigating the same CVEs every scan.

This site has three sections:

- [Scanner guides](scanners/) — translate each tool's output into a VEX statement, one tool at a time. Includes the [capability matrix](scanners/#capability-matrix) comparing every scanner on a common feature set.
- [Rule guides](rules/) — non-code mitigations. ModSec / WAF, Snort / Suricata / IPS, Sigma / SIEM, YARA / file detection, Nuclei / pentest, and how each one ties back into the triage decision.
- [Appendices](appendices/) — reference reading on [SBOMs](appendices/cyclonedx-sbom/), [VEX](appendices/vex/), the [SSVC Engineer Triage](appendices/ssvc/) framework, the [SARIF format](appendices/sarif/), [reachability tiers](appendices/reachability-deep-dive/), [supply-chain threats](appendices/supply-chain-threats/), [EOL gating](appendices/eol/), and per-language [package-manager mechanics](appendices/package-managers/).

**Unfamiliar with a term?** See the [Glossary](appendices/glossary/) — A–Z lookup for PURL, SBOM, VEX, KEV, EPSS, SSVC, CWE, CWSS, SARIF, MAL-, EOL, safe-harbour, reachability tiers, and the rest.
