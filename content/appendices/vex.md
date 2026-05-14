---
title: "VEX — overview"
description: "What VEX is, why it exists, which of the two formats to pick, and why writing one is worth your time."
weight: 20
---

## What a VEX statement is

A Vulnerability Exploitability eXchange (VEX) statement is a machine-readable record of a decision about a specific vulnerability in a specific piece of software. It answers one question: *is this CVE actually a problem for this component in this build, and what was done about it?*

VEX exists because vulnerability scanners do a particular kind of thing badly. They match component versions against advisory databases, then list every match — without checking whether the vulnerable code path is reachable, whether the input is attacker-controllable, or whether a compensating control already blocks the vector. Many matches are false positives in your particular build. Without a VEX statement, every person who runs the scanner against your code re-litigates the same noise. With one, tools that understand VEX can suppress findings you've already assessed.

## Two formats, one job

VEX comes in two flavours. They do the same job but live in different homes.

**[CycloneDX VEX](../cyclonedx-vex/)** is part of the CycloneDX standard. It travels with — or alongside — your SBOM, and every finding it records points back to a component declared in that SBOM by PURL. Use it when the vulnerability is in a packaged component you can name.

**[OpenVEX](../openvex/)** is a standalone, lightweight format. It doesn't need an SBOM to be useful, and the subject can be anything you can identify with a URL or PURL — your repository at a specific commit, a deployed service, an IaC manifest, a secret in source. Use it when the finding isn't a packaged component: SAST findings in code you wrote, secrets, runtime mitigations against vulnerabilities whose patches haven't shipped yet.

For the format details, field reference, and worked examples, see the dedicated pages.

## You don't need to pick

The format choice should never be your problem. The [Vulnetix AI Coding Agent](ai-coding-agent/) — slash-commands distributed across Claude Code, Cursor, Windsurf, Copilot, Gemini, and a dozen other editors — picks the right format from context and writes the attestation for you. Run `/vulnetix:vex-publish` after triaging a finding and it generates both file types as appropriate: entries with a [PURL](glossary/#purl-package-url) (library, package, OS dep, container layer) → CycloneDX VEX; entries without one (first-party SAST, secrets, runtime mitigations against unpatched vulnerabilities) → OpenVEX. The plugin also optionally cosign-signs the result and posts it to the originating GitHub PR.

If you do want to know the rule the agent applies: **PURL-backed component → CycloneDX VEX; everything else → OpenVEX.** That's it. The dedicated pages for [CycloneDX VEX](cyclonedx-vex/) and [OpenVEX](openvex/) have the field references and worked examples if you want to author one by hand, but you usually shouldn't have to.

## Why VEX matters to a developer

Writing VEX feels like an extra step. It's worth it for five reasons that compound over time.

**Future-you benefits first.** Six months from now, when the same CVE reappears in a new scanner report, the VEX statement carries your original reasoning. You don't re-investigate from scratch — you read what you wrote.

**Past decisions become defensible.** When a security team or auditor asks "what did you do about CVE-2024-12345?", a timestamped, machine-readable VEX statement is more trustworthy than a comment in a closed ticket or a half-remembered Slack thread.

**Your colleagues see less noise.** Scanner tooling that understands VEX will suppress findings already assessed as `not_affected` or `fixed`. When a colleague runs the scanner against your repository tomorrow, they don't get to re-discover what you already triaged.

**You benefit from other people's work.** The same suppression works in reverse. When a library maintainer publishes a VEX statement saying a CVE doesn't affect their default configuration, VEX-aware tools suppress that finding for you automatically.

**Compliance is already done.** VEX is referenced in CISA guidance, NIST SP 800-218, and the EU Cyber Resilience Act as the mechanism for communicating exploitability status. Producing VEX during normal development means the compliance artefact exists before it's requested.

[Grype](../scanners/grype/), [Trivy](../scanners/trivy/), and the Vulnetix platform all consume VEX today. The investment pays back every time the scanner runs.


---

Referenced in [NIST SP 800-218 (Secure Software Development Framework)](https://csrc.nist.gov/Projects/ssdf), the [CISA SSVC methodology](https://www.cisa.gov/ssvc), and the [EU Cyber Resilience Act](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act) — VEX statements form part of the evidence trail for SOC 2 Type II, PCI-DSS, ISO 27001, and FedRAMP compliance work.

See also: [AI Coding Agent](ai-coding-agent/), [CycloneDX VEX](cyclonedx-vex/), [OpenVEX](openvex/), [Glossary](glossary/), [SSVC Engineer Triage](ssvc/), [Capability matrix](../scanners/#capability-matrix).
