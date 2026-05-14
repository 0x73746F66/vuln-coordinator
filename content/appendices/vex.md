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

## Which one do I pick?

A short decision rule:

{{< decision >}}
Does the finding name a component that appears in your SBOM (a library, a package, an OS-level dependency, a container layer)?
  ├─ Yes → CycloneDX VEX, referencing the component by PURL
  └─ No  → OpenVEX, with the repo or service as the subject

If the same finding has both a packaged-component angle (the vulnerable library) and a runtime mitigation (a WAF rule that blocks the vector):
  ├─ Write the CycloneDX VEX entry for the component, status `affected` with `workaround_available`
  └─ Optionally write a parallel OpenVEX statement against the deployed service for SOC tooling that consumes OpenVEX
{{< /decision >}}

In practice most teams pick one format as canonical and only reach for the other when forced. Pick CycloneDX VEX if you already ship an SBOM in CI; pick OpenVEX if you don't, or if your stack is SAST-heavy where most findings sit in first-party code.

## Why VEX matters to a developer

Writing VEX feels like an extra step. It's worth it for five reasons that compound over time.

**Future-you benefits first.** Six months from now, when the same CVE reappears in a new scanner report, the VEX statement carries your original reasoning. You don't re-investigate from scratch — you read what you wrote.

**Past decisions become defensible.** When a security team or auditor asks "what did you do about CVE-2024-12345?", a timestamped, machine-readable VEX statement is more trustworthy than a comment in a closed ticket or a half-remembered Slack thread.

**Your colleagues see less noise.** Scanner tooling that understands VEX will suppress findings already assessed as `not_affected` or `fixed`. When a colleague runs the scanner against your repository tomorrow, they don't get to re-discover what you already triaged.

**You benefit from other people's work.** The same suppression works in reverse. When a library maintainer publishes a VEX statement saying a CVE doesn't affect their default configuration, VEX-aware tools suppress that finding for you automatically.

**Compliance is already done.** VEX is referenced in CISA guidance, NIST SP 800-218, and the EU Cyber Resilience Act as the mechanism for communicating exploitability status. Producing VEX during normal development means the compliance artefact exists before it's requested.

Grype, Trivy, and the Vulnetix platform all consume VEX today. The investment pays back every time the scanner runs.
