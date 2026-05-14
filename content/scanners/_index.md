---
title: "Scanner guides"
description: "Translate scanner output into a CycloneDX VEX or OpenVEX statement, one tool at a time."
weight: 10
---

Each scanner has its own dialect. Snyk's JSON looks nothing like Grype's, CodeQL's SARIF is its own thing, and Dependabot is a UI rather than a file you can grep. These guides cover what each scanner actually produces, which fields drive a triage decision, and how to translate the output into a VEX statement that records what you decided.

Pick the scanner that matches your pipeline. Every guide ends in the same place — either a CycloneDX VEX entry, when the finding ties back to an SBOM component, or an OpenVEX statement, for everything else.
