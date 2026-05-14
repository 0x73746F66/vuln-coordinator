#!/usr/bin/env python3
"""Generate a new scanner or rules guide stub."""
import sys

SCANNER_TEMPLATE = """\
---
title: "{name}"
description: ""
weight: 999
---

## What {name} does

<!-- TODO: One paragraph. What it analyses, what triggers it (CI step, scheduled scan, MR webhook, IDE plugin), what it produces, where the output lands. -->

## Reading the output

<!-- TODO: Where to find the report (CI artefact path, MR comment, dashboard, JSON on disk). What format (JSON, SARIF, plain table). One worked example of a single finding so the reader can pattern-match. -->

## What you can act on

<!-- TODO: The handful of fields you actually use for triage. Typically: vulnerability identifier (CVE / GHSA / internal), affected component + version, severity, location (file path or dependency path), fix availability. Ignore the rest until you need it. -->

## Decision tree

{{{{< decision >}}}}
Is the finding tied to a component declared in your SBOM?
  ├─ Yes → CycloneDX VEX entry referencing the PURL
  └─ No  → OpenVEX statement

Is the risk mitigated by a WAF, IPS, or SIEM rule?
  └─ If yes, status is `affected` with `workaround_available` and the rule reference
{{{{< /decision >}}}}

## Producing a CycloneDX VEX

<!-- TODO: Worked example. Reference the SBOM component by PURL, the vulnerability ID, an `analysis.state`, and the appropriate justification or response. -->

## Producing an OpenVEX

<!-- TODO: Worked example for findings that don't map to an SBOM component — transitive deps, code-level findings, secrets, network-mitigated risks. -->
"""

RULE_TEMPLATE = """\
---
title: "{name}"
description: ""
weight: 999
---

## What {name} does

<!-- TODO: One paragraph. What this control inspects (HTTP requests, network packets, files at rest, log events), where it sits in the stack, and the role it plays in vulnerability management — block, detect, or verify. -->

## Rule structure

<!-- TODO: The anatomy of a rule in this platform's syntax. Key sections, key fields, the metadata you'll want to attach for traceability (CVE tag, rule ID, version, deployment location). -->

## Writing a mitigation rule

<!-- TODO: Step-by-step example. Identify the attack signature from the scanner finding. Write the rule. Show one or two worked examples in tabbed code blocks. -->

## Testing the rule

<!-- TODO: How to confirm the rule fires on a malicious sample and doesn't fire on legitimate traffic. CLI commands, sample inputs, expected output. -->

## OpenVEX outcome

<!-- TODO: Worked OpenVEX statement that references the rule ID, the vulnerability, status `affected` with `workaround_available`, and the deployment location as evidence. -->
"""


def main():
    if len(sys.argv) != 4:
        print("Usage: new-guide.py <scanner|rule> <name> <output-path>")
        sys.exit(1)

    kind, name, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    template = SCANNER_TEMPLATE if kind == "scanner" else RULE_TEMPLATE
    content = template.format(name=name)

    with open(out_path, "w") as f:
        f.write(content)


if __name__ == "__main__":
    main()
