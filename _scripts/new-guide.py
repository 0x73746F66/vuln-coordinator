#!/usr/bin/env python3
"""Generate a new scanner or rules guide stub."""
import sys

SCANNER_TEMPLATE = """\
---
title: "{name}"
description: ""
weight: 999
---

## Overview

<!-- TODO -->

## Reading the report

### Report format

<!-- TODO -->

### Key fields

<!-- TODO -->

## Decision tree

{{{{< decision >}}}}
Is the affected component declared in your SBOM?
  ├─ Yes → CycloneDX VEX
  └─ No  → OpenVEX

Is the finding mitigated by a WAF / IPS rule or SIEM detection?
  └─ Yes → OpenVEX with workaround_available + rule reference
{{{{< /decision >}}}}

## CycloneDX VEX outcome

<!-- TODO -->

## OpenVEX outcome

<!-- TODO -->
"""

RULE_TEMPLATE = """\
---
title: "{name}"
description: ""
weight: 999
---

## Overview

<!-- TODO -->

## Rule structure

<!-- TODO -->

## Writing a mitigation rule

<!-- TODO -->

## Testing the rule

<!-- TODO -->

## OpenVEX outcome

<!-- TODO -->
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
