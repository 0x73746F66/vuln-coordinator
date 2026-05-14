---
title: "YARA — Detection (defender)"
description: "Write YARA rules to detect malicious files or artefacts related to a vulnerability, then reference them in a VEX statement."
weight: 40
---

## Overview

YARA is a pattern-matching tool for identifying and classifying malware and suspicious files. Rules describe byte sequences, strings, or conditions that match a file or memory region.

In the context of vulnerability management, YARA rules serve as **defender-side detection**: you write a rule that detects the artefact an attacker would drop or the payload they would use. Deploying the rule to your endpoint or file-scanning pipeline is evidence that you can detect exploitation attempts, which supports an OpenVEX `workaround_available` justification.

**Outcome type:** OpenVEX — YARA rules are detections, not package-level fixes.

## Rule structure

<!-- TODO: YARA rule anatomy: `rule Name { meta: ... strings: ... condition: ... }`. String types (text, hex, regex). Condition operators. Modules (pe, elf, math, hash). -->

## Writing a detection rule

<!-- TODO: Identify the exploit artefact or payload bytes. Write strings targeting them. Use conditions to avoid false positives. Test with `yara rule.yar <target>`. -->

{{< tabs >}}
{{< tab name="String match" >}}
```yara
rule CVE_XXXX_XXXX_exploit_payload {
  meta:
    description = "Detects CVE-XXXX-XXXX exploit payload in uploaded files"
    cve         = "CVE-XXXX-XXXX"
    author      = "vuln-coordinator"
    date        = "2026-05-14"

  strings:
    $magic  = { 4D 5A }                      // PE header
    $marker = "CVE-XXXX-XXXX-exploit" ascii

  condition:
    $magic at 0 and $marker
}
```
{{< /tab >}}
{{< tab name="Regex match" >}}
```yara
rule CVE_XXXX_XXXX_webshell {
  meta:
    description = "Detects webshell variant used with CVE-XXXX-XXXX"
    cve         = "CVE-XXXX-XXXX"

  strings:
    $cmd = /eval\(base64_decode\(['"]/

  condition:
    $cmd
}
```
{{< /tab >}}
{{< /tabs >}}

## Testing the rule

<!-- TODO: `yara -r rule.yar /path/to/scan`. Using YARA-X for improved performance. Integrating with ClamAV or endpoint agents. -->

## OpenVEX outcome

<!-- TODO: OpenVEX with `workaround_available`, YARA rule name + deployment location, CVE reference. -->
