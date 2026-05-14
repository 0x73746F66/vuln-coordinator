---
title: "YARA — Detection (defender)"
description: "Catch the payload at rest, then attest to the detection in OpenVEX."
weight: 40
---

## What YARA does

YARA matches files (or memory regions) against pattern rules — byte sequences, ASCII or UTF-16 strings, regex, and conditions that combine them. It's used by endpoint tooling, file-upload scanners, and incident responders to identify known malware families, webshells, exploit payloads, and second-stage tooling.

In vulnerability management YARA is the defender's mirror image of Nuclei. Where Nuclei probes a target to confirm the exploit works, YARA inspects files at rest to catch what an attacker would drop after exploiting the vulnerability — the dropped binary, the webshell, the payload encoded in an uploaded image. A YARA rule deployed to your endpoint or upload pipeline is evidence that you can detect exploitation activity, which supports an OpenVEX `affected` with `workaround_available` while a patch is being prepared.

YARA rules are detections, not component-level fixes, so the attestation is always OpenVEX.

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
