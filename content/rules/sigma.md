---
title: "Sigma — SIEM"
description: "Detect the attempt in your logs once it lands, then attest to the visibility in OpenVEX."
weight: 60
---

## What Sigma does

Sigma is a vendor-neutral signature format for SIEM detection rules. A rule written once in Sigma YAML compiles — via the `sigma-cli` tool — to Splunk SPL, Elastic Query DSL, Microsoft Sentinel KQL, QRadar AQL, Chronicle, and a long list of other backends. You write the detection logic once and let the toolchain translate it for whichever SIEM you're paying for this quarter.

Sigma belongs in vulnerability management for the cases where you can't fix at the code layer and can't block at the network layer either. The mitigation is detection: you won't stop the attack, but you'll see it land the moment it happens. A Sigma rule deployed to your SIEM is evidence that you have visibility into exploitation attempts — which supports an OpenVEX statement of `affected` with `workaround_available`, especially while a patch is in flight.

SIEM rules aren't SBOM components, so the attestation is always OpenVEX.

## Rule structure

<!-- TODO: Sigma YAML anatomy: `title`, `id` (UUID), `status`, `description`, `author`, `date`, `tags` (ATT&CK technique), `logsource` (product, category, service), `detection` (selection, condition), `falsepositives`, `level`. -->

## Writing a detection rule

<!-- TODO: Identify the log source (web server access log, endpoint EDR, Windows event log). Define the selection keywords or field conditions that indicate exploitation. Set the condition. Validate with `sigma check`. Compile with `sigma convert`. -->

{{< tabs >}}
{{< tab name="Web server log" >}}
```yaml
title: CVE-XXXX-XXXX Path Traversal Attempt
id: a1b2c3d4-0000-0000-0000-000000000001
status: experimental
description: Detects path traversal exploit attempts against CVE-XXXX-XXXX
author: vuln-coordinator
date: 2026-05-14
tags:
  - attack.initial_access
  - attack.t1190
logsource:
  category: webserver
detection:
  selection:
    cs-uri-stem|contains: '/../'
  condition: selection
falsepositives:
  - Legitimate URL encoding edge cases
level: high
```
{{< /tab >}}
{{< tab name="Windows event log" >}}
```yaml
title: CVE-XXXX-XXXX Exploitation via Privilege Escalation
id: a1b2c3d4-0000-0000-0000-000000000002
status: test
description: Detects post-exploitation activity from CVE-XXXX-XXXX on Windows
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: '\vulnerable_service.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
  condition: selection
level: critical
```
{{< /tab >}}
{{< tab name="Convert to Splunk" >}}
```bash
# Compile Sigma rule to Splunk SPL
sigma convert \
  --target splunk \
  --pipeline splunk_windows \
  CVE-XXXX-XXXX-detection.yaml
```
{{< /tab >}}
{{< tab name="Convert to Elastic" >}}
```bash
# Compile Sigma rule to Elastic Query DSL
sigma convert \
  --target elasticsearch \
  --pipeline ecs_windows \
  CVE-XXXX-XXXX-detection.yaml
```
{{< /tab >}}
{{< /tabs >}}

## Testing the rule

<!-- TODO: Using `sigma check` for syntax validation. Testing compiled queries against sample log data in your SIEM. Using `evtx2es` or similar tools to replay event logs. -->

## OpenVEX outcome

<!-- TODO: OpenVEX statement with `workaround_available`, Sigma rule UUID + SIEM deployment reference, CVE, and detection confidence. -->
