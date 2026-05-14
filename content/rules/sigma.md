---
title: "Sigma — SIEM"
description: "Write Sigma rules to detect exploitation activity in logs, then reference them in a VEX statement."
weight: 60
---

## Overview

Sigma is a generic, vendor-neutral signature format for SIEM detection rules. A single Sigma rule can be compiled to Splunk SPL, Elastic Query DSL, Microsoft Sentinel KQL, QRadar AQL, and many other backends using the `sigma-cli` tool.

In vulnerability management, Sigma rules serve as **detection-layer evidence**: deploying a rule that alerts on exploitation attempts proves that you have visibility into any attack against the vulnerability. This supports an OpenVEX `workaround_available` justification alongside (or instead of) a WAF/IPS mitigation.

**Outcome type:** OpenVEX — SIEM detection rules are not SBOM components.

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
