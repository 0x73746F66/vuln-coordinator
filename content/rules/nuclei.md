---
title: "Nuclei — Detection (attacker simulation)"
description: "Write Nuclei templates to verify whether a vulnerability is exploitable, then use the result to drive your VEX decision."
weight: 50
---

## Overview

Nuclei is a fast, template-driven vulnerability scanner used for attacker-side simulation. Unlike YARA (which detects artefacts on a defender's systems), Nuclei templates probe a live target to confirm whether a finding is actually exploitable.

In vulnerability management, Nuclei serves two purposes:

1. **Confirm exploitability** — run a Nuclei template to verify whether a scanner finding is a true positive before triaging it.
2. **Verify a mitigation** — after deploying a WAF rule or patch, re-run the template to confirm the fix holds.

**Outcome type:** The Nuclei result informs the VEX decision; it does not generate the VEX itself. A confirmed exploit → `affected` or `fixed`. A blocked exploit (WAF confirmed) → OpenVEX `workaround_available`.

## Template structure

<!-- TODO: Nuclei YAML template anatomy: `id`, `info` (name, author, severity, tags), `requests` (HTTP/TCP/DNS/code), `matchers`. -->

## Writing an exploit-verification template

<!-- TODO: Identify the HTTP request or TCP payload that triggers the vulnerability. Write a template with matchers that confirm a vulnerable response vs. a patched/blocked response. -->

{{< tabs >}}
{{< tab name="HTTP GET probe" >}}
```yaml
id: CVE-XXXX-XXXX-verify

info:
  name: CVE-XXXX-XXXX — path traversal verification
  author: vuln-coordinator
  severity: high
  tags: cve,CVE-XXXX-XXXX

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/files/../../../../etc/passwd"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "root:x:0:0"
```
{{< /tab >}}
{{< tab name="POST body probe" >}}
```yaml
id: CVE-XXXX-XXXX-sqli-verify

info:
  name: CVE-XXXX-XXXX — SQL injection verification
  severity: critical

http:
  - method: POST
    path:
      - "{{BaseURL}}/login"
    body: "user=' OR 1=1--&pass=x"

    matchers:
      - type: word
        words:
          - "Welcome"
        part: body
```
{{< /tab >}}
{{< /tabs >}}

## Running the template

<!-- TODO: `nuclei -t CVE-XXXX-XXXX-verify.yaml -u https://target.example.com`. Interpreting results. Running in CI as a post-deploy verification step. -->

## Driving VEX decisions with Nuclei results

<!-- TODO: If Nuclei confirms exploit: create `affected` VEX, prioritise fix. If Nuclei is blocked by WAF: create OpenVEX `workaround_available`. If Nuclei finds no vulnerable response: create `not_affected` VEX with `vulnerable_code_not_present` or `vulnerable_code_cannot_be_controlled_by_adversary`. -->
