---
title: "Nuclei — Detection (attacker simulation)"
description: "Confirm whether the exploit actually works, then let the result drive the VEX decision."
weight: 50
---

> **OSS** (MIT) · ProjectDiscovery · [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) · [Docs](https://docs.projectdiscovery.io/tools/nuclei) · Template library: [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) (MIT) · `vulnetix vdb nuclei get <CVE>` returns CVE-keyed templates ready for `nuclei -t -`.

## What Nuclei does

Nuclei probes a running target with crafted requests and decides — by matching the response against template-defined matchers — whether the target is vulnerable. Where YARA inspects files at rest on a defender's systems, Nuclei plays the attacker's part: send the request, watch the response, declare a verdict.

It earns two places in vulnerability management. First, before triage: run a Nuclei template against your environment to confirm a scanner finding is a true positive, not a CPE match against unreachable code. Second, after mitigation: re-run the template to prove a WAF rule, a patch, or a config change actually closes the vector.

A Nuclei result informs the VEX decision but doesn't generate the VEX itself. A confirmed exploit drives `affected` (or `fixed`, after you ship the patch). A blocked exploit — where the rule fires and the response no longer matches — drives `affected` with `workaround_available`. A negative result on a true vulnerable build supports `not_affected` with a sharper justification, typically `vulnerable_code_cannot_be_controlled_by_adversary` or `vulnerable_code_not_present`.

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


## See also

- [SSVC Engineer Triage](../../appendices/ssvc/) — the framework that maps a rule deployment to the `Mitigation Option` input.
- [OpenVEX appendix](../../appendices/openvex/) — the format these rule guides produce.
- [Glossary](../../appendices/glossary/).
