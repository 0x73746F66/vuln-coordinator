---
title: "ModSecurity — WAF"
description: "Block the attack vector at the WAF, then attest to the mitigation in OpenVEX."
weight: 10
---

## What ModSecurity does

ModSecurity inspects HTTP requests before they reach your application and decides — by way of rules written in the SecRule language — whether to block, log, or allow. It runs as a module inside Apache, nginx, or as a standalone library in front of any reverse proxy.

For vulnerability management it serves one purpose. When a CVE in your application can be exploited via an identifiable request pattern, a ModSecurity rule that blocks that pattern is a valid mitigation. You record the mitigation in an OpenVEX statement and the rule itself — its ID, its version, and where it's deployed — becomes the evidence.

WAF rules aren't SBOM components, so the attestation is always OpenVEX, never CycloneDX VEX.

## Rule structure

<!-- TODO: Anatomy of a SecRule directive: SecRule TARGET OPERATOR [ACTIONS]. Variables, operators, transformations, actions (deny, log, pass). -->

## Writing a mitigation rule

<!-- TODO: Step-by-step example — identify the attack vector from the scanner finding, write the SecRule to block it, test with `--test-rules`, deploy to your WAF. -->

{{< tabs >}}
{{< tab name="Block by pattern" >}}
```apache
# Block requests exploiting a path traversal in /api/files
SecRule REQUEST_URI "@contains /api/files" \
    "id:10001,phase:1,deny,status:403,\
    msg:'Path traversal blocked — CVE-XXXX-XXXX mitigation',\
    tag:'vuln-coordinator/CVE-XXXX-XXXX'"
```
{{< /tab >}}
{{< tab name="Block by payload" >}}
```apache
# Block SQL injection pattern in query string
SecRule ARGS "@detectSQLi" \
    "id:10002,phase:2,deny,status:400,\
    msg:'SQL injection blocked — CVE-XXXX-XXXX mitigation',\
    tag:'vuln-coordinator/CVE-XXXX-XXXX'"
```
{{< /tab >}}
{{< /tabs >}}

## Testing the rule

<!-- TODO: How to use `modsecurity-cli` or a test harness to verify the rule triggers on malicious input and does not fire on legitimate traffic. -->

## OpenVEX outcome

<!-- TODO: OpenVEX statement referencing the rule ID, the CVE, justification `workaround_available`, and a pointer to the deployed rule. -->
