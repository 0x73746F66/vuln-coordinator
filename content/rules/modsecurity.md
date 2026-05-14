---
title: "ModSecurity — WAF"
description: "Write ModSecurity rules to mitigate web application vulnerabilities, then reference them in a VEX statement."
weight: 10
---

## Overview

ModSecurity is an open-source web application firewall (WAF) engine. Rules written in the SecRule language can block or log HTTP requests that match known attack patterns — SQL injection, XSS, path traversal, and more.

When a vulnerability in your application is mitigated by a ModSecurity rule (rather than a code fix), you can document that mitigation in an OpenVEX statement. The rule becomes the evidence that the risk is managed, even if the underlying code is not yet patched.

**Outcome type:** OpenVEX — WAF rules are not SBOM components, so CycloneDX VEX does not apply.

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
