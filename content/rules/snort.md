---
title: "Snort — IPS"
description: "Write Snort rules to detect and block network-level exploitation attempts, then reference them in a VEX statement."
weight: 20
---

## Overview

Snort is an open-source intrusion prevention system (IPS). Rules written in the Snort rule language inspect network traffic and can alert on or block packets that match known exploit patterns.

When a vulnerability in a service you operate is mitigated by a Snort rule — blocking the network vector an attacker would use — that mitigation can be documented in an OpenVEX statement. The Snort rule SID becomes the reference evidence.

**Outcome type:** OpenVEX — IPS rules are not SBOM components.

## Rule structure

<!-- TODO: Anatomy of a Snort rule: action protocol src_ip src_port direction dst_ip dst_port (options). Header fields, rule options (msg, content, pcre, sid, rev, classtype). -->

## Writing a mitigation rule

<!-- TODO: Identify the network-level attack vector (port, protocol, payload pattern). Write a rule targeting that vector. Test with `snort -T`. Deploy to the IPS. -->

{{< tabs >}}
{{< tab name="Content match" >}}
```snort
alert tcp any any -> $HOME_NET 8080 (
  msg:"CVE-XXXX-XXXX exploit attempt blocked";
  content:"/../etc/passwd"; nocase;
  sid:1000001; rev:1;
  classtype:attempted-user;
  metadata:vuln-coordinator CVE-XXXX-XXXX;
)
```
{{< /tab >}}
{{< tab name="PCRE match" >}}
```snort
alert http any any -> $HTTP_SERVERS $HTTP_PORTS (
  msg:"CVE-XXXX-XXXX — malformed header exploit";
  pcre:"/X-Exploit:\s*[0-9]{50,}/i";
  sid:1000002; rev:1;
  classtype:web-application-attack;
)
```
{{< /tab >}}
{{< /tabs >}}

## Testing the rule

<!-- TODO: Using `snort -r <pcap>` to replay captured traffic and verify the rule fires. Using `snort -T` for syntax validation. -->

## OpenVEX outcome

<!-- TODO: OpenVEX statement with `workaround_available`, referencing the Snort SID, the CVE, and the deployment location. -->
