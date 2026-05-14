---
title: "Suricata — IPS"
description: "Write Suricata rules to detect and block network exploitation attempts, then reference them in a VEX statement."
weight: 30
---

## Overview

Suricata is a high-performance, multi-threaded network IDS/IPS/NSM engine. Its rule language is largely compatible with Snort but extends it with additional keywords for protocol-aware inspection (HTTP, TLS, DNS, SMB, and more).

When a vulnerability is blocked at the network level by a Suricata rule, that control can be referenced in an OpenVEX statement as evidence of risk management.

**Outcome type:** OpenVEX.

## Rule structure

<!-- TODO: Suricata rule anatomy. Similarities to Snort. Key differences: `http.uri`, `http.header`, `tls.sni`, `dns.query` sticky buffers; `flow` keyword; `pcre` with Suricata PCRE syntax. -->

## Writing a mitigation rule

<!-- TODO: Select the correct application-layer buffer for the protocol. Write the rule. Test with `suricata -T`. Enable in IPS mode (`-q 0` with NFQueue or AF_PACKET). -->

{{< tabs >}}
{{< tab name="HTTP URI match" >}}
```suricata
alert http any any -> $HOME_NET any (
  msg:"CVE-XXXX-XXXX — path traversal attempt";
  http.uri; content:"/../"; nocase;
  sid:2000001; rev:1;
  classtype:web-application-attack;
  metadata:vuln-coordinator CVE-XXXX-XXXX;
)
```
{{< /tab >}}
{{< tab name="HTTP header match" >}}
```suricata
alert http any any -> $HOME_NET any (
  msg:"CVE-XXXX-XXXX — malicious header";
  http.header; content:"X-Exploit:"; nocase;
  sid:2000002; rev:1;
  classtype:attempted-user;
)
```
{{< /tab >}}
{{< tab name="TLS SNI match" >}}
```suricata
alert tls any any -> any any (
  msg:"Suspicious TLS SNI — C2 indicator";
  tls.sni; content:"malicious.example.com"; nocase;
  sid:2000003; rev:1;
  classtype:trojan-activity;
)
```
{{< /tab >}}
{{< /tabs >}}

## Testing the rule

<!-- TODO: `suricata -T -c suricata.yaml -S local.rules` for validation. Replay pcap with `suricata -r <pcap>`. -->

## OpenVEX outcome

<!-- TODO: OpenVEX with `workaround_available`, Suricata SID reference, CVE, deployment location. -->
