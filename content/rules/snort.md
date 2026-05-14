---
title: "Snort — IPS"
description: "Block the exploit packet at the network edge, then attest to the mitigation in OpenVEX."
weight: 20
---

## What Snort does

Snort sits in the network path — inline as an IPS or out-of-band as an IDS — and matches packets against rules written in the Snort rule language. A rule that matches can pass the traffic, log it, alert on it, or drop it.

For vulnerability management the angle is narrow. When the exploit for a CVE has a recognisable wire signature — a specific URI fragment, header, payload, or protocol misuse — a Snort rule that drops the traffic before it reaches the vulnerable service is a valid mitigation. The Snort SID and the deployment location become the evidence in an OpenVEX statement.

IPS rules aren't SBOM components, so the attestation is always OpenVEX.

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
