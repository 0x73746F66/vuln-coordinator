---
title: "Suricata — IPS"
description: "Block the exploit at the network layer with protocol-aware rules, then attest to it in OpenVEX."
weight: 30
---

> **OSS** (GPL-2.0) · OISF · [OISF/suricata](https://github.com/OISF/suricata) · [Docs](https://suricata.io/documentation/) · Rule sources: [Emerging Threats](https://rules.emergingthreats.net/), Talos · `vulnetix vdb traffic-filters <CVE>` returns Snort/Suricata-compatible signatures.

## What Suricata does

Suricata is a multi-threaded network IDS / IPS / NSM engine. Its rule language reads like Snort's but extends it with protocol-aware sticky buffers — `http.uri`, `http.header`, `tls.sni`, `dns.query`, `smb.command` — which let you write rules that match against the parsed application layer rather than the raw bytes.

For vulnerability management the use case mirrors Snort's: when the exploit has a recognisable wire signature, a Suricata rule that drops it before it reaches the vulnerable service is a valid mitigation. Where Suricata earns its place over Snort is the protocol awareness — matching on `http.uri` is more precise (and survives encoding tricks) than matching on raw `content`.

IPS rules aren't SBOM components, so the attestation is always OpenVEX.

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


## See also

- [SSVC Engineer Triage](../../appendices/ssvc/) — the framework that maps a rule deployment to the `Mitigation Option` input.
- [OpenVEX appendix](../../appendices/openvex/) — the format these rule guides produce.
- [Glossary](../../appendices/glossary/).
