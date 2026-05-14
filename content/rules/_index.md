---
title: "Rules writing"
description: "Write the WAF, IPS, detection, or SIEM rule — then attest to the mitigation in OpenVEX."
weight: 20
---

Sometimes the right answer to a vulnerability isn't a code fix. A WAF rule blocks the attack vector. An IPS signature drops the exploit packet. A YARA rule catches the payload on disk. A Sigma rule alerts the moment an attempt hits your logs. Each is a valid response, but only when the mitigation is documented somewhere a scanner can read.

These guides cover the rule syntax for each platform, how to test the rule does what you claim, and how to reference the deployed rule in an OpenVEX statement so the next scanner run knows the finding is handled.
