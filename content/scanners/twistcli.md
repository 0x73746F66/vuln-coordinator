---
title: "Prisma Cloud (twistcli)"
description: "Palo Alto Networks Prisma Cloud Compute — twistcli CLI for build-time image / repo / serverless / IaC scans; Prisma Defender for runtime."
weight: 95
---

> **Commercial** · Palo Alto Networks · `twistcli` CLI + Prisma Defender runtime agent · [Docs](https://docs.prismacloud.io/) · companion: Prisma Defender (runtime)

`twistcli` is the build-time scanner for Prisma Cloud Compute (formerly Twistlock). One binary covers four scan modes — `twistcli images scan` (container image), `twistcli repository scan` (filesystem / SCM checkout), `twistcli serverless scan` (zipped Lambda / Azure-Functions bundles), and `twistcli iac scan` (Terraform / CloudFormation / k8s manifests). Every mode talks to the same Prisma Console, which holds the **Prisma Intelligence Stream** (PANW's commercial-curated vulnerability feed — NVD + GHSA + distro feeds + first-party exploit-intel) and the policy that decides whether a scan passes or fails.

The runtime sibling is **Prisma Defender**: a DaemonSet (Kubernetes) or host agent (VM / serverless) that watches the same workloads in production and emits incidents back to the Console. Build-time and runtime share the Intelligence Stream, but the lifecycle phases are different — twistcli is what runs in your pipeline; Defender is what watches the running container. The distinctive feature of the Prisma stack relative to the other tools on this site is **runtime feedback flowing back into the build-time picture** via Console: a `not_affected` triage decision at build-time that gets contradicted by a Defender incident in production is the strongest signal you can get that the assumption was wrong. Most build-time scanners have no equivalent signal.

This page covers the build-time twistcli workflow. Defender is treated as adjacent context — you need to know it exists, and what events it produces, but the triage workflow lives in twistcli's JSON.

## What twistcli finds in JSON

```bash
# Scan a container image — the most common mode
twistcli images scan \
  --address https://console.example.com \
  --output-file scan.json \
  --details \
  ghcr.io/yourorg/myapp:2.3.0

# Or a filesystem / repo checkout
twistcli repository scan \
  --address https://console.example.com \
  --output-file scan.json \
  --details \
  .

# Or a serverless bundle
twistcli serverless scan \
  --address https://console.example.com \
  --output-file scan.json \
  --details \
  lambda-bundle.zip
```

Top-level shape (`twistcli images scan`):

```json
{
  "results": [{
    "id": "sha256:...",
    "name": "ghcr.io/yourorg/myapp:2.3.0",
    "distro": "Debian GNU/Linux 12 (bookworm)",
    "vulnerabilities": [ /* one per CVE match */ ],
    "compliance": [ /* one per compliance rule fired */ ],
    "packages": [ /* every installed package, OS + language */ ],
    "complianceScanPassed": false,
    "vulnerabilityScanPassed": false
  }],
  "consoleURL": "https://console.example.com/#!/monitor/vulnerabilities/..."
}
```

Per-vulnerability fields:

| Field | Purpose |
|---|---|
| `id` | CVE / GHSA / vendor advisory ID |
| `cve` | The CVE if known (sometimes empty for vendor-only advisories) |
| `severity` | `critical` / `high` / `medium` / `low` |
| `cvss` | Numeric score (PANW's blend — usually NVD primary) |
| `vecStr` | CVSS vector string |
| `status` | `fixed in N.N.N` / `not fixed` / `deferred` |
| `fixDate` | Unix timestamp of when the upstream fix landed (handy for patch-lag analysis) |
| `riskFactors` | **Prisma-specific** heuristic blend — string keys: `Exploit exists`, `Attack vector: network`, `Has fix`, `DoS`, `Remote execution`, `Recent vulnerability`, `Recent vulnerability with fix` |
| `packageName` + `packageVersion` | The matched component |
| `layerTime` | Image-layer timestamp where the package landed (Class-A vs Class-C disambiguation) |
| `link` | Vendor advisory URL |
| `riskFactorsScore` | Composite of `riskFactors` (Prisma's priority signal — closest peer to a single-axis CWSS) |

`riskFactors` is the field that distinguishes Prisma's output from every other SCA scanner on this site. It is **not CVSS, not EPSS, and not a maturity label** — it is a small composite of seven heuristic flags that Prisma's analysts attach to each advisory. It is the closest commercial peer to Vulnetix's `x_threatExposure`, but it is a single bag-of-strings rather than a structured object: you parse the strings, not a schema.

Per-compliance fields:

| Field | Purpose |
|---|---|
| `id` | Prisma rule ID (e.g. `41` for "Image should be scanned for vulnerabilities", `425` for "Container should not run as root") |
| `title` | Human-readable rule name |
| `severity` | `critical` / `high` / `medium` / `low` |
| `cause` | Why it fired (e.g. the offending Dockerfile line) |
| `category` | `Docker` / `Kubernetes` / `Linux` / `Custom` |

Prisma ships ~200 built-in compliance rules across CIS Docker, CIS Kubernetes, NIST 800-190, and custom rule packs. They're the closest commercial peer to Vulnetix's [`VNX-DOCKER-*` rules](vulnetix/containers/) — but where Vulnetix is open-source and the rule list is enumerable in the docs, Prisma's compliance pack is closed and shifts with Console releases.

## Querying with jq

```bash
# Every vulnerability flattened
jq '.results[0].vulnerabilities[] | {
      id, cve,
      severity,
      cvss,
      pkg: .packageName,
      ver: .packageVersion,
      fix: .status,
      risk: .riskFactors
    }' scan.json

# Critical + High only — the gating triage queue
jq '.results[0].vulnerabilities[]
    | select(.severity == "critical" or .severity == "high")
    | {id, pkg: .packageName, ver: .packageVersion, risk: .riskFactors}' \
   scan.json

# Pull the Prisma-specific risk flags — the signal you can't get from other scanners
jq '.results[0].vulnerabilities[]
    | select(.riskFactors | has("Exploit exists") or has("Remote execution"))
    | {id, severity, risk: (.riskFactors | keys)}' scan.json

# Group by component — which deps generate most noise?
jq '[.results[0].vulnerabilities[] | {pkg: .packageName}]
    | group_by(.pkg)
    | map({pkg: .[0].pkg, count: length})
    | sort_by(-.count)' scan.json

# Compliance findings only
jq '.results[0].compliance[]
    | select(.severity == "critical" or .severity == "high")
    | {id, title, cause}' scan.json
```

## First: identify the finding class

A twistcli finding from a container scan falls into the same A/B/C/D classes as a [Grype](grype/#first-identify-the-finding-class) finding — the workflows are identical at the conceptual level. The differences are in *how you classify* with twistcli's JSON:

### Class A — OS package finding (base layer)

Read `packages[]` for the matching `packageName` — its `pkgsType` is `package` for OS packages, `nodejs` / `python` / `gem` / `jar` / `go` for language ecosystems. Twistcli does not emit PURLs in the vulnerability record itself; you cross-reference into `packages[]` by name + version:

```bash
jq '.results[0].vulnerabilities[]
    | . as $v
    | $v + {pkg_type:
              ([$.results[0].packages[]
                | select(.name == $v.packageName)
                | .pkgsType] | first)}
    | select(.pkg_type == "package")
    | {id, pkg: .packageName, ver: .packageVersion, layer: .layerTime}' \
   scan.json
```

Fix paths: base-image tag bump, distro package upgrade during build, or migrate to a hardened base. The mechanics match [Grype Class A](grype/#class-a--fix-mechanics) — Prisma surfaces `fixDate` so you can see how long a fix has been available before deciding to bump.

### Class B — language ecosystem finding

`pkgsType` is `nodejs` / `python` / `gem` / `jar` / `go`. Pivot to the [package managers appendix](../appendices/package-managers/) using the language hint. Twistcli does not report the manifest path the way Grype does (`artifact.locations[]`) — to find which file inside the image carries the package, fall back to image archaeology (`docker history` + `find <image-rootfs> -name <manifest>`).

### Class C — multi-stage leakage

Twistcli scans the image you point it at; if that image is an intermediate build stage, the finding may belong to a transient build-only tool. Always scan the runtime image (`docker build --target=runtime -t myapp:runtime` then `twistcli images scan myapp:runtime`).

### Class D — vendored OS package

Same as Grype — detect via `docker history --no-trunc <image>` for `RUN dpkg -i` referencing a `COPY`'d file.

## Compliance findings

`results[0].compliance[]` is where Prisma's Dockerfile / runtime-config / CIS findings land. Treat these as the analogue of [Vulnetix's `VNX-DOCKER-*` rules](vulnetix/containers/):

```bash
# CIS Docker rule 425 — "Container should not run as root"
jq '.results[0].compliance[] | select(.id == 425)' scan.json
```

Compliance findings are not CVE-scoped, so they map to **OpenVEX** (not CycloneDX VEX) when you decide to record a triage — the subject is the image, not a PURL component.

## From finding to root cause

twistcli supplies a different blend of signals than the OSS scanners. The Engineer Triage inputs from a twistcli scan:

- **Reachability** — twistcli does not surface call-graph or function-level data. Use the package-level cross-reference from `packages[]` + an `ldd` check (as on the [Grype page](grype/#from-finding-to-root-cause)). For Tier-2 / Tier-3 evidence, cross-reference [Vulnetix VDB](../appendices/glossary/#vulnetix-vdb) via `vulnetix vdb vuln`.
- **Remediation Option** — read `status` and `fixDate`. `fixed in X.Y.Z` plus a recent `fixDate` → `PATCHABLE_DEPLOYMENT`. `not fixed` → `PATCH_UNAVAILABLE`. `deferred` → vendor declined to patch → `NO_PATCH`.
- **Mitigation Option** — `AUTOMATION` for app deps, `INFRASTRUCTURE` for OS-layer issues. Prisma Defender can serve as an `INFRASTRUCTURE` mitigation in its own right when the runtime ruleset blocks the exploit chain — see *From build-time to runtime* below.
- **Priority** — `severity` + `cvss` + `riskFactors`. The flag combinations that should escalate:
  - `Exploit exists` + `Attack vector: network` + `Remote execution` → treat as if `Active Exploitation` in SSVC terms, even without an explicit EPSS / KEV signal.
  - `Has fix` + `Recent vulnerability` → fast-track patching window.
- **KEV / EPSS / SSVC** — not native. Cross-reference `vulnetix vdb vuln <CVE>` for these signals; they belong in your Coordinator-decision step. Prisma's `riskFactors` is not a substitute — it's a heuristic blend without the structured exploit-intel of KEV / EPSS.

See [SSVC Engineer Triage](../appendices/ssvc/) for the decision tree.

## Patching mechanics

Pick the workflow that matches the finding class:

- **Class A** — base-image tag bump / distro package upgrade in build / migrate to hardened base. See [Grype Class A — fix mechanics](grype/#class-a--fix-mechanics).
- **Class B** — SCA in source. See the [package managers appendix](../appendices/package-managers/).
- **Class C** — confirm runtime stage; then Class A or B for the carrying stage.
- **Class D** — update the vendored `.deb` / `.rpm` / `.apk` in source.

## From build-time to runtime: Prisma Defender

Defender runs as a DaemonSet (Kubernetes), host agent (VM), or extension (AWS Lambda / Azure Functions). It watches the same workload that twistcli scanned in CI and emits incidents to the Console when the runtime model fires. The Console's incident API exposes them:

```bash
# Console API — auth via the same token twistcli uses
curl -H "Authorization: Bearer $PRISMA_TOKEN" \
  "https://console.example.com/api/v1/audits/incidents?from=$(date -d '7 days ago' +%s)000"

# Or runtime audits — every process / network event
curl -H "Authorization: Bearer $PRISMA_TOKEN" \
  "https://console.example.com/api/v1/audits/runtime/container"
```

Incident JSON shape (representative):

```json
{
  "type": "container",
  "severity": "high",
  "attackType": "Lateral movement",
  "containerId": "...",
  "imageName": "ghcr.io/yourorg/myapp:2.3.0",
  "processName": "/usr/bin/curl",
  "msg": "Suspicious binary executed against an internal IP",
  "time": "2026-05-14T10:00:00Z"
}
```

The triage feedback loop matters: if you wrote a `not_affected` VEX at build-time for a CVE and Defender later flags an incident on the same image that maps to that CVE's `attackType`, the VEX assumption is wrong — escalate, re-triage, and (most likely) flip the status to `affected`. This is what makes Prisma's stack distinctive: build-time alone is half the picture, and Defender closes the loop.

Defender's runtime ruleset is a closed format — it does not produce Snort / YARA / Nuclei / Sigma rules you can take elsewhere. If you need open-format detection content for a CVE, see the [rules section](../rules/) of this site or `vulnetix vdb` / `vulnetix:detection-rules`.

## Decision tree

{{< decision >}}
twistcli vulnerability findings carry a package-name + version, not a PURL.
Construct the PURL from packageName + packageVersion + distro:

  For OS packages (pkgsType=package):
    → pkg:deb/debian/<name>@<version>?distro=debian-12
    → pkg:apk/alpine/<name>@<version>?distro=alpine-3.20
    → pkg:rpm/redhat/<name>@<version>?distro=rhel-9

  For language packages:
    → pkg:npm/<name>@<version>
    → pkg:pypi/<name>@<version>
    → pkg:maven/<group>/<artifact>@<version>

For PURL-backed vulnerabilities:
  → CycloneDX VEX entry referencing the constructed PURL

For compliance findings (no PURL — subject is the image, not a component):
  → OpenVEX statement with the image digest as the product @id

Need a runtime mitigation while the upgrade is in flight?
  → Defender custom runtime rule via Console (closed format)
  → Or vulnetix vdb traffic-filters <CVE> for an open-format equivalent
{{< /decision >}}

## Worked example: CVE-2023-50387 (KeyTrap DNSSEC) on `libbind9-9` in a `node:20-bookworm` base image

twistcli flags `libbind9-9` at version `1:9.18.19-1~deb12u1` in `ghcr.io/yourorg/api:v3.4.0` (which uses `node:20-bookworm`). The match record:

```json
{
  "id": "CVE-2023-50387",
  "cve": "CVE-2023-50387",
  "severity": "high",
  "cvss": 7.5,
  "vecStr": "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
  "status": "fixed in 1:9.18.28-1~deb12u2",
  "fixDate": 1718668800,
  "riskFactors": {
    "Attack vector: network": {},
    "Has fix": {},
    "Recent vulnerability with fix": {}
  },
  "packageName": "libbind9-9",
  "packageVersion": "1:9.18.19-1~deb12u1",
  "layerTime": 1707436800,
  "link": "https://security-tracker.debian.org/tracker/CVE-2023-50387"
}
```

`riskFactors` carries `Attack vector: network` + `Has fix` + `Recent vulnerability with fix` — the fix has landed upstream, the vulnerability is network-accessible, but **no `Exploit exists` flag**. CVSS 7.5, severity `high`. Reachability check: does any binary in the Node base image link against `libbind9-9`?

```bash
# Library name + version pulled from scan.json — not typed by hand
LIB=$(jq -r '.results[0].vulnerabilities[]
              | select(.id=="CVE-2023-50387")
              | .packageName' scan.json | head -1)

# Symbol-level supplement from VDB (twistcli's JSON has no function-level data)
ROUTINES=$(vulnetix vdb vuln CVE-2023-50387 --output json \
  | jq -r '.[0].containers.adp[0].x_affectedRoutines[]?
           | select(.kind=="function") | .name')

# Walk the image and check linkage
docker run --rm --entrypoint sh ghcr.io/yourorg/api:v3.4.0 \
  -c "find / -type f -executable 2>/dev/null \
      | xargs -I{} sh -c 'ldd {} 2>/dev/null | grep -l \"$LIB\" && echo {}'" \
  | sort -u
```

If no binary links against `libbind9-9` (Node doesn't use BIND's resolver; the package was pulled in as a dpkg transitive of something that doesn't exercise the vulnerable code), `Reachability: VERIFIED_UNREACHABLE` is honest. Engineer Triage: `Remediation: PATCHABLE_DEPLOYMENT` (next base-image bump picks up the fix), `Mitigation: AUTOMATION`, `Priority: HIGH` — outcome `NIGHTLY_AUTO_PATCH`.

Write the CycloneDX VEX entry (twistcli does not consume VEX directly — suppression lives in the Prisma Console dashboard as a manual exception — but downstream tools and audit consumers want it):

{{< outcome type="cyclonedx" >}}
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "vulnerabilities": [{
    "id": "CVE-2023-50387",
    "source": { "name": "NVD" },
    "affects": [{
      "ref": "pkg:deb/debian/libbind9-9@1%3A9.18.19-1~deb12u1?distro=debian-12",
      "versions": [{ "version": "1:9.18.19-1~deb12u1", "status": "affected" }]
    }],
    "analysis": {
      "state": "not_affected",
      "justification": "code_not_reachable",
      "detail": "Engineer Triage: NIGHTLY_AUTO_PATCH. libbind9-9 is in node:20-bookworm as a transitive dpkg dependency; no binary in the runtime image links against it (verified via ldd walk). twistcli riskFactors: 'Attack vector: network' + 'Has fix' + 'Recent vulnerability with fix' — no 'Exploit exists' flag. Will pick up the fix automatically when the base image is bumped past 1:9.18.28."
    }
  }]
}
```
{{< /outcome >}}

And the parallel OpenVEX statement (for any tools in your pipeline that prefer that format — Grype's `--vex`, public attestation consumers):

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-twistcli-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T10:00:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": { "name": "CVE-2023-50387" },
    "products": [{
      "@id": "pkg:deb/debian/libbind9-9@1%3A9.18.19-1~deb12u1?distro=debian-12"
    }],
    "status": "not_affected",
    "justification": "vulnerable_code_not_in_execute_path",
    "action_statement": "Engineer Triage: NIGHTLY_AUTO_PATCH. Mirrors the CycloneDX VEX entry — Prisma Console retains the matching exception."
  }]
}
```
{{< /outcome >}}

Suppress the finding in the Prisma Console via the **Vulnerabilities → Exceptions** UI (or the `/api/v1/policies/vulnerability` endpoint) so the next twistcli scan does not re-fire the gate. Keep the VEX entries in source alongside the exception — the Console state is per-tenant, the VEX is portable.

If Defender later flags an incident on `ghcr.io/yourorg/api:v3.4.0` with `attackType: "DNS amplification"` or a DNSSEC-related process anomaly, treat the `not_affected` VEX as falsified and re-triage.

## Developer gotchas — written for people who write code, not Dockerfiles

- **The Console / Defender split means a clean twistcli pass is not the full picture.** Defender incidents live in a different API. A build-time `PASS` plus a Defender `high` incident on the same image is the contradiction Prisma exists to surface — wire both into the same dashboard if you want one source of truth.

- **`riskFactors` is Prisma-specific and doesn't map 1:1 to CVSS or EPSS.** Treat it as a heuristic blend that escalates priority, not as an exploit-intel feed. Cross-reference `vulnetix vdb vuln <CVE>` for separated `x_epss`, `x_kev`, `x_exploitationMaturity` if you need the structured signals.

- **`twistcli images scan --containerized` vs `--docker-address` are different attach modes.** `--containerized` reads `/var/run/docker.sock` from inside a running container; `--docker-address` reaches a remote Docker daemon. Misconfigure and twistcli silently scans the wrong target — always check `results[].name` against the image you meant to scan.

- **`twistcli` exits non-zero based on `--vulnerability-threshold` / `--compliance-threshold`, not the JSON.** CI gating is via the exit code; the JSON is for triage downstream. If your CI green-lights a build, that doesn't mean the JSON is clean — it means it cleared *the threshold you set*.

- **Licence enforcement is fail-closed.** Expired Prisma licence → twistcli refuses to scan → CI breaks. Plan licence renewal cycles with the same lead time as cert renewals.

- **SBOM emission is a different subcommand.** `twistcli sbom --output cdx.json` emits CycloneDX 1.4. `twistcli images scan --output-file scan.json` is *not* an SBOM — it's a scan report. Two outputs, two ingestion paths. If you want both, run twistcli twice.

- **PURLs are not in the scan output.** Construct them from `packageName` + `packageVersion` + image `distro`. The decision tree above gives the recipes; build them into your scan post-processing script rather than hand-typing.

- **Defender events are not in `scan.json`.** They live in `https://console.example.com/api/v1/audits/incidents`. A unified triage picture needs ingestion from both endpoints — there is no single twistcli-emitted file that includes runtime context.

- **The Console policy can suppress findings the JSON still lists.** twistcli's `--output-file` returns the *scan result before policy filtering*. The Console UI shows the *policy-filtered* view. Numbers will differ; the JSON is authoritative for triage decisions, the Console for compliance dashboards.

## Producing a VEX

PURL-backed vulnerability findings → CycloneDX VEX (construct the PURL from `packageName` + `packageVersion` + image `distro`).

Compliance findings (`results[].compliance[]`) → OpenVEX with the image digest as the product `@id` — they're not component-scoped.

Defender runtime incidents → not VEX material. They're operational telemetry; record them in the SIEM or in the engineer-triage memo, not in a VEX statement.

## Capability snapshot

See the [capability matrix](../#capability-matrix) for the full comparison. twistcli / Prisma's row in summary:

- **Coverage**: SCA (image + repo + serverless), IaC (Terraform / CloudFormation / k8s), secrets (limited regex), Dockerfile compliance (~200 CIS rules). No native SAST. DAST out of scope.
- **[Database quality](../#database-quality-tiers)**: Prisma Intelligence Stream — commercial-curated, NVD + GHSA + distro feeds + first-party exploit-intel. Sits between OSV (Sufficient) and Vulnetix VDB (Full coverage) — better exploit-intel than OSV via `riskFactors`, less AI / sightings / weaponisation enrichment than Vulnetix.
- **[Reachability](../appendices/reachability-deep-dive/)**: **Tier 1** — package-level. No call-graph. Defender provides Tier-1.5 *runtime* evidence, orthogonal to the static three-tier model.
- **Exploit maturity**: `riskFactors` heuristic (PANW-curated string flags), not EPSS / KEV / SSVC. Cross-reference VDB.
- **[EOL](../appendices/eol/)**: native via Intelligence Stream — surfaces distro EOL and base-image lifecycle.
- **[Supply-chain threats](../appendices/supply-chain-threats/)**: reactive only (`MAL-` via feed). No proactive typosquat / maintainer-health.
- **Outputs**: JSON (rich, native), [SARIF](../appendices/sarif/) (`--output-format sarif`), JUnit, CycloneDX 1.4 (via `twistcli sbom`). VEX consumption is via Console exception UI (proprietary), not file-based.

## See also

- [Capability matrix](../#capability-matrix) — twistcli's column in context.
- [Grype](grype/) — open-source image-binary peer; the A/B/C/D class model on this page is the same framework.
- [Vulnetix containers](vulnetix/containers/) — open-source Dockerfile-rule peer for the `results[].compliance[]` shape.
- [Reachability deep-dive](../appendices/reachability-deep-dive/) — what Tier-1 evidence supports, and when you need Tier 2/3 (Defender runtime is Tier-1.5, separate axis).
- [EOL appendix](../appendices/eol/) — base-image migration decisions Prisma's `Recent vulnerability` heuristic alone can't drive.
- [Glossary](../appendices/glossary/) — definitions for the terms used above.
