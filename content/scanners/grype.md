---
title: "Grype"
description: "Anchore's vulnerability scanner — JSON / SARIF output, native OpenVEX consumption via `--vex`."
weight: 90
---

> **OSS** (Apache-2.0) · Anchore · [anchore/grype](https://github.com/anchore/grype) · [Docs](https://github.com/anchore/grype#readme) · Companion SBOM generator: [anchore/syft](https://github.com/anchore/syft)

Grype matches components against several vulnerability databases (NVD, GitHub Advisory, GitLab Advisory, OS-distribution feeds — Ubuntu USN, Alpine secdb, RedHat, Amazon ALAS, Wolfi) and runs against three input types: a container image, a directory tree, or an existing SBOM. For triage work the most useful mode is the third: `grype sbom:./sbom.cdx.json` re-scans the SBOM you already trust, with no re-resolution.

The single feature that makes Grype distinct from the other SCA tools is **native OpenVEX consumption** via `--vex` — write an OpenVEX statement once, point Grype at it, and the affected finding stops appearing in every subsequent scan. The feedback loop makes Grype the tool where OpenVEX investment pays back fastest. Note the format: `--vex` reads **OpenVEX**, not CycloneDX VEX. If you also keep a CycloneDX VEX (for tools that consume that format), maintain both.

## What Grype finds in JSON

```bash
# Scan an SBOM (the recommended path for VEX-aware triage)
grype sbom:./.vulnetix/sbom.cdx.json -o json > grype.json

# Or scan an image directly
grype ghcr.io/yourorg/myapp:2.3.0 -o json > grype.json

# Or a directory
grype dir:. -o json > grype.json
```

Top-level shape:

```json
{
  "matches": [ /* one per finding */ ],
  "ignoredMatches": [ /* suppressed by config or --vex */ ],
  "source": { /* what was scanned */ },
  "distro": { /* OS identification, if applicable */ },
  "descriptor": { /* Grype version, DB version */ }
}
```

Per-match fields:

| Field | Purpose |
|---|---|
| `matches[].vulnerability.id` | CVE / GHSA / OS-vendor advisory ID |
| `matches[].vulnerability.severity` | `Critical` / `High` / `Medium` / `Low` / `Negligible` / `Unknown` |
| `matches[].vulnerability.fix.versions[]` | Versions that include the fix |
| `matches[].vulnerability.fix.state` | `fixed` / `not-fixed` / `wont-fix` / `unknown` |
| `matches[].artifact.name` + `.version` | The matched component |
| `matches[].artifact.purl` | The PURL — direct input to a CycloneDX VEX entry |
| `matches[].artifact.locations[]` | Where the component lives in the source (file path for filesystem scans; layer digest for images) |
| `matches[].matchDetails[]` | Why Grype thinks the match is real. `matcher` is one of `javascript-matcher`, `python-matcher`, `java-matcher`, `dpkg-matcher`, `rpm-matcher`, `apk-matcher`, `go-module-matcher`, `rust-matcher`, `ruby-gem-matcher`, `dotnet-matcher`, `stock-matcher` (CPE fallback). `type` is `exact-direct-match`, `exact-indirect-match`, or `cpe-match` |
| `matches[].vulnerability.cvss[]` | CVSS vectors (`type: "Primary"` or `"Secondary"`, plus the vector string) |
| `matches[].vulnerability.epss[]` | EPSS score per scoring date |
| `matches[].relatedVulnerabilities[]` | Cross-feed aliases — typically the NVD CVE for a GHSA-flagged finding |

The `matchDetails[].type` distinguishes `exact-direct-match` (high confidence — the PURL matches an advisory's affected range exactly) from `cpe-match` (lower confidence — the match goes through a CPE lookup, sometimes producing false positives on CPE collisions).

## Querying with jq

```bash
# Every match flattened
jq '.matches[] | {
      id: .vulnerability.id,
      severity: .vulnerability.severity,
      purl: .artifact.purl,
      fix: .vulnerability.fix.versions[0],
      matcher: .matchDetails[0].matcher
    }' grype.json

# Critical + High only — the gating triage queue
jq '.matches[]
    | select(.vulnerability.severity == "Critical" or .vulnerability.severity == "High")
    | {id: .vulnerability.id, purl: .artifact.purl}' grype.json

# Distinguish CPE matches (lower confidence) from PURL matches
jq '.matches[]
    | select(.matchDetails[0].matcher | test("cpe"))
    | {id: .vulnerability.id, purl: .artifact.purl, type: "cpe-match"}' \
   grype.json

# Group by component — which deps generate most noise?
jq '[.matches[] | {purl: .artifact.purl}]
    | group_by(.purl)
    | map({purl: .[0].purl, count: length})
    | sort_by(-.count)' grype.json

# All findings the VEX already suppresses (run with --vex first)
jq '.ignoredMatches[] | {
      id: .match.vulnerability.id,
      purl: .match.artifact.purl,
      reason: .appliedIgnoreRules[0].reason
    }' grype.json
```

## First: identify the finding class

A Grype finding in a container can be one of three very different things, and each demands a different triage workflow. Read `matches[].matchDetails[].matcher` and `matches[].artifact.purl` from the JSON to classify *before* you do anything else.

### Class A — OS package finding (base layer)

`matchDetails[].matcher` is one of `dpkg-matcher`, `apk-matcher`, `rpm-matcher`, `alpine-matcher`, `wolfi-matcher`, etc. PURL scheme is `pkg:deb/`, `pkg:apk/`, `pkg:rpm/`. The package came from the base image's OS layer (`/var/lib/dpkg/status`, `/lib/apk/db/installed`, `/var/lib/rpm/Packages`).

```bash
jq '.matches[]
    | select(.matchDetails[].matcher
             | test("(dpkg|apk|rpm|alpine|wolfi)-matcher"))
    | { id: .vulnerability.id, pkg: .artifact.name, purl: .artifact.purl,
        path: .artifact.locations[0].path,
        upstream: .relatedVulnerabilities[0].id }' grype-results.json
```

The right fix is one of:
- **Upgrade the base image tag** (the common case — Debian, Ubuntu, Alpine, RHEL UBI all release patched tags on a regular cadence). Bump the `FROM` line in your Dockerfile.
- **Run the distro package manager during build** to upgrade the specific package above the base image's pinned version. See *Class A — fix mechanics* below.
- **Migrate to a maintained hardened base** if upstream is abandoned (next subsection).

### Class B — language ecosystem finding inside the container

`matchDetails[].matcher` is one of `javascript-matcher`, `python-matcher`, `java-matcher`, `go-module-matcher`, `ruby-matcher`, `php-matcher`. PURL scheme is `pkg:npm/`, `pkg:pypi/`, `pkg:maven/`, `pkg:golang/`, `pkg:gem/`, `pkg:composer/`. The artefact came from a manifest or lockfile that was `COPY`'d into the container:

```bash
jq '.matches[]
    | select(.matchDetails[].matcher
             | test("(javascript|python|java|go-module|ruby|php)-matcher"))
    | { id: .vulnerability.id, pkg: .artifact.name, purl: .artifact.purl,
        manifest: .artifact.locations[0].path,
        builtin: (.artifact.locations[0].path | test("^/usr/local/lib|^/opt|^/var/lib") | not) }' \
   grype-results.json
```

**This is a normal SCA finding, not a container finding.** Pivot to the appropriate package-manager triage workflow in the [package managers appendix](../appendices/package-managers/) using the manifest path Grype reported. Common false-pivot trap: a developer treats this as a base-image issue and tries to upgrade the OS, when the real fix is to bump the version in `package.json` / `requirements.txt` / `pom.xml` *back in the source repo* and rebuild the image.

The path Grype reports — `/app/package-lock.json`, `/srv/app/requirements.txt`, `/app/target/myapp.jar` — tells you where the manifest landed inside the image, which in turn tells you whether to fix it in your source tree or in a stage of a multi-stage build (next subsection).

### Class C — multi-stage-build artefact leakage

Some images are built with a multi-stage `Dockerfile`. Class B findings can land in any stage:

```dockerfile
FROM maven:3.9-eclipse-temurin-21 AS build
COPY pom.xml .
COPY src/ src/
RUN mvn -B package

FROM eclipse-temurin:21-jre AS runtime
COPY --from=build /target/myapp.jar /app/myapp.jar
```

The Maven build dependencies are scoped to the `build` stage; only the JAR (and *its bundled deps* if it's an uber-JAR) survives to `runtime`. Inspect the Grype match's `locations[].path`:

- If `path` is `/target/...` or `/build/...` → likely the build stage (you scanned a multi-stage build's intermediate image; the finding is in build-time tooling and not in the runtime image).
- If `path` is `/app/myapp.jar` and the matcher is `java-matcher` → the artefact is shaded into the uber-JAR; triage is a normal SCA workflow against the source POM (Class B) and the rebuild propagates.
- If `path` is the runtime image's OS metadata (`/var/lib/dpkg/status`) → Class A.

**Always scan the runtime image, not the build stage.** `docker build --target=runtime -t myapp:runtime` then `grype myapp:runtime`.

### Class D — copied-in OS package files

Rare but real: a `Dockerfile` that does `COPY ./vendored/some-debian-package.deb /tmp/` and `RUN dpkg -i /tmp/some-debian-package.deb`. The package shows as a dpkg match (Class A) but the fix isn't a base-image bump — it's updating the vendored `.deb` in your source repo. Detect via `RUN` archaeology: `docker history --no-trunc <image>` shows the layer commands. If a `dpkg -i` references a `COPY`'d file, treat the version pin as a source-repo concern.

### Class A — fix mechanics

Once you've identified an OS-package finding, you have three escalating options:

**Option 1 — base image tag bump (preferred).**

```dockerfile
# Before
FROM debian:12.5-slim

# After — check the upstream tag list
FROM debian:12.8-slim
```

Check the maintainer's tag cadence:

```bash
# Debian
docker run --rm debian:12.8-slim cat /etc/debian_version

# Alpine
docker run --rm alpine:3.20 cat /etc/alpine-release

# RHEL UBI (Red Hat Universal Base Image)
docker run --rm registry.access.redhat.com/ubi9/ubi:latest cat /etc/redhat-release

# Compare against the fix-available version Grype reported
jq '.matches[] | select(.vulnerability.id=="<CVE>") | .vulnerability.fix' grype-results.json
```

If the latest available tag still ships the affected version, the upstream hasn't patched yet — fall through to Option 2 or Option 3.

**Option 2 — distro package upgrade during build.**

When the base image tag is current but the specific package is lagging, override at build time:

```dockerfile
# Debian / Ubuntu
FROM debian:12.8-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libbind9-9=1:9.18.28-1~deb12u2 \
 && rm -rf /var/lib/apt/lists/*

# Alpine
FROM alpine:3.20
RUN apk add --no-cache 'libssl3>=3.3.2-r0'

# RHEL UBI
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest
RUN microdnf upgrade -y openssl-libs && microdnf clean all

# Wolfi (apko-based)
FROM cgr.dev/chainguard/wolfi-base
RUN apk add --no-cache 'libcrypto3>=3.3.2-r0'
```

**Multi-stage gotcha**: if your runtime stage is `FROM scratch` or `FROM gcr.io/distroless/static`, you can't run a package manager. Either move to a base that has one (distroless-with-debian-libc, UBI minimal, Wolfi) or upgrade the package in an intermediate stage and `COPY --from=` the binaries you actually need.

**Option 3 — migrate to a maintained hardened base.**

When the upstream base image is abandoned (the maintainer stopped publishing security patches, or the upstream distro itself reached EOL), the *only* honest fix is to migrate. Red Hat publishes a family of free hardened base images that get tracked security advisories:

- **[Red Hat Universal Base Image (UBI)](https://catalog.redhat.com/software/base-images)** — `registry.access.redhat.com/ubi9/ubi`, `ubi9/ubi-minimal`, `ubi9/ubi-micro`. Freely redistributable; tied to RHEL's CVE backports.
- **[Red Hat container images catalogue](https://catalog.redhat.com/en)** — language-specific runtimes (Node, Python, OpenJDK) built on UBI.
- **[images.redhat.com](https://images.redhat.com/)** — front door for the image programme.
- **[Red Hat container docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/building_running_and_managing_containers/index)** — security model, advisory consumption (`microdnf updateinfo list`), and rebuild cadence.

Other maintained hardened alternatives:

- **[Chainguard Images](https://images.chainguard.dev/)** — Wolfi-based, minimal-CVE, daily-rebuilt; many are free, enterprise tier for the rest.
- **[Google distroless](https://github.com/GoogleContainerTools/distroless)** — `gcr.io/distroless/{base,java,nodejs,python}`, no shell, no package manager, very small attack surface.
- **[Microsoft CBL-Mariner](https://github.com/microsoft/CBL-Mariner)** — Microsoft's hardened Linux distro for Azure-hosted containers.

The migration decision: an abandoned base image gets *no* future security patches no matter how diligent your scanning is. Plan the migration; don't just keep adding VEX statements. A `not_affected` VEX on `libssl` is honest; a `not_affected` VEX on every CVE that ever lands against an EOL OS is wishful thinking.

### Class B — fix mechanics

Treat as SCA. The manifest path Grype reported maps to a source-tree file:

| Path inside image | Source path | Appendix |
|---|---|---|
| `/app/package-lock.json` | `package-lock.json` | [JavaScript](../appendices/package-managers/javascript/) |
| `/app/requirements.txt` | `requirements.txt` | [Python](../appendices/package-managers/python/) |
| `/app/poetry.lock` | `poetry.lock` | [Python](../appendices/package-managers/python/) |
| `/app/myapp.jar` (uber-JAR) | `pom.xml` / `build.gradle` | [JVM](../appendices/package-managers/jvm/) |
| `/app/go.mod` | `go.mod` | [Go](../appendices/package-managers/go/) |
| `/app/Cargo.lock` | `Cargo.lock` | [Rust](../appendices/package-managers/rust/) |

Fix in source, rebuild the image, re-scan. If the finding persists after a clean rebuild, check for stale build cache (`docker build --no-cache`) and for vendored copies of the dep (e.g. `node_modules/` committed to the source tree).

## From finding to root cause

Grype is the tool where the triage workflow most rewards OpenVEX investment. The loop:

```bash
# 1. Scan with the OpenVEX file already in place
grype sbom:./.vulnetix/sbom.cdx.json \
  --vex ./.vulnetix/vex.openvex.json \
  -o json > grype.json

# 2. Findings to triage are everything NOT in ignoredMatches
jq '.matches[] | {id: .vulnerability.id, purl: .artifact.purl}' grype.json

# 3. For each, pull Vulnetix's data for Engineer Triage
ID=$(jq -r '.matches[0].vulnerability.id' grype.json)   # GHSA-* or CVE-*
vulnetix vdb vuln "$ID" --output json \
  | jq '.[0].containers.adp[0] | {
          coordinator: .x_ssvc.decision,
          exploitation: .x_exploitationMaturity.level,
          kev: .x_kev.knownRansomwareCampaignUse,
          routines: .x_affectedRoutines
        }'

# 4. Decide. If not_affected, append an OpenVEX statement; Grype will suppress
#    the finding on the next scan. The match moves to ignoredMatches[].
```

Engineer Triage inputs from Grype:

- **Reachability** — for application deps, use the language-specific tool from the [package managers appendix](../appendices/package-managers/) against the names in `x_affectedRoutines`. For OS-layer findings in an image, check whether any binary in the image links against the affected library: `find / -type f -executable | xargs ldd 2>/dev/null | grep <lib>`.
- **Remediation Option** — read `matches[].vulnerability.fix.state`. `fixed` + your version ≤ a fixed version → `PATCHABLE_DEPLOYMENT` if your manifest allows the bump. `wont-fix` → `NO_PATCH`. `not-fixed` → `PATCH_UNAVAILABLE`.
- **Mitigation Option** — typically `AUTOMATION` for app deps (rebuild with the upgrade), `INFRASTRUCTURE` for OS-layer issues you can't yet patch (WAF rule in front of the service).
- **Priority** — Grype `severity` + Vulnetix `coordinator` + `exploitation`.

See [SSVC Engineer Triage](../appendices/ssvc/) for the decision tree.

## Patching mechanics

Pick the workflow that matches the finding class identified above:

- **Class A — OS package** → base-image tag bump, distro package upgrade in build, or migrate to a maintained hardened base (see *Class A — fix mechanics* above; Red Hat UBI, Chainguard, distroless, Wolfi).
- **Class B — language ecosystem** → SCA, fix in source manifest. See the [package managers appendix](../appendices/package-managers/) for the ecosystem.
- **Class C — multi-stage leakage** → confirm runtime stage scan, then apply Class A or B for the stage that actually carries the artefact.
- **Class D — vendored OS package** → update the vendored `.deb` / `.rpm` / `.apk` in source; rebuild image.

## Decision tree

{{< decision >}}
Grype scans against an SBOM (or extracts one from an image), so every finding has a PURL.

For the suppression loop:
  → OpenVEX statement referencing the PURL from .artifact.purl
    (this is what Grype's --vex consumes — NOT CycloneDX VEX)

For tools that consume CycloneDX VEX (Vulnetix, others):
  → CycloneDX VEX entry referencing the same PURL

When you append the OpenVEX statement, Grype's --vex consumes it on subsequent scans:

  grype sbom:./sbom.cdx.json --vex ./vex.openvex.json -o json

The finding moves from matches[] to ignoredMatches[] — no more triage noise.

Need a WAF / IPS / SIEM mitigation while the upgrade is in flight?
  → vulnetix vdb traffic-filters <CVE> supplies the rule;
    status is `affected` + `workaround_available` and the rule reference
{{< /decision >}}

## Worked example: CVE-2023-50387 (KeyTrap DNSSEC) on `libbind9` in a Debian-based image

Grype flags `libbind9-9@1:9.18.19-1~deb12u1` in the `ghcr.io/library/postgres:16.2` base image. The match record:

```json
{
  "matches": [{
    "vulnerability": {
      "id": "CVE-2023-50387",
      "severity": "High",
      "fix": { "state": "fixed", "versions": ["1:9.18.28-1~deb12u2"] }
    },
    "artifact": {
      "name": "libbind9-9",
      "version": "1:9.18.19-1~deb12u1",
      "purl": "pkg:deb/debian/libbind9-9@1%3A9.18.19-1~deb12u1?distro=debian-12",
      "locations": [{ "path": "/var/lib/dpkg/status" }]
    },
    "matchDetails": [{
      "matcher": "dpkg-matcher",
      "type": "exact-direct-match"
    }]
  }]
}
```

The finding is an exact-direct dpkg match (high confidence) on a Debian package. Reachability check — does anything in the image link against the affected library? Drive the library name from Grype's own JSON instead of typing it (and pull the function-level grep list from `vulnetix vdb vuln` when symbol-level reach matters):

```bash
# Library name from grype-results.json — never typed by hand
LIB=$(jq -r '.matches[]
              | select(.vulnerability.id=="CVE-2024-1737")
              | .artifact.name' grype-results.json | head -1)

# Symbol-level supplement (Grype's JSON only carries the package — vulnetix
# provides the affected functions/files for binaries that *do* link the lib)
ROUTINES=$(vulnetix vdb vuln CVE-2024-1737 --output json \
  | jq -r '.[0].containers.adp[0].x_affectedRoutines[]?
           | select(.kind=="function") | .name')

# Pull a copy of the image and inspect linkage against $LIB
docker run --rm --entrypoint sh ghcr.io/library/postgres:16.2 \
  -c "find / -type f -executable 2>/dev/null \
      | xargs -I{} sh -c 'ldd {} 2>/dev/null | grep -l \"$LIB\" && echo {}'" \
  | sort -u
```

If no binary in the image links against `libbind9` (PostgreSQL doesn't use BIND's resolver; the package was installed as a dpkg dependency of something that doesn't actually exercise the vulnerable code), `Reachability: VERIFIED_UNREACHABLE` is honest. Engineer Triage: `Remediation: PATCHABLE_DEPLOYMENT` (next base-image bump picks up the fix), `Mitigation: AUTOMATION`, `Priority: HIGH` (CVSS 7.5) — outcome `NIGHTLY_AUTO_PATCH`.

Write the OpenVEX statement (this is what Grype's `--vex` reads). From the next scan onward, Grype suppresses this finding:

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-grype-001.json",
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
    "action_statement": "Engineer Triage: BACKLOG (escalated to NIGHTLY_AUTO_PATCH at next base-image bump). libbind9-9 is in the postgres:16.2 base image as a transitive dpkg dependency but no binary in the image links against it — verified by walking /var/lib/dpkg/info/*.list for files, then ldd against every executable, no result matched libbind9. Will pick up the fix automatically when the base image is bumped past 1:9.18.28."
  }]
}
```
{{< /outcome >}}

Confirm on the next scan:

```bash
grype sbom:./.vulnetix/sbom.cdx.json --vex ./vex.openvex.json -o json \
  | jq '.ignoredMatches[]
        | select(.match.vulnerability.id == "CVE-2023-50387")
        | { id: .match.vulnerability.id, rules: .appliedIgnoreRules }'
# → returns the entry, with appliedIgnoreRules[].vex-status = "not_affected"
```

If you also need a CycloneDX VEX entry (for other tools in your pipeline that consume that format — Vulnetix's vdb workflow, audit consumers), maintain it in parallel:

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
      "detail": "Engineer Triage: BACKLOG. Mirrors the OpenVEX statement at vex.openvex.json — Grype consumes the OpenVEX form."
    }
  }]
}
```
{{< /outcome >}}

## Developer gotchas — written for people who write code, not Dockerfiles

You write the application code; somebody's CI builds the image. These are the container-finding surprises that catch developers when triaging a Grype report.

- **The same package can appear three times in one scan.** Your Node.js app's container has `node` (OS-package matcher, from the base image), `nodejs` (npm self-reference, sometimes embedded), and a few hundred npm modules from `package-lock.json`. A CVE in OpenSSL may surface as both a Debian dpkg match (`libssl3`) and an npm package match (`ssl-root-cas`) — the dpkg one is the base image, the npm one is your manifest. Same library, different triage workflow.

- **"Just rebuild the image" doesn't always pick up the fix.** Docker layer caching keeps an `apt-get install foo` layer until the base image tag (or the previous `RUN` line) changes. A new security advisory for `foo` doesn't invalidate that cache. Force with `docker build --no-cache` or pin to the advisory's fixed version explicitly: `apt-get install -y foo=1.2.3-1+deb12u2`.

- **Your `latest` tag isn't stable.** `FROM debian:latest` resolves at build time and varies week to week. The CVE that was in your last build may be patched in this one; new ones may appear. Pin to a date-stamped or version-stamped tag (`debian:12.8-slim`, `debian:bookworm-20240701-slim`). Scanners reading a `Dockerfile` may not even know which version the build resolved.

- **`COPY --from=` only copies what you name.** Multi-stage builds let the build stage be huge and the runtime stage tiny. But a `COPY --from=build /app /app` brings *the entire `/app` directory*, including any node_modules / vendor / target that wasn't pruned. CVE in a dev dep can survive the multi-stage if you forgot `npm prune --production` or `mvn dependency:purge` before the copy.

- **`USER root` vs `USER nobody` doesn't change CVE exposure but changes blast radius.** A reachable RCE in a container running as root pwns the container; as `nobody` it pwns less. The CVE counts are the same; the *consequence* of "VERIFIED_REACHABLE + HIGH" differs. Worth noting in the VEX `analysis.detail`.

- **Distroless images don't have `apt`/`apk` — you can't upgrade in place.** `gcr.io/distroless/static` has no shell, no package manager. Your only fix is to rebuild the upstream distroless image's base — which means waiting for Google to publish a patched tag, or switching to a base that has package management (UBI minimal, Wolfi, Alpine).

- **`SCRATCH` images have no package surface but you're not off the hook.** `FROM scratch` then `COPY mybinary /` — no OS packages, no libc, nothing for Grype to scan. The CVE you should worry about is in `mybinary` itself: if it's a Go binary, dependencies are baked in; if it's a dynamically-linked C binary, you'll have linker errors. Run `grype` on the binary directly: `grype file:./mybinary -o json`.

- **`.dockerignore` controls what reaches the image — and what the scanner sees.** Adding `.git/` to `.dockerignore` means scanners can't compute git-based identifiers. Adding `vendor/` means a vendored CVE-affected dep doesn't appear in the image at all. Conversely, *not* having `node_modules/` in `.dockerignore` lets local dev dependencies leak into prod images.

- **Health checks and entrypoint scripts can be vulnerable too.** A custom `ENTRYPOINT` that calls `curl <hardcoded URL>` brings in `libcurl`. Grype catches the library; the entrypoint script is often invisible to source SCA tools. Read the Dockerfile, not just `package.json`.

- **`docker scan` and `docker scout` are different tools with different DBs.** "docker scanned clean" from a `docker scout cves` doesn't mean Grype agrees. Different feed sources, different matching algorithms. For CI gating, pick one and stick with it.

- **The image's reported OS may not match what's actually installed.** `docker inspect <image> | jq '.[0].Config.Labels'` reports labels the image author set. `cat /etc/os-release` from inside the container is authoritative. Some images report `debian` but install `apk` on top (rare but real for vendor-built images).

- **Container scans don't see what your runtime mounts.** A read-only `ConfigMap` mounted at `/app/config/` in Kubernetes isn't in the image; a `PersistentVolume` mounted at `/data/` likewise. CVE counts from the image may differ from reality on the cluster. Same for `:rw` bind mounts in `docker-compose.yml`.

- **`docker history` reveals secrets that aren't in the image's filesystem.** A `RUN export AWS_KEY=foo && do-thing` puts `foo` in the layer metadata, even if it's not in the final filesystem. Grype won't flag it as a CVE, but secret scanners on the image (Trivy with `--security-checks secret`) will. Worth knowing the gotcha exists even though it's a different scanner family.

## Producing an OpenVEX

For Dockerfile-pattern findings (Grype doesn't emit these — they come from Vulnetix or hadolint), OpenVEX would apply. For Grype's package-level matches, CycloneDX VEX is the right format because every match has a PURL.

The exception: if Grype is scanning a binary directory (`grype dir:./build/`) and the matched component lacks a manifest-derived PURL (rare — usually a CPE fallback match), use OpenVEX with the binary path as the subject identifier.
