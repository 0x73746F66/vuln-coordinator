---
title: "EOL gating — when a CVE means migrate, not patch"
description: "End-of-life detection for runtimes, packages, and container base images. The SSVC mapping when no upstream fix will ever exist."
weight: 26
---

A CVE on a maintained component has a fix path — bump the version, re-run the build, ship. A CVE on an end-of-life (EOL) component has no fix path, ever. The upstream isn't shipping patches anymore. Bulk-fixing CVEs on an EOL'd runtime or distro is whack-a-mole; the only durable outcome is migration.

EOL detection is therefore an SSVC-level concern. It changes `Remediation Option` to `NO_PATCH` (or `PATCH_UNAVAILABLE` if a community fix is in flight). It changes the right `Engineer Triage` outcome from `NIGHTLY_AUTO_PATCH` to `SPIKE_EFFORT` (plan migration) — and it changes the unit of work from "this CVE" to "this entire stack."

For terminology used here, see the [Glossary](glossary/).

## What goes EOL

Three layers, distinct lifecycles, distinct evidence sources:

1. **Language runtimes** — Python 2.7, Node.js 14/16, OpenJDK 8 (free Oracle JDK; commercial vendors continue), Go versions older than `latest-2`, Rust edition support.
2. **Packages / libraries** — npm packages with no commits for years, Maven artefacts the maintainer publicly stopped maintaining, Python packages explicitly deprecated, Linux distro packages dropped from a release.
3. **Container base images / OS distros** — Debian releases past their LTS window (Debian 10 = LTS-EOL 2024-06; Debian 9 = ELTS), Ubuntu non-LTS releases past 9 months, Alpine maintenance branches, RHEL major-version lifecycle, Amazon Linux 1 (EOL 2023).

## Data sources for EOL

| Source | What it covers | Notes |
|---|---|---|
| [endoflife.date](https://endoflife.date/) | Single biggest cross-language EOL catalogue — Python, Node, Java, Go, Ruby, PHP, distros, frameworks, databases | Free, well-maintained, JSON API at `https://endoflife.date/api/<product>.json`. Most scanners that surface EOL ultimately query this. |
| [python-eol](https://python-eol.org/) | Python-only, with per-minor end dates | Python 3.x release schedule details |
| [Node.js release schedule](https://nodejs.org/en/about/previous-releases) | Active LTS / Maintenance / End-of-Life | Authoritative for Node |
| [OpenJDK lifecycle](https://www.oracle.com/java/technologies/java-se-support-roadmap.html) | Java versions; distinct vendor lifecycles (Oracle, Eclipse Temurin, Amazon Corretto, Azul Zulu) | Free vs commercial timelines differ |
| [Debian releases](https://wiki.debian.org/DebianReleases) | Per-release EOL dates including LTS and ELTS extensions | Debian's LTS volunteers extend support, ELTS via Freexian commercial |
| [Ubuntu release schedule](https://wiki.ubuntu.com/Releases) | LTS (5y) / interim (9mo) | ESM for older LTS via Ubuntu Pro |
| [Alpine releases](https://alpinelinux.org/releases/) | Per-version maintenance windows | Two-year support window typical |
| [RHEL lifecycle](https://access.redhat.com/support/policy/updates/errata) | Full support / maintenance / ELS phases | UBI follows the underlying RHEL lifecycle |
| [Amazon Linux lifecycle](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/al1-end-of-life.html) | AL1 EOL; AL2 / AL2023 active | |
| [Vulnetix VDB](glossary/#vulnetix-vdb) | Per-package + per-runtime + per-base-image `lifecycleStage` field | First-party — integrates the above sources plus first-party EOL judgements on packages |

## Runtime EOL signalling — what the runtime tells you

Most runtimes don't proactively warn that they're EOL. Notable exceptions:

- **Python 2.7** prints `DeprecationWarning: Python 2 is no longer supported` on import of `pip` in current versions.
- **Node.js** logs `(node:1) NodeAgentLoader: Node.js LTS support ended on YYYY-MM-DD` on startup for unsupported versions.
- **Java** prints warnings for preview features past their preview window, but not for the whole runtime.
- **Most distros**: silent. You need to check the version against the lifecycle table.

In practice, build your gate at scan time rather than relying on runtime warnings:

```bash
# Python runtime EOL gate
PY_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d. -f1-2)
PY_EOL=$(curl -s "https://endoflife.date/api/python.json" \
  | jq -r --arg v "$PY_VERSION" '.[] | select(.cycle == $v) | .eol')
[ "$(date -u +%Y-%m-%d)" \> "$PY_EOL" ] && {
  echo "Python $PY_VERSION is EOL ($PY_EOL) — block deploy"; exit 1; }

# Node.js
NODE_MAJOR=$(node --version | cut -dv -f2 | cut -d. -f1)
NODE_EOL=$(curl -s "https://endoflife.date/api/nodejs.json" \
  | jq -r --arg v "$NODE_MAJOR" '.[] | select(.cycle == $v) | .eol')

# Container base image EOL — read from inside the image
DISTRO_VERSION=$(docker run --rm myapp:tag sh -c '. /etc/os-release && echo "$ID-$VERSION_ID"')
# Then look up against endoflife.date or the distro's table.
```

## The SSVC mapping

EOL changes the [Remediation Option](ssvc/#2-remediation-option) directly:

| Component status | Remediation Option | Notes |
|---|---|---|
| Maintained, fix available in version range your manifest accepts | `PATCHABLE_DEPLOYMENT` | Normal case |
| Maintained, fix available but your version is pinned | `PATCHABLE_VERSION_LOCKED` | Bump and test |
| Maintained, fix available but breaks API | `PATCHABLE_MANUAL` | Port the fix |
| Maintained, no fix yet — vendor is working on one | `PATCH_UNAVAILABLE` | Wait + mitigate |
| **EOL — vendor stopped publishing patches** | **`NO_PATCH`** | **Migrate** |
| EOL — community/distro is back-porting (Debian LTS, RHEL ELS) | `PATCH_UNAVAILABLE` (for now) shading toward `NO_PATCH` (eventually) | Time-limited fix path |

The `Engineer Triage` outcome for `NO_PATCH` is rarely `NIGHTLY_AUTO_PATCH` (there's nothing to auto-patch). It's usually `SPIKE_EFFORT` (plan the migration in the next sprint) or `BACKLOG` if the priority is low enough to live with — though "live with" on a critical CVE in EOL software is a hard sell to anyone reviewing the decision.

## Worked example — Python 2.7 EOL with a critical CVE

A legacy service on Python 2.7. A scanner flags `CVE-2024-NNNNN` against a transitive dep `urllib3`. The fix exists in `urllib3>=2.0`, but `urllib3>=2.0` requires Python 3.8+.

**Engineer Triage inputs**:
- `Reachability` = `VERIFIED_REACHABLE` (the service makes outbound HTTPS calls through `urllib3`).
- `Remediation Option` = `NO_PATCH` (urllib3's 1.x line is EOL; the only fix is on the 2.x line, which doesn't support Python 2.7).
- `Mitigation Option` = `INFRASTRUCTURE` (egress proxy with TLS validation, mTLS, or `CODE_CHANGE` to swap `urllib3` for `requests` 2.27 + a vendor-specific HTTP client — also Python-2-incompatible).
- `Priority` = `HIGH` or `CRITICAL` depending on the CVE.

**Outcome**: `SPIKE_EFFORT`. The unit of work isn't "bump urllib3" — it's "migrate the service off Python 2.7." Any per-CVE patching effort spent on this service is wasted; the next CVE will arrive in weeks. Record the EOL evidence in the VEX:

```json
"analysis": {
  "state": "affected",
  "response": ["will_not_fix"],
  "detail": "Engineer Triage: SPIKE_EFFORT. Inputs: reachability=VERIFIED_REACHABLE, remediation=NO_PATCH (Python 2.7 reached EOL 2020-01-01; urllib3 2.x is the only fixed line and requires Python 3.8+), mitigation=INFRASTRUCTURE (egress proxy with TLS validation pending migration), priority=HIGH. Migration to Python 3.11 tracked in PROJ-1234 (target FY26-Q1)."
}
```

## Container base image EOL — same shape, different blast radius

When a container base image reaches EOL, every dependent image inherits the problem. A `FROM debian:10-slim` post-LTS gets no security updates for the OS layer. Every CVE on `libc6`, `openssl`, `bash` etc. becomes a `NO_PATCH` per the above table.

**Three escalating fix options** (mirrors [Grype's Class A](../../scanners/grype/#class-a--fix-mechanics)):

1. **Bump to a still-supported tag of the same distro**: `debian:10` → `debian:12`. Cheapest; usually breaks one or two things (library version bumps, locale config).
2. **Migrate to a maintained alternative**: Debian 10 → [Red Hat UBI](https://catalog.redhat.com/software/base-images) / [Chainguard Wolfi](https://images.chainguard.dev/) / [Google distroless](https://github.com/GoogleContainerTools/distroless) / Alpine. More breakage, smaller attack surface ongoing.
3. **Pay for extended support**: Debian Freexian ELTS, Ubuntu Pro ESM, RHEL ELS. Buys time; doesn't solve the structural problem.

A scanner without native EOL data won't flag the base image as the root cause — it'll flag the dozens of individual OS-package CVEs. Pivot via:

```bash
# Identify the base image's OS version from inside the image
docker run --rm <image> cat /etc/os-release

# Look up EOL
curl -s "https://endoflife.date/api/debian.json" \
  | jq '.[] | select(.cycle == "10") | {release: .releaseDate, eol: .eol, lts: .extendedSupport}'

# Vulnetix-native: read lifecycleStage per OS finding
vulnetix vdb vuln <CVE> --output json \
  | jq '.[0].containers.adp[0].x_remediationTimeline.lifecycleStage'
```

## Per-tool applicability — EOL coverage

| Tool | Runtime EOL | Package EOL | Container base-image EOL |
|---|---|---|---|
| [Vulnetix](../../scanners/vulnetix/) | ✅ Native via `vdb` `lifecycleStage` | ✅ Native | ✅ Native — `vulnetix:eol-check` skill plus `--block-eol` gate |
| [Grype](../../scanners/grype/) | ❌ No native EOL; OS feed surfaces "no fix available" which is a *weak* signal | ❌ Same | 🟡 Inferred — when an OS package is past upstream support, the feed will lack a `fixed` version, which approximates EOL |
| [Snyk OSS](../../scanners/snyk-oss/) | 🟡 Some EOL signalling in commercial tiers | 🟡 Same | 🟡 Container-image scanning surfaces base-image age (commercial) |
| [Dependabot](../../scanners/github-dependabot/) | ❌ No EOL signalling | ❌ Surfaces deprecated-package advisories where the maintainer has published one, but no proactive lifecycle | ❌ Not a container scanner |
| [OSV-Scanner](../../scanners/osv-scanner/) | ❌ | ❌ | ❌ |
| [GitLab Dependencies](../../scanners/gitlab-dependencies/) | ❌ | ❌ | 🟡 GitLab Container Scanning checks; lifecycle is implicit |
| [Semgrep/Opengrep](../../scanners/semgrep-opengrep/) | ❌ (SAST scope) | ❌ | ❌ |
| [CodeQL](../../scanners/github-codeql/) | ❌ (SAST scope) | ❌ | ❌ |

`✅` native first-party EOL data; `🟡` partial / commercial-tier-only / inferred; `❌` not covered, cross-reference [endoflife.date](https://endoflife.date/) or [Vulnetix](../../scanners/vulnetix/sca/).

The [database quality tiers](../../scanners/#capability-matrix) feed EOL the same way they feed CVE coverage — the broader the source set, the more EOL signals are picked up automatically.

## When community / distro backporting changes the answer

Some upstream-EOL components keep getting fixes from third parties:

- **Debian LTS / ELTS**: Debian volunteers cover non-current releases for two extra years; Freexian's ELTS extends for several more. `apt-get install` fetches patched versions even though the upstream Debian release is "EOL."
- **Ubuntu Pro / ESM**: paid commercial extension of LTS support.
- **RHEL ELS**: Red Hat's Extended Life-cycle Support.
- **AlmaLinux / Rocky Linux**: community RHEL rebuilds with their own backporting cadence.
- **Independent community forks**: occasionally a maintainer-fork picks up an abandoned package (rare, fragile).

For these, the `Remediation Option` is `PATCH_UNAVAILABLE` (a fix is in flight from a third party, but not from upstream) shading toward `NO_PATCH` as the third-party window closes. Record the third-party patch path in the VEX `action_statement` so future-you knows where the fix came from.

## See also

- [SSVC Engineer Triage](ssvc/) — where EOL feeds `Remediation Option`.
- [Vulnetix SCA](../../scanners/vulnetix/sca/#eol-gating-and---block-eol) — the native EOL gate.
- [Grype's Class A finding-class taxonomy](../../scanners/grype/#first-identify-the-finding-class) — base-image EOL is the canonical "bump or migrate" decision.
- [Glossary](glossary/) — EOL, safe-harbour, lifecycle stage entries.
- [Capability matrix](../../scanners/#capability-matrix) — EOL coverage column.
- [endoflife.date](https://endoflife.date/) — the cross-language EOL catalogue most tools query.
