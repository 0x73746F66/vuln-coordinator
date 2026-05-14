---
title: "SSVC — Engineer Triage for developers"
description: "The decision framework that turns a scanner finding into one of four actions — NIGHTLY_AUTO_PATCH, BACKLOG, SPIKE_EFFORT, or DROP_TOOLS."
weight: 15
---

## Why a decision framework

CVSS gives you a number; the number doesn't tell you what to do next. "Critical, score 9.8" could mean *stop everything and patch right now* — or *route to next sprint*, depending on whether the code is reachable, whether a patch even exists, and what defensive measures are already in place.

SSVC (Stakeholder-Specific Vulnerability Categorization) is the framework that turns scanner output into a verdict on **action**. It comes in several flavours per stakeholder — coordinators issue advisories, deployers run infrastructure, *engineers* write the code. Each gets its own decision tree because each has different levers.

Vulnetix's CLI exposes the **CISA Coordinator** decision via `vdb vuln`'s `x_ssvc` field. That's useful, but Coordinator is the wrong methodology for a developer audience — its outputs (`Track`, `Track*`, `Attend`, `Act`) are about whether a coordinator should publish an advisory, not whether you should patch your service. The developer methodology is **Engineer Triage**, published as part of the [Vulnetix typescript-ssvc package](https://github.com/Vulnetix/typescript-ssvc).

This page covers Engineer Triage. The Coordinator decision Vulnetix returns serves as one input — the priority signal — into the engineer's tree.

## Engineer Triage in one paragraph

Four inputs answer a four-step question: *can the vulnerable code run, what patches exist, what defences can we add, how bad is it?* The combination resolves to one of four actions: ship in tonight's auto-deploy, drop tools and fix now, spike effort to scope the work, or put it on the backlog. Every input value and outcome name is documented; nothing depends on subjective rating.

## The four inputs

### 1. Reachability

*Can the vulnerable code path actually execute in your service?*

| Value | Meaning |
|---|---|
| `VERIFIED_REACHABLE` | Evidence (coverage, call graph, runtime trace) confirms the vulnerable function can be called from your code |
| `VERIFIED_UNREACHABLE` | Evidence the vulnerable function is never called — dead branch, disabled feature, build-time-only dep |
| `UNKNOWN` | No conclusive evidence. **The tree treats UNKNOWN as REACHABLE** — bias is toward acting on the finding |

How to gather: see the [package managers appendix](../package-managers/) — each per-language page has the static and runtime reachability tooling for that ecosystem.

### 2. Remediation Option

*What patching paths exist?*

| Value | Meaning |
|---|---|
| `PATCHABLE_DEPLOYMENT` | The fix lands in a redeployment without code changes (caret/tilde ranges, container base bumps) |
| `PATCHABLE_VERSION_LOCKED` | A patch exists but your version is pinned for compatibility — needs planning and testing |
| `PATCHABLE_MANUAL` | A patch exists, version isn't locked, but applying it requires manual work (porting a fix, breaking API) |
| `PATCH_UNAVAILABLE` | The CVE has no fix from the vendor *yet* — patch is in flight or pending |
| `NO_PATCH` | Vendor has no plans, project is abandoned, or runtime is EOL |

How to gather: `vulnetix vdb fixes <CVE-ID>` returns the patch landscape per registry. Check your lockfile's constraint for the affected component against the fixed version to decide between `PATCHABLE_DEPLOYMENT` and `PATCHABLE_VERSION_LOCKED`.

### 3. Mitigation Option

*If we can't patch immediately, what defensive measure can we deploy in the meantime?*

| Value | Meaning |
|---|---|
| `INFRASTRUCTURE` | WAF / IPS / network control / API gateway policy. Patch is independent of app code |
| `CODE_CHANGE` | Application-level mitigation — input validation, feature flag, sanitisation around the vuln |
| `UPSTREAM_PR` | Active upstream project where you can contribute the fix |
| `ALTERNATIVE` | A mature replacement library exists; swap is feasible |
| `AUTOMATION` | CI / pipeline-level control — block on next scan, automate the dependency bump, monitor for exploitation |

Vulnetix can supply the infrastructure mitigation directly: `vulnetix vdb traffic-filters <CVE>` (Snort / Suricata), `vulnetix vdb snort-rules get <CVE>`, `vulnetix vdb nuclei get <CVE>`.

### 4. Reported Priority

*How severe is the CVE itself, in isolation?*

| Value | Source |
|---|---|
| `CRITICAL` | CVSS 9.0–10.0, or KEV-listed with active exploitation |
| `HIGH` | CVSS 7.0–8.9 |
| `MEDIUM` | CVSS 4.0–6.9 |
| `LOW` | CVSS 0.0–3.9 |

This is where the Vulnetix CISA Coordinator output enters: pull `x_ssvc.decision` and `x_ssvc.inputs.exploitation` to inform the priority decision. `Act` + `ACTIVE` exploitation = `CRITICAL` regardless of CVSS.

```bash
vulnetix vdb vuln CVE-2021-44228 --output json \
  | jq '.[0].containers.adp[0] | {
          cvss: (.x_exploitationMaturity.factors.cess // null),
          epss: .x_exploitationMaturity.factors.epss,
          kev: .x_kev.knownRansomwareCampaignUse,
          coordinator: .x_ssvc.decision,
          exploitation: .x_exploitationMaturity.level
        }'
```

## The four outcomes

| Outcome | When | Timeline | Effort |
|---|---|---|---|
| `NIGHTLY_AUTO_PATCH` | Unreachable code, or reachable but deployment-patchable at low risk | Next automated deploy (24–48h) | Minimal — Dependabot/Renovate PR + green CI |
| `BACKLOG` | Lower-priority findings where evidence supports deferral | Next sprint or planning cycle | Standard development workflow |
| `SPIKE_EFFORT` | Complex case needing scoping before commitment | Within current sprint, time-boxed (2–8h) | Investigate, plan, estimate, then implement |
| `DROP_TOOLS` | Critical exploitable now, no good alternative | Hours, not days | All hands — emergency change procedure |

## The decision tree

The full tree has 184 nodes. The summary patterns below cover the high-traffic decisions; the full mermaid graph is in the [upstream guide](https://github.com/Vulnetix/typescript-ssvc/blob/main/docs/engineer_triage.md).

### When reachability is `VERIFIED_REACHABLE`

| Remediation | Mitigation | Priority | → Outcome |
|---|---|---|---|
| `PATCHABLE_DEPLOYMENT` | `AUTOMATION` | LOW–HIGH | `NIGHTLY_AUTO_PATCH` |
| `PATCHABLE_DEPLOYMENT` | `AUTOMATION` | CRITICAL | `SPIKE_EFFORT` |
| `PATCHABLE_VERSION_LOCKED` | `CODE_CHANGE` | CRITICAL / HIGH | `DROP_TOOLS` |
| `PATCHABLE_VERSION_LOCKED` | `CODE_CHANGE` | MEDIUM / LOW | `SPIKE_EFFORT` |
| `PATCHABLE_MANUAL` | `CODE_CHANGE` | CRITICAL / HIGH | `DROP_TOOLS` |
| `PATCHABLE_MANUAL` | `CODE_CHANGE` | MEDIUM / LOW | `NIGHTLY_AUTO_PATCH` |
| `PATCH_UNAVAILABLE` | `INFRASTRUCTURE` | CRITICAL / HIGH | `DROP_TOOLS` |
| `PATCH_UNAVAILABLE` | `INFRASTRUCTURE` | MEDIUM | `SPIKE_EFFORT` |
| `PATCH_UNAVAILABLE` | `INFRASTRUCTURE` | LOW | `BACKLOG` |
| `PATCH_UNAVAILABLE` | `UPSTREAM_PR` | CRITICAL | `DROP_TOOLS` |
| `PATCH_UNAVAILABLE` | `UPSTREAM_PR` | HIGH–LOW | `SPIKE_EFFORT` |
| `NO_PATCH` | `ALTERNATIVE` | CRITICAL / HIGH | `DROP_TOOLS` |
| `NO_PATCH` | `ALTERNATIVE` | MEDIUM | `SPIKE_EFFORT` |
| `NO_PATCH` | `ALTERNATIVE` | LOW | `BACKLOG` |

### When reachability is `VERIFIED_UNREACHABLE`

The whole tree shifts left — unreachable code can't be exploited, so most outcomes fall into `NIGHTLY_AUTO_PATCH` or `BACKLOG`. The exceptions are critical findings on locked or unpatched components, which still warrant `SPIKE_EFFORT` to plan for a future fix.

| Remediation | Priority | → Outcome |
|---|---|---|
| `PATCHABLE_DEPLOYMENT` | any | `NIGHTLY_AUTO_PATCH` |
| `PATCHABLE_VERSION_LOCKED` | CRITICAL / HIGH | `SPIKE_EFFORT` |
| `PATCHABLE_VERSION_LOCKED` | MEDIUM / LOW | `BACKLOG` |
| `PATCH_UNAVAILABLE` | CRITICAL | `SPIKE_EFFORT` |
| `PATCH_UNAVAILABLE` | HIGH–LOW | `BACKLOG` |
| `NO_PATCH` | CRITICAL | `SPIKE_EFFORT` |
| `NO_PATCH` | HIGH–LOW | `BACKLOG` |

### When reachability is `UNKNOWN`

Treated as `VERIFIED_REACHABLE` — the table above applies. The honest move when uncertain is to invest a small spike in reachability evidence (one or two hours of static + dynamic analysis) and re-classify. The wrong move is to declare `VERIFIED_UNREACHABLE` without evidence; future-you and the auditor both want the evidence in the VEX.

## Worked examples (from the Vulnetix Engineer Triage guide)

### Example 1 — `lodash` deserialization in production

Scanner: `npm audit` flags lodash 4.17.15 (CVSS 7.2 HIGH, fix in 4.17.21).

| Input | Value | Why |
|---|---|---|
| Reachability | `VERIFIED_REACHABLE` | `grep -r "lodash" src/` finds imports across the codebase |
| Remediation | `PATCHABLE_DEPLOYMENT` | `package.json` has `"lodash": "^4.17.15"` — caret range allows 4.17.21 |
| Mitigation | `AUTOMATION` | Dependabot can open the PR; CI verifies |
| Priority | `HIGH` | CVSS 7.2 |

**→ `NIGHTLY_AUTO_PATCH`**

### Example 2 — `openssl` critical in a container

Scanner: Trivy flags openssl 1.1.1k in the base image (CVE-2023-5678, CRITICAL, fix in 1.1.1l).

| Input | Value | Why |
|---|---|---|
| Reachability | `VERIFIED_REACHABLE` | The web server links openssl for TLS |
| Remediation | `PATCHABLE_DEPLOYMENT` | Bumping the base image FROM line picks up the fixed openssl |
| Mitigation | `AUTOMATION` | CI rebuilds the container nightly |
| Priority | `CRITICAL` | Marked critical, KEV-relevant |

**→ `SPIKE_EFFORT`** — critical priority forces the explicit scope-and-deploy spike even though the patch path is automatable.

### Example 3 — express version-locked at 4.16.4

Scanner: Dependabot alert on express 4.16.4 (CVSS 6.5 MEDIUM, fix in 4.17.0+).

| Input | Value | Why |
|---|---|---|
| Reachability | `VERIFIED_REACHABLE` | Express is the web framework |
| Remediation | `PATCHABLE_VERSION_LOCKED` | `"express": "=4.16.4"` — exact pin, can't just bump |
| Mitigation | `CODE_CHANGE` | Bump probably affects middleware contracts; needs testing |
| Priority | `MEDIUM` | CVSS 6.5 |

**→ `SPIKE_EFFORT`** — sprint-scoped scope-and-bump, not a same-day emergency, not a deferral.

## Recording the decision in VEX

Engineer Triage's outcome belongs in the VEX `analysis.detail` along with the inputs that produced it. Future-you (and an auditor) needs to see the reasoning, not just the verdict.

For CycloneDX VEX:

```json
"analysis": {
  "state": "resolved",
  "detail": "Engineer Triage: NIGHTLY_AUTO_PATCH. Inputs: reachability=VERIFIED_REACHABLE (grep shows lodash imported across src/utils/), remediation=PATCHABLE_DEPLOYMENT (^4.17.15 allows the fixed 4.17.21), mitigation=AUTOMATION (Dependabot PR), priority=HIGH (CVSS 7.2). Auto-patched in commit abc1234, MR !42, deployed to prod 2026-05-14T22:00Z."
}
```

For OpenVEX:

```json
"status": "fixed",
"action_statement": "Engineer Triage: DROP_TOOLS. Reachable critical exploit with version-locked dep — manual port + emergency deploy. Coordinator output from vulnetix vdb vuln: decision=Act, exploitation=ACTIVE, KEV=Known. Fix landed in commit def5678, deployed via emergency-change MR !99 on 2026-05-14T03:14Z. Incident INC-2026-042."
```

The naming convention `Engineer Triage: <OUTCOME>` at the start of the detail field makes the analysis machine-parseable for future scanner tooling that consumes VEX with SSVC awareness.

## When Coordinator and Engineer disagree

The Coordinator output Vulnetix returns is a generic, deployment-agnostic answer. Your deployment knowledge moves the needle:

- Coordinator says `Act` (critical, active exploitation) — but your service runs on an internal VPC with mTLS-only ingress. Engineer Triage's `Reachability` is still `VERIFIED_REACHABLE` (the code runs), but `Mitigation` is `INFRASTRUCTURE` (the perimeter already blocks the vector), and Priority drops from `CRITICAL` to `HIGH`. Outcome: `SPIKE_EFFORT`, not `DROP_TOOLS`.
- Coordinator says `Track` (low) — but the vulnerable function happens to be on your hot path for handling authentication tokens. Engineer Triage's `Reachability` is `VERIFIED_REACHABLE` and `Priority` is `HIGH` regardless of what Coordinator says. Outcome: `SPIKE_EFFORT` or `DROP_TOOLS`.

The Coordinator decision is **an input**, not the conclusion. Engineer Triage's tree is what produces the action. Record both in your VEX `detail` field — the disagreement, if any, is what makes the analysis durable.
