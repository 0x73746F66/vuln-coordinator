---
title: "AI Coding Agent — triage, remediation, VEX"
description: "The Vulnetix plugin for Claude Code, Cursor, Windsurf, Copilot, Gemini, and a dozen other editors. Removes the burden of picking VEX formats, remediation strategies, and SSVC inputs by hand."
weight: 6
---

The [pix-ai-coding-assistant](https://github.com/Vulnetix/pix-ai-coding-assistant) plugin is the easiest way to drive everything on this site. It ships slash-commands ("skills"), sub-agents, hooks, and CLI wrappers across Claude Code, Cursor, Windsurf, Copilot, Gemini, Codex, Augment, Cline, Amazon Q, OpenHands, Codebuddy, Cortex, Qoder, Qwen, Kiro, and iFlow — one `hooks.<ide>.json` config per editor.

The plugin removes the developer-side burden of *deciding* between scanner outputs, [VEX](vex/) formats, remediation strategies, and [SSVC](ssvc/) inputs. It surfaces the data, picks the form, and writes the artefact. Reference: [ai-docs.vulnetix.com/docs](https://ai-docs.vulnetix.com/docs).

This page is a triage / remediation / VEX slice — not a full plugin tour. For the rest, see the upstream docs.

## Skills (slash commands)

Every command below is invoked as `/vulnetix:<skill>` from your editor's command palette / chat input. Each writes durable state to `.vulnetix/memory.yaml` so a follow-on command picks up the previous one's work.

**Vulnerability intelligence**
- `/vulnetix:vuln <CVE-or-pkg>` — full vulnerability lookup; surfaces [SSVC Coordinator](glossary/#cisa-coordinator-decision) + [KEV](glossary/#kev-known-exploited-vulnerabilities) + [EPSS](glossary/#epss-exploit-prediction-scoring-system) + [`x_affectedRoutines`](glossary/#x_affectedroutines) + repo-impact assessment.
- `/vulnetix:exploits <CVE>` — exploit analysis, [ATT&CK](glossary/#attack) mapping, [CWSS](glossary/#cwss-common-weakness-scoring-system) priority, PoC source caching, threat-model recording in `.vulnetix/memory.yaml`.

**Remediation**
- `/vulnetix:fix <CVE>` — concrete remediation proposal with [Safe Harbour](glossary/#safe-harbour) confidence — version bump, inline as first-party code, patch, workaround, or advisory. Dry-run + rollback-safe manifest edits.
- `/vulnetix:remediation <CVE>` — context-aware plan with confidence ranking: registry fixes vs upstream commits vs distro patches vs workarounds vs CWE-specific defensive strategies; per-package-manager verification commands.
- `/vulnetix:safe-version <pkg>` — newest non-vulnerable version capped by `--max-major-bump` policy.
- `/vulnetix:dep-resolve` — dependency-conflict resolution when `/vulnetix:fix` fails (peer-dep analysis, override mechanism selection, [JVM appendix](package-managers/jvm/) mechanisms, safe-harbour fallback).
- `/vulnetix:verify-fix <CVE>` — post-fix re-scan, gate on `--exploits weaponized --severity high`, write verdict to `.vulnetix/memory.yaml`.

**VEX**
- `/vulnetix:vex-publish` — generate [OpenVEX](openvex/) / [CycloneDX VEX](cyclonedx-vex/) from `.vulnetix/memory.yaml` triage decisions. **Auto-picks the format** ([PURL](glossary/#purl-package-url)-backed → CycloneDX VEX; everything else → OpenVEX). Optional cosign sign + Vulnetix upload + GitHub PR post.
- `/vulnetix:dashboard` — read `.vulnetix/memory.yaml`, surface CWSS-priority sorted entries by status (`under_investigation` / `affected` / `fixed` / `not_affected`) and decision.

**Supply-chain / lifecycle / triage queue**
- `/vulnetix:dep-add-guard <pkg>` — pre-install ALLOW / WARN / BLOCK gate composing vuln history, AI-malware, license, [EOL](eol/), maintainer-health, version-lag. Run before every `npm install`, `pip install`, `cargo add`.
- `/vulnetix:typosquat-check` — name-similarity heuristic against popular packages plus AI-malware family intelligence. See [supply-chain threats](supply-chain-threats/).
- `/vulnetix:kev-watch` — CISA + EU KEV catalogue watch against installed deps; deadline-driven action list.
- `/vulnetix:eol-check` — EOL detection for runtimes (Node, Python, Java, Go, .NET) and key packages; past-EOL items and items reaching EOL within 90 days.
- `/vulnetix:license-check` — package license analysis; copyleft conflicts against permissive policy.
- `/vulnetix:soc-triage` — daily SOC pull cross-referenced with installed dependencies; P1–P4 action list, filter by severity / ecosystem / KEV-only.
- `/vulnetix:incident-respond <CVE>` — end-to-end playbook for an actively exploited CVE (KEV/EPSS/sightings → IOCs → ATT&CK → patch path → VEX attestation).

**Code-level**
- `/vulnetix:code-review-security` — unified pre-merge SAST + SCA + secrets + container + IaC + license against the PR diff. Optional `gh pr review` posting.
- `/vulnetix:sast-scan` — static analysis on changed source files, optionally Semgrep-augmented.
- `/vulnetix:secret-scan` — hardcoded-secret detection.
- `/vulnetix:secure-code-write` — proactive secure-coding coach scoped to the file you're editing.

**Detection content**
- `/vulnetix:detection-rules <CVE>` — IDS/IPS detection content (Snort/Suricata, YARA, Nuclei, traffic-filters); capability-aware (skips families when the binary isn't installed).

## Sub-agents (multi-step orchestrators)

Sub-agents run the multi-step workflows that don't fit a single command. Each is invoked via the plugin's agent-spawning mechanism (the exact invocation varies per IDE).

- **`vulnetix:bulk-triage`** — parallel CWSS scoring across many vulnerabilities. Single consolidated `.vulnetix/memory.yaml` write at the end; P1–P4 grouped output.
- **`vulnetix:compliance-bundler`** — end-to-end compliance bundle. CycloneDX SBOM + SPDX licenses + SARIF findings + OpenVEX / CycloneDX VEX, optional cosign signing, optional Vulnetix upload, manifest.json with SHA-256 sums, Markdown index.
- **`vulnetix:dep-upgrade-orchestrator`** — end-to-end dependency upgrade across all manifests. Capabilities-detect → scan → plan-by-risk → apply-per-manifest → install → verify → loop on conflicts.
- **`vulnetix:incident-responder`** — full SOC playbook for an actively exploited CVE. Parallel sightings + KEV + IOCs + ATT&CK + fixes + remediation pull; capability-aware detection-rule deployment; optional patch path with verify-fix; VEX attestation publication.
- **`vulnetix:pr-security-reviewer`** — comprehensive pre-merge security review. Parallel SAST + SCA + secrets + container + IaC + license against the PR diff; dep-add-guard for new direct deps; optional `gh pr review` posting.
- **`vulnetix:safe-harbor-resolver`** — multi-step conflict resolver when `/vulnetix:fix` fails. Tries single bump retry → package-manager override → safe-harbour inline → workaround + detection-only mitigation.
- **`vulnetix:secure-code-coach`** — long-running coach for a feature branch. Proactive SAST + secret + secure-code reminders across multiple edits; re-checks after each edit batch; end-of-session unified review.

## Hooks (autonomous gates)

Hooks run automatically in response to editor / git / build events. Wire them in your editor's hook config (`hooks.claude.json`, `hooks.cursor.json`, `hooks.windsurf.json`, `hooks.copilot.json`, `hooks.gemini.json`, `hooks.codex.json`, `hooks.augment.json`, `hooks.cline.json`, etc. — the plugin ships one per supported editor).

The triage-relevant hooks:

- **`pre-commit-scan.sh`** — runs SAST + secret scan against staged changes before the commit lands.
- **`manifest-edit-scan.sh`** — when you edit `package.json`, `pom.xml`, `requirements.txt`, `go.mod`, etc., the hook re-scans and surfaces any new vulnerabilities introduced.
- **`dep-install-gate.sh`** — intercepts `npm install`, `pip install`, `cargo add` etc. and runs `dep-add-guard` before letting the install proceed.
- **`dockerfile-edit-gate.sh`** — Dockerfile edits trigger container-rule evaluation (`USER`, pinned tags, healthcheck, `ADD` vs `COPY`, etc.).
- **`iac-edit-gate.sh`** + **`terraform-apply-gate.sh`** — IaC edits and `terraform apply` invocations trigger misconfiguration scans.
- **`git-push-gate.sh`** — blocks pushes that contain secrets or that introduce HIGH/CRITICAL findings without VEX coverage.
- **`post-install-scan.sh`** — after a package-manager install completes, runs an SCA scan to catch anything `dep-add-guard` missed in resolution.

## CLI wrappers

The plugin shells out to the Vulnetix CLI so you don't have to memorise the invocations. Skills cover the common patterns; the CLI commands themselves are still available for ad-hoc work:

- Scanning: `vulnetix scan`, `vulnetix triage`, `vulnetix sca`, `vulnetix sast`, `vulnetix containers`, `vulnetix iac`, `vulnetix secrets`, `vulnetix license`, `vulnetix upload`.
- VDB queries: `vulnetix vdb vuln`, `vdb fixes`, `vdb remediation`, `vdb sightings`, `vdb iocs`, `vdb attack-techniques`, `vdb kev`, `vdb yara-rules`, `vdb snort-rules`, `vdb traffic-filters`, `vdb nuclei`, `vdb vex`, `vdb sources`, `vdb summary`, `vdb metrics`, and ~40 more.

## How it removes the VEX-format burden

The earlier version of this site asked the developer to decide between [CycloneDX VEX](cyclonedx-vex/) and [OpenVEX](openvex/) per finding. With the AI Coding Agent the decision goes away:

1. As you run `/vulnetix:vuln`, `/vulnetix:exploits`, `/vulnetix:fix`, and `/vulnetix:verify-fix`, each command writes its decision into `.vulnetix/memory.yaml`.
2. When you run `/vulnetix:vex-publish`, the plugin reads the memory file, classifies every entry by subject:
   - Entry with a [PURL](glossary/#purl-package-url) → emit a CycloneDX VEX entry into `.vulnetix/vex.cdx.json` (SBOM-coupled).
   - Entry without a PURL (SAST in first-party code, secret leak, repo-state finding) → emit an OpenVEX statement into `.vulnetix/vex.openvex.json` (standalone).
3. Optional cosign sign of both files.
4. Optional upload to Vulnetix + optional comment-post to the originating GitHub PR.

The developer never picks a format. The plugin picks one consistent with the artefact, generates both attestations if some entries are PURL-backed and others aren't, and signs them.

## Why this matters to a developer

The same five reasons that justify writing [VEX](vex/) by hand apply here, but more strongly:

- **Future-you doesn't need to remember the format.** The plugin picked one consistent with the artefact.
- **Past decisions are durable.** `.vulnetix/memory.yaml` is committed to the repo; every triage decision is reproducible.
- **Colleagues see less noise.** The same `--vex` consumption loop ([Grype](../scanners/grype/), [Trivy](../scanners/trivy/), Vulnetix) suppresses findings the plugin's `/vulnetix:vex-publish` has already attested.
- **Compliance is already done.** The compliance-bundler agent produces a single ZIP with SBOM + SPDX + SARIF + VEX + cosign signatures + a manifest, ready for audit.
- **The decision burden moves to the tool.** The whole point of the plugin is that you stay in the code, not in a security UI.

## Reference

- Upstream docs: [ai-docs.vulnetix.com/docs](https://ai-docs.vulnetix.com/docs).
- Repository: [github.com/Vulnetix/pix-ai-coding-assistant](https://github.com/Vulnetix/pix-ai-coding-assistant).
- Editor support: Claude Code, Cursor, Windsurf, Copilot, Gemini, Codex, Augment, Cline, Amazon Q, OpenHands, Codebuddy, Cortex, Qoder, Qwen, Kiro, iFlow. Per-IDE setup detail in the upstream docs.

## See also

- [VEX overview](vex/) — what the plugin auto-generates.
- [CycloneDX VEX](cyclonedx-vex/) and [OpenVEX](openvex/) — the two formats `/vulnetix:vex-publish` picks between.
- [SSVC Engineer Triage](ssvc/) — the framework `/vulnetix:exploits` and `/vulnetix:fix` apply.
- [Reachability deep-dive](reachability-deep-dive/) — Vulnetix's Tier-3 semantic model.
- [Supply-chain threats](supply-chain-threats/) — what `/vulnetix:typosquat-check` and `/vulnetix:dep-add-guard` detect.
- [EOL appendix](eol/) — what `/vulnetix:eol-check` and `--block-eol` gate against.
- [Glossary](glossary/).
- [Capability matrix](../scanners/#capability-matrix) — Vulnetix's row, end-to-end.
