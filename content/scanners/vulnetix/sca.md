---
title: "SCA — dependency vulnerabilities"
description: "Triaging SCA findings: every package manager, lockfile mechanics, transitive coercion, reachability analysis per language."
weight: 10
---

SCA is where most vulnerability work starts and where most of it ends. A scanner finds a vulnerable component in your dependency graph; you decide whether the vulnerable code is reachable in your build, then either upgrade, mitigate at runtime, or write a `not_affected` VEX statement with a sharp justification. The hard part isn't the decision — it's the mechanics: which lockfile to edit, how to coerce a transitive that you don't declare directly, how to actually check reachability in the language at hand.

This page covers all of that.

## What SCA finds in Vulnetix output

SCA findings appear in `.vulnetix/sbom.cdx.json`. Two structures matter for triage:

**`components[]`** — the resolved component graph. Each entry carries:

- `bom-ref` — the local identifier used to reference this component from `dependencies[]` and `vulnerabilities[]`.
- `purl` — the canonical package URL: `pkg:<ecosystem>/<namespace>/<name>@<version>`. This is the only field you need to reference the same component in a CycloneDX VEX.
- `version`, `name`, `type` (`library`, `framework`, `application`).
- `hashes[]` — integrity hashes from the registry. Match against the lockfile to detect tampering.
- `licenses[]` — SPDX identifiers when resolvable.

```bash
# Every component as {purl, version, type}
jq '.components[] | {purl, version, type}' .vulnetix/sbom.cdx.json

# One component by name
jq '.components[] | select(.name == "log4j-core")' .vulnetix/sbom.cdx.json

# All npm components only
jq '.components[] | select(.purl | startswith("pkg:npm/")) | .purl' \
   .vulnetix/sbom.cdx.json

# Components missing licence metadata
jq '.components[] | select(.licenses == null or (.licenses | length == 0)) | .purl' \
   .vulnetix/sbom.cdx.json
```

**`dependencies[]`** — the resolved graph as a list of `{ref, dependsOn[]}` records. Walk this backwards from a transitive finding to the top-level dep that pulled it in. The walk is the single most useful triage step in SCA.

```bash
# Forward walk: what does X depend on?
jq --arg ref "log4j-core@2.14.1" \
   '.dependencies[] | select(.ref == $ref) | .dependsOn' \
   .vulnetix/sbom.cdx.json

# Backward walk: who depends on X? — the canonical triage query
jq --arg target "log4j-core@2.14.1" \
   '.dependencies[] | select(.dependsOn | index($target)) | .ref' \
   .vulnetix/sbom.cdx.json

# Full transitive parentage of X (walk back until you hit a root)
jq --arg target "log4j-core@2.14.1" '
  def parents($t):
    [.dependencies[] | select(.dependsOn | index($t)) | .ref]
    | unique
    | if length == 0 then $t
      else . + (.[] | parents(.) | if type == "array" then . else [.] end)
      end ;
  parents($target)
' .vulnetix/sbom.cdx.json
```

When vulnerabilities are embedded inline, they appear under `vulnerabilities[]`:

- `id` — the CVE, GHSA, or vendor advisory ID.
- `source` — where the metadata came from.
- `ratings[]` — severity, optionally with CVSS vector.
- `affects[].ref` — the affected component's `bom-ref` (resolves to a PURL).
- `analysis` — Vulnetix's own assessment when one is available; if present, it's a starting point, not the final word.

```bash
# Every vuln with severity + affected PURLs
jq '.vulnerabilities[] | {
      id,
      severity: .ratings[0].severity,
      affects: [.affects[].ref]
    }' .vulnetix/sbom.cdx.json

# Critical only
jq '.vulnerabilities[] | select(.ratings[]?.severity == "critical") | .id' \
   .vulnetix/sbom.cdx.json

# Group by severity for a triage queue
jq '[.vulnerabilities[]
     | {id, severity: .ratings[0].severity}]
    | group_by(.severity)
    | map({severity: .[0].severity, count: length, ids: [.[].id]})' \
   .vulnetix/sbom.cdx.json

# Vulns Vulnetix already has an analysis on
jq '.vulnerabilities[]
    | select(.analysis != null)
    | {id, state: .analysis.state, justification: .analysis.justification}' \
   .vulnetix/sbom.cdx.json
```

### Gating signals to read first

Vulnetix's CI flags double as triage signals. If the scan failed because of one of these, the finding belongs at the top of your queue:

- `--severity high|critical` — standard severity gate.
- `--block-malware` — the package is on a known-malicious list. Treat as an incident, not a CVE: see the [xz-utils worked example](#worked-example-cve-2024-3094-xz-utils-backdoor).
- `--block-eol` — the runtime or a dependency is past end-of-life. No patches will be issued.
- `--block-unpinned` — a direct dependency uses a version range. Pin it before the next upgrade catches you out.
- `--exploits poc|active|weaponized` — the vuln has known exploit code at this maturity. KEV-listed CVEs typically hit `weaponized`.
- `--version-lag N` — your dep is N or more releases behind. Catches stale deps before they become vulnerable.
- `--cooldown N` — the dep was published within N days. Defends against typosquats and account-takeover supply-chain attacks.

## From finding to root cause

The universal six-step path, each step with the exact `jq` or CLI to run.

```bash
# Step 1 — read the PURL for one finding (start with the first critical)
jq -r '.vulnerabilities[]
       | select(.ratings[]?.severity == "critical")
       | .affects[0].ref' .vulnetix/sbom.cdx.json | head -1
# e.g. "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"

# Step 2 — backward-walk the dep graph to find the declared top-level
PURL="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
jq --arg p "$PURL" '
  .components[] as $c
  | select($c.purl == $p)
  | .["bom-ref"]
' .vulnetix/sbom.cdx.json
# Then feed that bom-ref to the backward-walk query in the previous section.

# Step 3 — pull the prioritisation signal as input to Engineer Triage
#   vulnetix exposes the CISA Coordinator SSVC decision; use it as the
#   `priority` input to the developer-side Engineer Triage methodology.
#   See ../../appendices/ssvc/ for the framework and the decision tree.
vulnetix vdb vuln CVE-2021-44228 --output json \
  | jq '.[0].containers.adp[0] | {
          coordinator_decision: .x_ssvc.decision,
          exploitation: .x_exploitationMaturity.level,
          kev: .x_kev.knownRansomwareCampaignUse,
          epss: .x_exploitationMaturity.factors.epss
        }'
# →  { "coordinator_decision": "Act", "exploitation": "ACTIVE",
#      "kev": "Known", "epss": 0.94 }
# Engineer Triage priority = CRITICAL (Coordinator=Act + ACTIVE exploitation + KEV)

# Step 4 — patches and workarounds per registry, with exploit maturity
vulnetix vdb fixes CVE-2021-44228

# Step 5 — context-aware fix recommendation
vulnetix vdb remediation plan \
  --purl "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" \
  --current-version 2.14.1 \
  --include-guidance \
  --include-verification-steps

# Step 6 — reachability check (see the per-language section below),
# then produce the VEX statement.
```

If a code-level fix isn't immediately possible — patch is pending, transitive coercion has compatibility risk, the dep is part of a frozen vendor binary — the Vulnetix CLI itself can supply the mitigating rules so you don't have to author them from scratch:

```bash
# Snort / Suricata signatures attached to the CVE
vulnetix vdb traffic-filters CVE-2021-44228
vulnetix vdb snort-rules get CVE-2021-44228 --format rules > log4shell.rules

# Nuclei templates to verify an exploit is reachable from outside the WAF
vulnetix vdb nuclei get CVE-2021-44228 --format yaml > log4shell.yaml
nuclei -t log4shell.yaml -u https://staging.example.com

# IOC pivots — IPs, ASNs, ATT&CK techniques observed exploiting the CVE
vulnetix vdb iocs CVE-2021-44228
vulnetix vdb iocs list --cve-id CVE-2021-44228 --format stix > log4shell.stix.json
```

Deploy the rule, run the Nuclei template against staging to confirm the WAF blocks the attack vector, then write the CycloneDX VEX with `analysis.response: ["workaround_available"]` and reference the rule ID in `analysis.detail`.

Decision criteria for step 6: if the vulnerable function in the dep isn't reachable from your code, `not_affected` is honest and durable. If it is, upgrade or mitigate, then `resolved` / `exploitable + workaround_available`.

## Patching — the lockfile mechanics

Lockfile mechanics, transitive-dependency coercion, integrity verification, and the gotchas are the same regardless of which scanner surfaced the finding. They live in the **[package managers appendix](../../../appendices/package-managers/)** — one page per language family, with the [transitive-coercion quick-reference table](../../../appendices/package-managers/#transitive-coercion-quick-reference) on the bundle's landing page for fast lookup.

The worked examples below link to the relevant appendix page from each patching step.

## Reachability

The question is always the same: *is the vulnerable function in the dependency actually called from any code path that runs in production?* If not, OpenVEX `not_affected` with `vulnerable_code_not_in_execute_path` is the honest answer and saves you from a noisy upgrade.

The practical rule: combine a **static check** (does our code import the vulnerable symbol?) with a **dynamic check** (does the code that imports it actually run under coverage?). If both come back negative, you have evidence for the VEX.

Each [package managers appendix page](../../../appendices/package-managers/) carries the static and runtime reachability tooling for its ecosystem. The summary by language is on the page that matches your stack — [JavaScript](../../../appendices/package-managers/javascript/#reachability), [Python](../../../appendices/package-managers/python/#reachability), [JVM](../../../appendices/package-managers/jvm/#reachability), [Go](../../../appendices/package-managers/go/#reachability), [Rust](../../../appendices/package-managers/rust/#reachability), [Ruby](../../../appendices/package-managers/ruby/#reachability), [.NET](../../../appendices/package-managers/dotnet/#reachability), [PHP](../../../appendices/package-managers/php/#reachability), [Swift / iOS](../../../appendices/package-managers/swift-ios/#reachability), [other ecosystems](../../../appendices/package-managers/other/#cc-reachability-conan--vcpkg).

### JavaScript / TypeScript

- Static: `npm ls <pkg> --all` walks the dep tree to show every path that pulls in the pkg. `madge --image graph.svg src/` visualises the import graph of your own code.
- Bundler analysis: `esbuild --bundle --metafile=meta.json src/index.ts` produces a JSON metafile listing every imported symbol; `grep` for the vulnerable function name confirms reach.
- Runtime: c8 / nyc coverage during integration tests. If the file that imports the vulnerable lib never gets covered, the static reach is dead in practice.

### Python

- Static: `pip show <pkg>` shows direct/transitive relationships. `pydeps <module>` renders the import graph. `python -c "import sys; print('vuln_fn' in dir(__import__('pkg')))"` confirms the symbol exists.
- Reachability: `coverage.py` with `--branch` during a representative test run. A module imported but never run is `vulnerable_code_not_in_execute_path`.

### Java

- Static: `mvn dependency:tree -Dincludes=group:artifact` shows the path. `jdeps --multi-release 17 --print-module-deps target/myapp.jar` reports class-level reachability. For full static analysis: SootUp or WALA produce a call graph; query for the vulnerable method's class+signature.
- Runtime: JaCoCo coverage on integration tests. If the class containing the vuln isn't covered, document it.

### Go

- Static: `go mod why <module>` produces the import chain from your main module to a target. `go list -deps -json ./... | jq` walks every transitive. `go tool callgraph -algo=cha` from `golang.org/x/tools/cmd/callgraph` produces a static call graph.
- Runtime: `go test -coverprofile=cover.out ./... && go tool cover -html=cover.out`.

### Rust

- Static: `cargo tree -p <crate> -e features --invert` shows what depends on the crate. `cargo-callgraph` or `cargo-modules` for symbol-level analysis.
- Runtime: `cargo tarpaulin` for coverage, or `cargo llvm-cov` on nightly.

### Ruby

- Static: `bundle viz` produces a Graphviz of the gem graph. `bundle show --paths` lists every gem's source. For call analysis: `ruby-static-analyzer` or runtime tracing with `TracePoint`.
- Runtime: SimpleCov.

### C# / .NET

- Static: `dotnet list package --include-transitive` enumerates the graph. Roslyn analyzers (`Microsoft.CodeAnalysis`) can query for method calls; `dotnet build /p:RunAnalyzers=true`.
- Runtime: dotCover or `coverlet` integrated with `dotnet test`.

### PHP

- Static: `composer show -t <pkg>` produces a tree. `phpcallgraph` for method-level reachability.
- Runtime: Xdebug code coverage.

### C / C++

- Static: linker map (`gcc -Wl,--print-map`), then `nm`, `readelf`, or `objdump` for symbol enumeration. `cflow` for source-level call graphs.
- Runtime: Valgrind callgrind (`valgrind --tool=callgrind`) under a representative load.

### Swift

- Static: `swift package show-dependencies --format json | jq` for the resolved graph. The Xcode call graph instrument shows runtime call edges.
- Runtime: `xcodebuild -enableCodeCoverage YES`.

### Dart

- Static: `dart pub deps` lists the graph. `dart analyze` for symbol-level analysis.
- Runtime: `dart test --coverage`.

### Elixir

- Static: `mix xref graph --format dot` for cross-module call graph. `mix xref callers <module>.<function>/<arity>` answers reachability directly.
- Runtime: `mix coveralls`.

### What constitutes evidence

A clean negative on both static (function not imported or imported but only in dead branches) and dynamic (file containing the call site has no test or production coverage) is enough to write a CycloneDX VEX with:

```json
"analysis": {
  "state": "not_affected",
  "justification": "code_not_reachable",
  "detail": "Static analysis with <tool> shows <vulnerable.function> is imported via <path> but not called. Runtime coverage under <test suite> confirms the importing module is never executed in production code paths. Verified <date>."
}
```

The bar is *evidence*, not certainty — auditors and future-you both want to see the methodology, not just the conclusion.

## Worked example: CVE-2021-44228 (Log4Shell)

The shape of the relevant slice of `.vulnetix/sbom.cdx.json`:

```json
{
  "components": [
    { "bom-ref": "log4j-core@2.14.1", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "version": "2.14.1" }
  ],
  "dependencies": [
    { "ref": "myapp@1.0.0", "dependsOn": ["spring-boot-starter-web@2.5.6"] },
    { "ref": "spring-boot-starter-web@2.5.6", "dependsOn": ["spring-boot-starter-logging@2.5.6"] },
    { "ref": "spring-boot-starter-logging@2.5.6", "dependsOn": ["log4j-core@2.14.1"] }
  ],
  "vulnerabilities": [
    { "id": "CVE-2021-44228", "affects": [{ "ref": "log4j-core@2.14.1" }] }
  ]
}
```

Extract the chain from the real artefact:

```bash
# Confirm the finding is present
jq '.vulnerabilities[] | select(.id == "CVE-2021-44228")' .vulnetix/sbom.cdx.json

# Trace the chain up to the root
jq --arg target "log4j-core@2.14.1" '
  def ancestors($t):
    .dependencies[]
    | select(.dependsOn | index($t))
    | .ref ;
  [ancestors($target)]
' .vulnetix/sbom.cdx.json
# → ["spring-boot-starter-logging@2.5.6"]

# Run again with the parent to keep walking
jq --arg target "spring-boot-starter-logging@2.5.6" '
  [.dependencies[] | select(.dependsOn | index($target)) | .ref]
' .vulnetix/sbom.cdx.json
# → ["spring-boot-starter-web@2.5.6"]
# → eventually reaches "myapp@1.0.0" (your top-level)
```

Two coercion paths:

{{< tabs >}}
{{< tab name="bump Spring Boot" >}}
```xml
<parent>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-parent</artifactId>
  <version>2.7.18</version>
</parent>
```
This bumps the Spring Boot BOM which in turn upgrades log4j-core to a safe version.
{{< /tab >}}
{{< tab name="pin log4j-core directly" >}}
```xml
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.17.1</version>
    </dependency>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-api</artifactId>
      <version>2.17.1</version>
    </dependency>
  </dependencies>
</dependencyManagement>
```
This pins log4j-core even when Spring Boot's BOM resolves an older version. Use when you can't bump Spring Boot for compatibility reasons.
{{< /tab >}}
{{< /tabs >}}

Now build the reachability check. Pull `x_affectedRoutines` from the enriched vuln record — it's the canonical list of affected functions and files, deduplicated from the CVE 5.x `programRoutines` / `programFiles` plus the AI-derived `x_affectedFunctions`.

```bash
# Fetch the full advisory enrichment
vulnetix vdb vuln CVE-2021-44228 --output json > /tmp/cve.json

# Severity + KEV + EPSS + Coordinator decision in one shot
jq '.[0].containers.adp[0] | {
      exploitation: .x_exploitationMaturity.level,
      epss: .x_exploitationMaturity.factors.epss,
      kev_listed: .x_kev.knownRansomwareCampaignUse,
      coordinator: .x_ssvc.decision,
      attack_surface: .x_attackSurface.reasoning,
      cwes: .x_kev.cwes
    }' /tmp/cve.json
# →  {
#      "exploitation": "ACTIVE",
#      "epss": 0.94,
#      "kev_listed": "Known",
#      "coordinator": "Act",
#      "attack_surface": "Remotely exploitable; Low complexity; No privileges; No user interaction",
#      "cwes": ["CWE-20", "CWE-400", "CWE-502"]
#    }

# The affected functions and files — what to grep for
jq '.[0].containers.adp[0].x_affectedRoutines' /tmp/cve.json
# →  [
#      { "kind": "function", "name": "org.apache.logging.log4j.core.lookup.JndiLookup.lookup" },
#      { "kind": "function", "name": "org.apache.logging.log4j.core.pattern.MessagePatternConverter.format" },
#      { "kind": "file", "path": "log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/JndiLookup.java" },
#      ...
#    ]

# Attack paths — tactic → ATT&CK techniques
jq '.[0].containers.adp[0].x_attackPaths' /tmp/cve.json
# →  [
#      { "tactic": "Initial Access",
#        "techniques": [{ "id": "T1190", "name": "Exploit Public-Facing Application", "relation": "primary_method" }] },
#      { "tactic": "Execution",
#        "techniques": [{ "id": "T1059", "name": "Command and Scripting Interpreter", "relation": "post_exploit" }] }
#    ]
```

If `x_affectedRoutines` isn't yet populated for the CVE (the AI enrichment hasn't run, or you're on a stale cache), fall back to the patch PR — the URL is in `vdb fixes`:

```bash
vulnetix vdb fixes CVE-2021-44228 --output json \
  | jq '.fixes.sourceCode[] | select(.type == "pr") | .url' | sort -u
# →  "https://github.com/apache/logging-log4j2/pull/608"
```

Either way, you end up with class/function names to grep your codebase for:

```bash
# Static: are the affected routines actually in your build's classpath?
jq -r '.[0].containers.adp[0].x_affectedRoutines[]
       | select(.kind == "function") | .name' /tmp/cve.json \
  | xargs -I{} jdeps --multi-release 17 --print-module-deps target/myapp.jar 2>&1 \
  | grep -i '{}'

# Source-level: do you log anything from request data without scrubbing?
git grep -nE 'logger\.(info|warn|error|debug|trace)\([^)]*(request|req\.|input|userAgent|param)' \
  src/main/java/

# Find any log4j2.properties / log4j2.xml that set formatMsgNoLookups
git grep -nE 'formatMsgNoLookups|log4j2.formatMsgNoLookups' .

# Did the build's log4j-core actually load? (CycloneDX dependencies graph)
jq '.dependencies[] | select(.dependsOn | index("log4j-core@2.14.1"))' .vulnetix/sbom.cdx.json
```

If the app uses Logback (Spring Boot's default) and log4j-core is only on the classpath as a transitive — `JndiLookup.lookup` never instantiated, no `MessagePatternConverter.format` call site reachable from request input — Engineer Triage's `Reachability` resolves to `VERIFIED_UNREACHABLE`, and the VEX justification is `vulnerable_code_not_in_execute_path`. The `x_affectedRoutines` list + the jdeps output + the grep evidence is what goes in the `analysis.detail`.

The `x_attackPaths` data isn't used for reachability — it drives **detection-rule selection** for the WAF / IPS / SIEM layer. Feed each technique ID to `vdb snort-rules` and `vdb nuclei` to pull the existing detection content per attack path:

```bash
jq -r '.[0].containers.adp[0].x_attackPaths[]
       | .techniques[] | .id' /tmp/cve.json | sort -u \
  | while read tid; do
      echo "== ATT&CK $tid =="
      vulnetix vdb snort-rules list --technique "$tid" --severity high --limit 5
    done
```

{{< outcome type="cyclonedx" >}}
```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2021-44228",
      "affects": [
        { "ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1",
          "versions": [
            { "version": "2.14.1", "status": "affected" },
            { "version": "2.17.1", "status": "unaffected" }
          ] }
      ],
      "analysis": {
        "state": "resolved",
        "detail": "Pinned log4j-core to 2.17.1 in pom.xml's <dependencyManagement>. mvn dependency:tree confirms no transitive still resolves a vulnerable version. Spring Boot stays on 2.5.6 for compatibility. See MR !128."
      }
    }
  ]
}
```
{{< /outcome >}}

## Worked example: CVE-2022-23541 (jsonwebtoken)

Vulnetix flags `pkg:npm/jsonwebtoken@8.5.1`. Confirm and trace from the SBOM:

```bash
jq '.vulnerabilities[] | select(.id == "CVE-2022-23541")' .vulnetix/sbom.cdx.json

# Every direct parent of jsonwebtoken@8.5.1
jq --arg target "jsonwebtoken@8.5.1" \
   '[.dependencies[] | select(.dependsOn | index($target)) | .ref]' \
   .vulnetix/sbom.cdx.json
```

`npm ls jsonwebtoken` confirms the same paths in human-readable form:

```
yourapp@1.0.0
├─┬ express-jwt@7.0.0
│ └── jsonwebtoken@8.5.1
├─┬ next-auth@4.10.0
│ └── jsonwebtoken@8.5.1
└─┬ jose-helper@2.1.0
  └── jsonwebtoken@8.5.1
```

Three top-level libraries all transit jsonwebtoken. Coerce once:

{{< tabs >}}
{{< tab name="npm" >}}
```json
{
  "overrides": {
    "jsonwebtoken": "^9.0.2"
  }
}
```
{{< /tab >}}
{{< tab name="yarn" >}}
```json
{
  "resolutions": {
    "jsonwebtoken": "^9.0.2"
  }
}
```
{{< /tab >}}
{{< tab name="pnpm" >}}
```json
{
  "pnpm": {
    "overrides": {
      "jsonwebtoken": "^9.0.2"
    }
  }
}
```
{{< /tab >}}
{{< /tabs >}}

Reachability: search the source for `jwt.verify` and `jwt.decode` call sites; check whether any use a JWT that originated from an attacker-controllable channel. If only used for first-party-issued service tokens with HS256 + a known issuer, the algorithm-confusion vector is contained.

{{< outcome type="cyclonedx" >}}
```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2022-23541",
      "affects": [
        { "ref": "pkg:npm/jsonwebtoken@9.0.2",
          "versions": [
            { "version": "8.5.1", "status": "affected" },
            { "version": "9.0.2", "status": "unaffected" }
          ] }
      ],
      "analysis": {
        "state": "resolved",
        "detail": "Coerced jsonwebtoken to 9.0.2 via package.json overrides. All three transit paths (express-jwt, next-auth, jose-helper) now resolve 9.0.2. Verified with npm ls jsonwebtoken. See MR !302."
      }
    }
  ]
}
```
{{< /outcome >}}

## Worked example: CVE-2024-3094 (xz-utils backdoor)

This is qualitatively different. The package isn't vulnerable in the CVE sense — it was deliberately backdoored. Vulnetix fires through `--block-malware`, not just `--severity`:

```bash
vulnetix scan --block-malware
# Exit 1: pkg:generic/xz-utils@5.6.0 — malware indicator
```

The action sequence is incident response, not a normal upgrade:

1. **Downgrade immediately** to a known-clean version (`5.4.6` is the pre-backdoor branch).
2. **Audit any build host or developer machine** that pulled the affected version. If the affected version was installed, treat the host as potentially compromised — rotate SSH keys, audit auth logs, check for unexpected processes.
3. **Audit any binary built on an affected host** — the backdoor was sshd-targeted but in principle could have affected anything linked against the compromised liblzma.
4. **Document the rollback** in the CycloneDX VEX, not just the upgrade.

{{< outcome type="cyclonedx" >}}
```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2024-3094",
      "affects": [
        { "ref": "pkg:generic/xz-utils@5.4.6",
          "versions": [
            { "version": "5.6.0", "status": "affected" },
            { "version": "5.6.1", "status": "affected" },
            { "version": "5.4.6", "status": "unaffected" }
          ] }
      ],
      "analysis": {
        "state": "resolved",
        "detail": "Rolled back xz-utils from 5.6.0 to 5.4.6 on 2024-03-29 across all build images. Audited build hosts for evidence of exploitation (none found). Rotated SSH host keys on affected runners. See incident INC-2024-014."
      }
    }
  ]
}
```
{{< /outcome >}}

## EOL gating and `--block-eol`

EOL findings don't have a CVE — the runtime or package is simply past its support window, so no patches will be issued for future vulnerabilities. Vulnetix flags these via the embedded EOL database. Check ad-hoc:

```bash
vulnetix vdb eol package npm jsonwebtoken 8.5.1
vulnetix vdb eol product python 3.7
```

Three actions are possible:

1. **Upgrade past EOL** — usually the right answer. Plan it as a deliberate piece of work, not a rushed fix.
2. **Accept and document** — sometimes business reality means the runtime stays on an EOL version. The OpenVEX statement is `affected` with a clear `action_statement` naming the compensating controls (isolated network, no internet access, manual security patches).
3. **Decommission** — for a service no longer worth maintaining, replace or retire.

EOL findings always go to **OpenVEX**, not CycloneDX VEX — the subject is the deployment / runtime, not a packaged component with a vulnerability advisory.

## Producing the CycloneDX VEX

Field-by-field reference, then three full examples covering the common analysis states.

| Field | Value |
|---|---|
| `vulnerabilities[].id` | The CVE / GHSA / vendor ID |
| `vulnerabilities[].source.name` | `NVD`, `GitHub`, `OSV`, etc. |
| `vulnerabilities[].ratings[]` | Severity + method (`CVSSv3`, `CVSSv4`) |
| `vulnerabilities[].affects[].ref` | The PURL of the affected component (matches an SBOM `bom-ref`) |
| `vulnerabilities[].affects[].versions[]` | Per-version `status: affected\|unaffected` |
| `vulnerabilities[].analysis.state` | `not_affected`, `in_triage`, `exploitable`, `resolved`, `resolved_with_pedigree`, `false_positive` |
| `vulnerabilities[].analysis.justification` | When `not_affected`: `code_not_present`, `code_not_reachable`, `requires_configuration`, `requires_dependency`, `requires_environment`, `protected_by_compiler`, `protected_at_runtime`, `protected_at_perimeter`, `protected_by_mitigating_control` |
| `vulnerabilities[].analysis.response[]` | When `exploitable`: `will_not_fix`, `update`, `rollback`, `workaround_available`, `can_not_fix` |
| `vulnerabilities[].analysis.detail` | Free-text explanation — the field future-you will actually read |

{{< tabs >}}
{{< tab name="not_affected" >}}
```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2024-12345",
      "affects": [{ "ref": "pkg:npm/vulnerable-lib@1.2.3" }],
      "analysis": {
        "state": "not_affected",
        "justification": "code_not_reachable",
        "detail": "vulnerable-lib's parseXML() is imported by our request validator but the validator's XML branch is dead code — the application uses JSON exclusively. Verified in MR !88 with a coverage report showing parseXML never executes in the production build."
      }
    }
  ]
}
```
{{< /tab >}}
{{< tab name="exploitable + workaround" >}}
```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2024-12345",
      "affects": [{ "ref": "pkg:npm/vulnerable-lib@1.2.3" }],
      "analysis": {
        "state": "exploitable",
        "response": ["workaround_available"],
        "detail": "ModSecurity rule 10001 blocks the path-traversal vector at the WAF. Rule deployed 2026-05-14. Patch upgrade to vulnerable-lib@1.2.4 tracked in issue #99 for sprint 24."
      }
    }
  ]
}
```
{{< /tab >}}
{{< tab name="resolved" >}}
```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2024-12345",
      "affects": [{
        "ref": "pkg:npm/vulnerable-lib@1.2.4",
        "versions": [
          { "version": "1.2.3", "status": "affected" },
          { "version": "1.2.4", "status": "unaffected" }
        ]
      }],
      "analysis": {
        "state": "resolved",
        "detail": "Upgraded vulnerable-lib from 1.2.3 to 1.2.4 in commit abc1234. Coerced via package.json overrides because the dep is transitive through three different runtime libraries. See MR !42."
      }
    }
  ]
}
```
{{< /tab >}}
{{< /tabs >}}
