---
title: "Reachability — the three-tier model"
description: "Stated booleans vs real call-graph evaluation vs semantic intent-to-use. The model the SSVC Reachability input is graded against, and where each scanner sits on it."
weight: 22
---

[SSVC Engineer Triage](ssvc/) takes a single value for `Reachability` — `VERIFIED_REACHABLE`, `VERIFIED_UNREACHABLE`, or `UNKNOWN`. Behind those three labels sit three very different *grades of evidence*. A finding called "VERIFIED_UNREACHABLE" because the affected function doesn't appear in your built JAR is meaningfully different from one called "VERIFIED_UNREACHABLE" because a static call graph proves no path from your entry points to it — and different again from one called "VERIFIED_REACHABLE" because the affected class is wired in via Spring auto-configuration even though no static call edge exists.

The site grades reachability evidence on three tiers. Each scanner sits at a tier — see the [capability matrix](../../scanners/#capability-matrix). Pick the tier that matches the strength of the claim you need to defend.

For terminology used here, see the [Glossary](glossary/).

## Tier 1 — Stated booleans

**Claim**: the affected component is present in the build.

**How it's established**: read the manifest / lockfile / package metadata. The artefact's name and version appear in `package-lock.json`, `pom.xml`, `go.sum`, `Cargo.lock`, `requirements.txt`. The scanner queries its vulnerability database for that name+version, finds a CVE, raises a finding.

**What it proves**: the *package* exists in the build. Nothing about whether your code calls anything in the package, whether the affected function is in the JAR/binary at all, or whether the path that reaches it is alive.

**What you can defend with it**:
- `VERIFIED_REACHABLE` only as a worst-case ("the package is there; we have no reason to think the affected function won't be exercised").
- `VERIFIED_UNREACHABLE` *only* if the package is genuinely absent from the runtime artefact (test-scope-only Maven dep, npm `devDependency` that prod doesn't install, `--omit=dev`, scope demotion).
- Otherwise → `UNKNOWN` (which the [SSVC tree](ssvc/) treats as `VERIFIED_REACHABLE`).

**Cost**: zero. The scanner already did the work.

**Tools that stop here**: [Dependabot](../../scanners/github-dependabot/), [osv-scanner](../../scanners/osv-scanner/), [Grype](../../scanners/grype/), [Snyk OSS](../../scanners/snyk-oss/) (without the reachability-enabled Deep Test add-on), [GitLab Dependencies](../../scanners/gitlab-dependencies/) (gemnasium).

**Practical Tier-1 verification commands**:

```bash
# Is the package even in the runtime install?
npm ls <pkg>                                  # node
mvn dependency:tree -Dscope=runtime           # maven
pip show <pkg>                                # python
go list -m <module>                           # go

# Is the class/symbol in the built artefact?
jar tf target/myapp.jar | grep <class-path>   # JVM uber-JAR
unzip -l dist/bundle.js | grep <symbol>       # JS bundle
nm myapp | grep <symbol>                      # native binary

# Container — is the package in the *runtime* image, or only in a build stage?
docker build --target=runtime -t myapp:rt .
grype myapp:rt -o json | jq '.matches[].artifact.purl'
```

Tier 1 is fast, cheap, and the right answer for most P3/P4 findings. Treat it as the *floor*: every SSVC `Reachability` decision should at minimum have Tier-1 evidence behind it.

## Tier 2 — Real call-graph evaluation

**Claim**: a static analyser has built an interprocedural call graph and proved (or disproved) an edge from your code's entry points to the affected method.

**How it's established**: pick a call-graph algorithm, run it over the compiled bytecode / IR / source, query for the affected symbol. The algorithm dictates precision/coverage trade-offs:

- **CHA (Class Hierarchy Analysis)**: every virtual call dispatches to every override in the hierarchy. Fast, coarse — *over-approximates* the call set. Used by SootUp's default. Good for "the symbol is *not* reachable" claims because if CHA can't find it, finer analyses won't either. Bad for "the symbol *is* reachable" claims because CHA may report false-positive edges.
- **RTA (Rapid Type Analysis)**: a tighter version of CHA that only considers types actually instantiated. Smaller call graph; still over-approximates because instantiation may be control-dependent.
- **VTA (Variable Type Analysis)**: tracks the types that can flow into each variable. More precise; more expensive.
- **Pointer analysis**: tracks which objects a variable can point to. The most precise common technique; expensive at scale (minutes-to-hours on large codebases). Doop, WALA, OPAL all support points-to.
- **Taint flow** (a specialisation): tracks data from a *source* (often user input) through transformations to a *sink* (a dangerous operation). The output is a [codeFlow](sarif/#codeflow--the-taint-trace) in SARIF. CodeQL, Snyk SAST, Semgrep Pro all produce taint flows.

**What it proves**:
- "Edge exists in graph X → the affected method is reachable from entry points in graph X." Whether that's enough depends on whether graph X captures the real execution model — see the limits below.
- "No edge in graph X → the affected method is unreachable *under the assumptions graph X makes*." Strong evidence for `VERIFIED_UNREACHABLE` *if* the assumptions hold.

**What it doesn't prove**:
- Reflection (`Class.forName`, `Method.invoke`) — call edges are constructed at runtime; no static graph sees them unless modelled.
- Dynamic dispatch through interfaces with many implementations — over-approximation; some "reachable" edges are dead in practice.
- `eval`, `Function()`, `new Function(...)`, `String#evaluate` — runtime-constructed code; invisible.
- Framework auto-configuration (Spring `@EnableAutoConfiguration`, Quarkus extensions, Rails autoloading) — the framework wires in beans/handlers based on classpath presence; the static graph sees the static code but not the framework's runtime wiring.
- ServiceLoader / Java SPI / OSGi services — discovery happens at runtime via `META-INF/services/`; no static call edge from your code to the service implementation.
- Dependency injection containers — `@Autowired`, `@Inject`, Guice `Module#configure`, the .NET `IServiceCollection`. The DI container is the *real* edge constructor.
- Plugin systems (Eclipse RCP, IntelliJ plugins, WordPress hooks) — same shape.
- Native interop (`extern "C"`, JNI, CGO, PInvoke) — the call leaves the analyzable language.

**Cost**: minutes per scan (CodeQL build + analyse runs ~10–30 min on a medium project). Some tools (Semgrep OSS pattern-match, Grype) don't compute a call graph at all — adding Tier 2 means adding a different tool.

**Tools that reach Tier 2**: [CodeQL](../../scanners/github-codeql/) (taint + dataflow), [Snyk SAST](../../scanners/snyk-sast/) (codeFlow), [Snyk OSS Deep Test](../../scanners/snyk-oss/) (via `functions[]` reachability), [Semgrep Pro / Opengrep `--pro`](../../scanners/semgrep-opengrep/) (taint). Java users can drop down to [SootUp / WALA / OPAL / Tai-e](package-managers/jvm/#layer-3--full-call-graph-analysis) for ad-hoc analysis when the SAST tool's built-in queries don't cover the CWE you care about.

**Practical Tier-2 evidence commands**:

```bash
# JVM — jdeps for class-level, ad-hoc Soot/WALA for method-level
jdeps -e org.apache.logging.log4j.core.lookup.JndiLookup target/myapp.jar
# (See JVM appendix Layer 3 for SootUp/WALA invocation.)

# Read a CodeQL codeFlow from SARIF
jq '.runs[].results[]
    | select(.ruleId=="py/insecure-deserialization")
    | .codeFlows[0].threadFlows[0].locations[]
    | { file: .location.physicalLocation.artifactLocation.uri,
        line: .location.physicalLocation.region.startLine,
        step: .location.message.text }' codeql.sarif

# Go — built-in call graph
go tool callgraph -algo=cha ./... | grep -E "(myapp -> |.+ -> .+vulnerable\.method)"

# JS/TS — esbuild metafile import graph
esbuild --bundle --metafile=meta.json src/index.ts >/dev/null
jq -r '.inputs | to_entries[] | select(.value.imports[]?.path | contains("lodash")) | .key' meta.json

# Python — pycallgraph or pyan3 (for offline)
pyan3 --uses --colored --output=cg.html src/**/*.py
```

Tier 2 is the right answer when the finding warrants a defensible `VERIFIED_UNREACHABLE` claim on a common code path — typical for P2 findings where a fix is expensive but the analysis time is much less so. Pair with Tier 3 when frameworks are involved.

## Tier 3 — Semantic / intent-to-use

**Claim**: the affected symbol is — or isn't — *effectively in use* at runtime, accounting for the dynamic wiring that Tier 2's call graph can't see.

**How it's established**: a combination of (a) reading the framework / DI / plugin / reflection configuration to determine what the runtime wires in, and (b) runtime evidence (coverage data, production traces, eBPF/OpenTelemetry observation) to confirm what actually executes.

**Why Tier 3 exists**: modern JVM, .NET, and Python applications spend a substantial fraction of their execution inside framework-managed code paths that Tier 2 misses. A Spring Boot service whose `pom.xml` includes `log4j-core` doesn't have a static call edge from a controller to `JndiLookup.lookup` — the controller calls `Logger.info(...)`, the logger is wired by `LoggerContext` via Spring's auto-configuration, the format conversion runs through `MessagePatternConverter` which dispatches to `JndiLookup` via reflection. The static call graph sees the controller call to `Logger.info`; it doesn't see the path into `JndiLookup`. Tier 2 reports "unreachable"; Tier 3 (and reality) report "reachable".

**What populates the dynamic wiring**:
- **Reflection** — `Class.forName(...)`, `Method.invoke(...)`, `Constructor.newInstance(...)`. The class/method name is often a string literal, sometimes computed from config.
- **Dependency injection** — Spring `@Component`, `@Autowired`, `@Bean`; Guice `@Inject`; `IServiceCollection.AddSingleton<T>()` (.NET); FastAPI/Flask `Depends()`. The DI container resolves graph edges at runtime.
- **ServiceLoader / Java SPI / OSGi** — `META-INF/services/<interface>` files list implementations; `ServiceLoader.load(...)` discovers them.
- **Framework auto-configuration** — Spring Boot's `@EnableAutoConfiguration` scans the classpath for `META-INF/spring.factories` (Boot 2) or `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` (Boot 3) and instantiates listed classes if their `@Conditional` evaluates true.
- **Plugin systems** — `MEF` in .NET, `OSGi-Bundle-Activator`, Rails `Rails::Engine`, WordPress action/filter hooks, Jenkins Plugin Extension Points.
- **DSL-driven invocation** — Rails route DSL, Django URL configuration, Camel routes, Activiti workflows, Spring Integration channels.
- **`eval` / dynamic code** — `new Function(...)` (JS), `eval(...)` (Python/Ruby), `Module#class_eval` (Ruby), `exec(...)` (Python), `Compiler.parse` (Scala macros at compile time).
- **JIT-resolved native interop** — `dlopen` + `dlsym`, JNI `RegisterNatives`, `LD_PRELOAD`.
- **Reflective enum / annotation processing** — JAX-RS endpoints discovered via `@Path` scanning; Spring `@RestController` scanning; Hibernate `@Entity` scanning.

**Tier-3 evidence sources**:
- **Static**: read the framework config. Spring Boot's `META-INF/spring.factories` / `AutoConfiguration.imports`. `pom.xml` `<dependencies>` that contribute auto-config (e.g. `spring-boot-starter-logging` brings `LoggingApplicationListener`). DI module definitions. ServiceLoader provider files. Reflection sites (`grep -r "Class.forName"`).
- **Dynamic**: integration-test coverage that exercises the relevant code path. Production traces (OpenTelemetry, eBPF, Java agent like JaCoCo's runtime mode). The `vulnetix:exploits` skill cross-references attempted exploitation IOCs with the affected routines.
- **Vulnetix-native**: the [VDB](glossary/#vulnetix-vdb)'s `x_affectedRoutines` plus its semantic reachability model accounts for known framework wiring patterns automatically — see the [capability matrix](../../scanners/#capability-matrix). This is where Vulnetix is strongest *and* weakest: strongest because it captures intent-to-use that call-graph tools miss; weakest because where the question genuinely is a call-graph question (precise edge from controller A to method B with attacker-controlled `String`), CodeQL's bytecode-level analysis is more precise than semantic models.

**Practical Tier-3 evidence commands**:

```bash
# Spring Boot — read the auto-configuration imports for the application JAR
unzip -p target/myapp.jar BOOT-INF/lib/spring-boot-autoconfigure-*.jar \
  | jar tf - 2>/dev/null \
  | grep AutoConfiguration

# Spring Boot 3 auto-config classes loaded
unzip -p target/myapp.jar META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports

# ServiceLoader providers in the build
for f in target/myapp.jar; do unzip -l "$f" | grep META-INF/services; done

# Reflection sites in your code
git grep -nE 'Class\.forName|Method\.invoke|getDeclaredMethod' src/

# Coverage during integration tests — actually-executed lines
mvn -P integration verify
xdg-open target/site/jacoco/index.html    # red = uncovered = dead in practice

# Production-grade runtime trace (Java agent)
java -javaagent:jacocoagent.jar=destfile=jacoco-prod.exec -jar myapp.jar &
# ... run a representative load, then dump:
java -jar jacococli.jar dump --address localhost --destfile jacoco-prod.exec
java -jar jacococli.jar report jacoco-prod.exec --classfiles target/classes --html report/

# Vulnetix semantic reachability — driven from x_affectedRoutines + the framework knowledge in VDB
vulnetix vdb vuln CVE-2021-44228 --output json \
  | jq '.[0].containers.adp[0].x_affectedRoutines'
```

**Where Tier 3 is essential**:
- Spring Boot / Quarkus / Micronaut applications (auto-configuration changes the graph).
- Any DI-heavy code (`@Inject`-driven .NET, Guice, Dagger).
- Plugin / extension systems.
- Reflection-heavy patterns (ORM proxies, JSON deserializers like Jackson with type-info handling, RPC stubs).
- Polyglot apps (a CVE in a Python lib loaded via Jython from a Java app).
- Containerised microservices where the `Dockerfile` or entrypoint wires in env-driven behaviour.

**Tools at Tier 3**: [Vulnetix](../../scanners/vulnetix/) (semantic + intent-to-use is the default model — accounts for framework wiring). No mainstream SAST/SCA tool reaches Tier 3 out of the box; CodeQL and Snyk SAST can be *augmented* with hand-written queries that model specific framework patterns, but the default behaviour is Tier 2.

## Decision framing — which tier do you need?

```
Is the finding:
  P3 / P4 (low priority)?
    → Tier 1 is enough. Don't over-invest.

  P2 (would patch this sprint)?
    → Tier 1 + Tier 2 if a call-graph tool covers the language. If unsure,
      stay at Tier 1 and treat the finding as VERIFIED_REACHABLE
      (the SSVC default for UNKNOWN).

  P1 (incident-grade or KEV-listed)?
    → Tier 2 if the application has no framework wiring around the affected
      area. Tier 3 if the affected lib is logging / serialization /
      template engine / DI container — anywhere framework activation can
      make a static-graph "unreachable" answer wrong.
```

The cost progression is roughly: Tier 1 is free (scanner already did it), Tier 2 is minutes-to-hours of analyser time, Tier 3 is hours-to-days of human time reading framework config plus the analyser runs. Tier 3 evidence is also the only kind that survives an auditor or incident-response review when the finding is on the critical path.

## VEX justification → tier mapping

Each [VEX justification](glossary/#justification) maps to the tier that supports it:

| Justification | Tier |
|---|---|
| `component_not_present` | Tier 1 (the package itself isn't in the build) |
| `vulnerable_code_not_present` | Tier 1 / Tier 2 (the class/symbol is excluded from the artefact) |
| `vulnerable_code_not_in_execute_path` | Tier 2 / Tier 3 (the symbol is present but no execution path reaches it) |
| `vulnerable_code_cannot_be_controlled_by_adversary` | Tier 2 / Tier 3 + adversary-controllability reasoning |
| `inline_mitigations_already_exist` | Orthogonal to tier — runtime mitigation (WAF, input validation) |

State the tier in the `analysis.detail` field so future-you and an auditor can grade the evidence:

```json
{
  "analysis": {
    "state": "not_affected",
    "justification": "vulnerable_code_not_in_execute_path",
    "detail": "Engineer Triage: BACKLOG. Reachability evidence Tier 3: log4j-core is on classpath via spring-boot-starter-logging; Spring Boot auto-config wires Logback (META-INF/spring.factories LoggingApplicationListener) and never instantiates JndiLookup. Vulnetix x_affectedRoutines.JndiLookup.lookup not in target/myapp.jar's loaded classes (jdeps -e). JaCoCo integration-test coverage shows the class never loaded under a representative load."
  }
}
```

## Worked example — Spring Boot + Log4Shell, three tiers in conflict

A Spring Boot 3.2 app's `pom.xml` includes `spring-boot-starter-web`. The transitive resolution surfaces `log4j-core@2.14.1`. CVE-2021-44228 fires.

**Tier 1 evidence**: `mvn dependency:tree | grep log4j-core` shows the dep is resolved. `jar tf target/myapp.jar | grep log4j-core` shows it's bundled. → "Reachable" (package present).

**Tier 2 evidence**: `jdeps -e org.apache.logging.log4j.core.lookup.JndiLookup target/myapp.jar` reports zero static references from the application's classes. CodeQL's call graph (if you run it) shows no edge from `@RestController` methods to `JndiLookup.lookup`. → "Unreachable" (no static edge).

**Tier 3 evidence**: read `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` — it lists `LoggingApplicationListener`. Read Spring Boot's logging starter — by default it pulls Logback, not Log4j-core, and explicitly excludes Log4j initialisation. *But* the project's `pom.xml` adds `log4j-core` directly (perhaps for a JDBC driver that requires it). Logback handles the actual logging; Log4j-core is on the classpath but its `LoggerContext` is never instantiated. The reflective dispatch path (`MessagePatternConverter.format` → `JndiLookup.lookup`) is dead. JaCoCo integration-test coverage confirms `JndiLookup` is never loaded. → "Unreachable, Tier 3 verified."

The Tier-3 evidence is what changes the decision from "patch as a precaution" to a defensible `not_affected` VEX with `vulnerable_code_not_in_execute_path`. Tier 2 alone would have already pointed at unreachable, but a reviewer or auditor could push back on a Spring Boot codebase ("how do you know auto-config doesn't activate it?"). Tier 3 closes the loop.

## See also

- [SSVC Engineer Triage](ssvc/) — the framework that takes `Reachability` as one of four inputs.
- [SARIF appendix](sarif/) — the format that carries Tier-2 codeFlow evidence.
- [VEX overview](vex/) and [OpenVEX](openvex/) — where you record the tier-graded decision.
- [JVM appendix layer 3](package-managers/jvm/#layer-3--full-call-graph-analysis) — Tier-2 tooling for the JVM (SootUp / WALA / OPAL / Tai-e).
- Per-language reachability sections: [JavaScript](package-managers/javascript/#reachability), [Python](package-managers/python/#reachability), [Go](package-managers/go/#reachability), [Rust](package-managers/rust/#reachability), [Ruby](package-managers/ruby/#reachability), [.NET](package-managers/dotnet/#reachability), [PHP](package-managers/php/#reachability), [Swift / iOS](package-managers/swift-ios/#reachability), [others](package-managers/other/).
- [Capability matrix](../../scanners/#capability-matrix) — which scanner sits at which tier.
- [Glossary](glossary/) — for the terms used above.
