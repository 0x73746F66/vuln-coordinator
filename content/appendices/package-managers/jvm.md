---
title: "JVM — Maven, Gradle, Ivy, SBT"
description: "Dependency management for Java, Kotlin, and Scala. Maven and Gradle each carry a dozen distinct ways to specify, coerce, override, and pin a dependency — pick the one whose blast radius matches your finding."
weight: 30
---

## Before you touch the build

The hardest part of a Java triage is figuring out *which build mechanism actually controls the resolved version*. A POM-declared dependency may not be the one shipping in your JAR; a Gradle constraint may be silently overridden by a `platform()`; a Spring Boot BOM may be re-pinning your bump every build. Before editing anything, answer four questions:

1. **Is the affected artefact a direct dependency or a transitive?** Run `mvn dependency:tree -Dverbose -Dincludes=<groupId>:<artifactId>` (Maven) or `./gradlew :app:dependencyInsight --dependency <artifactId> --configuration runtimeClasspath` (Gradle). The output shows the path from your project to the artefact. If the path is one hop, it's direct — edit the declaration. If it's many hops, it's transitive — coerce it via dependencyManagement / constraints.
2. **Is its version pinned by a BOM you import?** Look for `<scope>import</scope>` in `<dependencyManagement>` (Maven) or `platform()` / `enforcedPlatform()` (Gradle). BOMs override transitive versions silently — your coercion has to land in the right place relative to the BOM import.
3. **Is there a parent POM contributing dependencyManagement?** If `<parent>` is set (e.g. `spring-boot-starter-parent`), the parent's dependencyManagement applies before yours. The child POM overrides the parent only if the artefact is re-declared in the child's own dependencyManagement.
4. **Is it shaded into a fat JAR?** Run `unzip -l target/myapp.jar | grep -i log4j` (or `jar tf` for non-uber jars). A shaded relocation moves classes to a different package (`com.example.shaded.org.apache.logging.log4j`), which changes both reachability and patchability — you may need to rebuild the shading parent rather than bump the original artefact.

Answer those four before picking a fix.

## Maven (`pom.xml`)

Maven has no native lockfile. The effective lockfile is the combined `<dependencyManagement>` of your POM hierarchy plus any imported BOMs. A dozen distinct mechanisms can change what version ends up on the classpath; pick the one whose blast radius matches the finding.

### 1. Direct upgrade in `<dependencies>`

The simplest case — the artefact is declared in your POM. Bump the `<version>`:

```xml
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <version>2.17.1</version>
</dependency>
```

Use when the artefact is direct, no BOM controls it, no transitive brings in a conflicting version, and no version property is in play. This is the only mechanism that doesn't need a follow-up `mvn dependency:tree` to verify.

### 2. Property-driven version

Most well-organised POMs centralise versions in `<properties>`. The artefact's `<version>` references the property:

```xml
<properties>
  <log4j.version>2.17.1</log4j.version>
</properties>
...
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <version>${log4j.version}</version>
</dependency>
```

`mvn versions:set-property -Dproperty=log4j.version -DnewVersion=2.17.1` edits the property in place. Useful in multi-module reactor builds where the same property feeds many modules.

### 3. `<dependencyManagement>` pin (transitive coercion)

The canonical way to coerce a transitive that's not directly declared. Pin the artefact in the root POM's `<dependencyManagement>`:

```xml
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.17.1</version>
    </dependency>
  </dependencies>
</dependencyManagement>
```

The dependencyManagement entry only takes effect if *something* in the dep graph drags in `log4j-core` — it doesn't add the artefact, it only sets the version. Verify with `mvn dependency:tree -Dincludes=org.apache.logging.log4j:log4j-core` after the change.

**Gotcha:** if the artefact isn't pulled in by any transitive (e.g. you added the management entry pre-emptively), it stays absent. Add it as a direct `<dependency>` (without `<version>`) to materialise it.

### 4. BOM import (`<scope>import</scope>`)

A BOM is a POM whose `<dependencyManagement>` is meant to be imported wholesale. Spring Boot's `spring-boot-dependencies`, AWS SDK's `bom`, Jackson's `jackson-bom`, Netty's `netty-bom`, and dozens of vendor BOMs work this way. Import via:

```xml
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-dependencies</artifactId>
      <version>3.2.0</version>
      <type>pom</type>
      <scope>import</scope>
    </dependency>
  </dependencies>
</dependencyManagement>
```

The BOM pins ~250 transitive versions in one line. **Order matters within `<dependencyManagement>`** — Maven uses "nearest wins" plus "first-declared wins for ties." To override a BOM-managed artefact, declare it *before* the BOM import:

```xml
<dependencyManagement>
  <dependencies>
    <!-- BEFORE the BOM — this wins -->
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.17.1</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-dependencies</artifactId>
      <version>3.2.0</version>
      <type>pom</type>
      <scope>import</scope>
    </dependency>
  </dependencies>
</dependencyManagement>
```

### 5. Override a Spring Boot BOM via property

When using `spring-boot-starter-parent` (which auto-imports the BOM), the cleanest override is to set the BOM's exposed property:

```xml
<properties>
  <log4j2.version>2.17.1</log4j2.version>
</properties>
```

The Spring Boot BOM publishes property names like `log4j2.version`, `jackson.version`, `tomcat.version`. Setting the property in your POM's `<properties>` re-pins the BOM's resolved version without rewriting the dependencyManagement. Check the [Spring Boot dependency-management plugin docs](https://docs.spring.io/spring-boot/docs/current/reference/html/dependency-versions.html) for the supported property names; not every BOM-managed artefact exposes one.

### 6. `<exclusions>` to drop a transitive

If the safe answer is to remove the artefact entirely (the parent dependency works without it, or you'll bring it in via a different artefact like `log4j-to-slf4j`):

```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-web</artifactId>
  <exclusions>
    <exclusion>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
    </exclusion>
  </exclusions>
</dependency>
```

**Gotcha:** exclusions apply only to *that* dependency's transitive tree. If three different starters pull in `log4j-core`, you need three `<exclusions>` blocks — or push the artefact out via `<dependencyManagement>` + a runtime-substitute like `log4j-to-slf4j`. Maven 4+ adds `<exclusions>` at the dependencyManagement level for fleet-wide exclusion.

### 7. Scope changes (`runtime` / `provided` / `test`)

Sometimes the right fix is to demote the artefact's scope so it doesn't ship in the production classpath:

```xml
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <scope>test</scope>
</dependency>
```

Use when the affected code path only runs under `test` or `provided` (e.g. the dep is provided by the application server at runtime — `javax.servlet-api` is the classic case). Verify with `mvn dependency:tree -Dscope=runtime`.

### 8. Version ranges (use sparingly)

Maven supports range syntax `[2.17.1,)` (allow 2.17.1+), `[2.17.1,3.0.0)` (allow 2.x ≥ 2.17.1, exclude 3.x). Rarely the right answer — ranges break reproducibility and Maven's "nearest wins" algorithm becomes harder to reason about. Prefer exact versions plus `mvn versions:display-dependency-updates` to surface candidates.

### 9. Maven Enforcer Plugin gates

After you fix the version, gate the fix so a future transitive bump can't regress it. The enforcer plugin runs as part of `mvn verify`:

```xml
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-enforcer-plugin</artifactId>
  <executions>
    <execution>
      <goals><goal>enforce</goal></goals>
      <configuration>
        <rules>
          <dependencyConvergence/>
          <requireUpperBoundDeps/>
          <banVulnerable>
            <excludes>
              <exclude>org.apache.logging.log4j:log4j-core:[,2.17.1)</exclude>
            </excludes>
          </banVulnerable>
        </rules>
      </configuration>
    </execution>
  </executions>
</plugin>
```

`dependencyConvergence` fails the build if two transitives disagree on a version. `requireUpperBoundDeps` ensures the nearest-wins resolution didn't pick a *lower* version than the BOM. The `banVulnerable` rule (from `extra-enforcer-rules`) hard-blocks regressions on a specific CVE-affected range.

### 10. `versions-maven-plugin` for fleet upgrades

`mvn versions:display-dependency-updates` lists candidate upgrades. `mvn versions:use-latest-versions -Dincludes=org.apache.logging.log4j` bumps everything matching the include pattern. `mvn versions:set-property -Dproperty=log4j.version -DnewVersion=2.17.1` edits a single property. `mvn versions:update-parent` bumps the `<parent>` reference. `mvn versions:commit` cleans up the `.versionsBackup` files left by the dry-run flag.

### 11. Parent POM strategy

Multi-module reactor builds let you centralise dependencyManagement in a parent POM that child modules inherit. Pin once in the parent; every child sees the pin. Use `<dependencyManagement>` in the parent's `<dependencyManagement>` section (without `<scope>import</scope>`) and child modules just declare the artefact without a `<version>`:

```xml
<!-- parent/pom.xml -->
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.17.1</version>
    </dependency>
  </dependencies>
</dependencyManagement>

<!-- child/pom.xml -->
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <!-- no version — inherited from parent -->
</dependency>
```

### 12. Maven profiles for env-specific overrides

`<profiles>` can host environment-specific `<dependencyManagement>` blocks — handy when prod and CI need different pins (e.g. JDK 8 vs 17 build matrix):

```xml
<profiles>
  <profile>
    <id>jdk8</id>
    <activation><jdk>1.8</jdk></activation>
    <dependencyManagement>...</dependencyManagement>
  </profile>
</profiles>
```

### Verification commands

```bash
mvn dependency:tree -Dverbose -Dincludes=org.apache.logging.log4j:log4j-core
# Shows omitted transitives; -Dverbose reveals what got displaced.

mvn dependency:analyze
# "Unused declared" and "used undeclared" — finds POM/classpath drift.

mvn dependency:list -DexcludeTransitive=false -DoutputFile=deps.txt
# Flat list of every resolved artefact + version.

mvn help:effective-pom -Doutput=effective.xml
# After all inheritance, parent POMs, and BOM imports are applied.

mvn enforcer:enforce
# Re-runs the convergence + banVulnerable gates without a full build.

mvn versions:display-dependency-updates -Dverbose
# Candidate upgrades with available versions.

jar tf target/myapp.jar | grep -i log4j
# Confirm what's actually shipping in the built artefact.
```

## Gradle (`gradle.lockfile`)

Gradle has even more ways to specify a version than Maven. The mechanisms range from "blunt force" (`force` — overrides everything) to "polite suggestion" (`prefer` — lowest priority). Pick by blast radius.

### 1. Direct upgrade in `dependencies { }`

```kotlin
dependencies {
    implementation("org.apache.logging.log4j:log4j-core:2.17.1")
}
```

### 2. `dependencies.constraints` (preferred coercion)

The right tool for transitive coercion. Records the reason in the build report:

```kotlin
dependencies {
    constraints {
        implementation("org.apache.logging.log4j:log4j-core:2.17.1") {
            because("CVE-2021-44228 mitigation — see security ticket SEC-1234")
        }
    }
}
```

The constraint only applies if the artefact is in the graph. Verify with `./gradlew dependencyInsight --dependency log4j-core --configuration runtimeClasspath`.

### 3. Rich versions (`strictly` / `require` / `prefer` / `reject`)

Fine-grained version negotiation. `strictly` is the strongest — it fails the build if any other declaration disagrees:

```kotlin
dependencies {
    implementation("org.apache.logging.log4j:log4j-core") {
        version {
            strictly("[2.17.1,)")        // fail if anything else negotiates < 2.17.1
            prefer("2.17.1")              // pick this when range allows
            reject("2.17.1-rc1")          // never pick this
        }
        because("CVE-2021-44228")
    }
}
```

Use when you need to block specific bad versions (a yanked release, a known-broken patch) while leaving room for future bumps.

### 4. `resolutionStrategy.force` (legacy hard override)

```kotlin
configurations.all {
    resolutionStrategy {
        force("org.apache.logging.log4j:log4j-core:2.17.1")
    }
}
```

Older Gradle codebases use this. It's brutal — overrides everything, no negotiation, no reason text. Prefer `constraints` for new code; reach for `force` only when constraints don't take effect (rare — usually a sign of a misconfigured platform import).

### 5. `resolutionStrategy.eachDependency { }` (programmatic)

For sweeping rewrites across an entire dep graph:

```kotlin
configurations.all {
    resolutionStrategy.eachDependency {
        if (requested.group == "org.apache.logging.log4j") {
            useVersion("2.17.1")
            because("CVE-2021-44228 — pin whole log4j family")
        }
    }
}
```

Runs for every resolved dep — useful for "upgrade *all* artefacts in this group" patterns.

### 6. `resolutionStrategy.dependencySubstitution { }`

Replace one module with another entirely:

```kotlin
configurations.all {
    resolutionStrategy.dependencySubstitution {
        substitute(module("org.apache.logging.log4j:log4j-core"))
            .using(module("org.apache.logging.log4j:log4j-to-slf4j:2.17.1"))
            .because("Route log4j calls through slf4j; project uses Logback")
    }
}
```

The killer use case for Log4Shell on a Logback-based app — substitute `log4j-core` for `log4j-to-slf4j`, which routes log4j API calls to Logback's actual implementation and leaves `JndiLookup` dead.

### 7. `platform()` / `enforcedPlatform()` (BOM imports)

Gradle's BOM-import mechanism:

```kotlin
dependencies {
    implementation(platform("org.springframework.boot:spring-boot-dependencies:3.2.0"))
    implementation("org.apache.logging.log4j:log4j-core")  // version from BOM
}
```

`platform()` brings in version recommendations — your own constraints can still override. `enforcedPlatform()` is non-negotiable — the BOM's versions win against any constraint or strict version. Use `enforcedPlatform()` only when you specifically need that lock-down; the default `platform()` plus constraints is more flexible.

### 8. Version catalogs (`libs.versions.toml`)

The modern way to centralise versions in a Gradle build:

```toml
# gradle/libs.versions.toml
[versions]
log4j = "2.17.1"

[libraries]
log4j-core = { module = "org.apache.logging.log4j:log4j-core", version.ref = "log4j" }
```

```kotlin
// build.gradle.kts
dependencies {
    implementation(libs.log4j.core)
}
```

Edit one TOML file; every subproject in the build picks up the new version. Plays well with `dependabot.yml`'s `gradle` ecosystem.

### 9. Dependency locking (`gradle.lockfile`)

Per-configuration lockfile. Enable:

```kotlin
dependencyLocking {
    lockAllConfigurations()
}
```

Then `./gradlew dependencies --write-locks` writes the lockfile. `./gradlew --update-locks org.apache.logging.log4j:log4j-core` updates one entry without rewriting everything. **Multi-project builds**: enable locking in `subprojects { }` (or in a convention plugin) so every module emits its own lockfile.

### 10. Capability conflicts

When two artefacts provide the same capability (`log4j-core` and `log4j-to-slf4j` both provide log4j-API), Gradle flags a conflict. Resolve with:

```kotlin
configurations.all {
    resolutionStrategy.capabilitiesResolution {
        withCapability("org.apache.logging.log4j:log4j-impl") {
            selectHighestVersion()
            // or: select("org.apache.logging.log4j:log4j-to-slf4j:0")
        }
    }
}
```

### 11. Init scripts (cross-build overrides)

When you can't edit the build file (third-party build script, CI-only override), use an init script. `~/.gradle/init.d/security.gradle`:

```kotlin
allprojects {
    configurations.all {
        resolutionStrategy.eachDependency {
            if (requested.name == "log4j-core" && requested.version!!.startsWith("2.") && requested.version!! < "2.17.1") {
                useVersion("2.17.1")
                because("CVE-2021-44228 floor (init script)")
            }
        }
    }
}
```

### Verification commands

```bash
./gradlew :app:dependencyInsight --dependency log4j-core --configuration runtimeClasspath
# Shows the resolved version and *why* (constraint, force, platform, etc.)

./gradlew :app:dependencies --configuration runtimeClasspath
# Full resolved tree.

./gradlew :app:dependencies --configuration runtimeClasspath | grep -A1 log4j
# Quick scan for the artefact in the tree.

./gradlew dependencies --write-locks
# Write/refresh the lockfile after a change.

./gradlew --refresh-dependencies build
# Force re-resolution; ignores cached resolution.
```

## Ivy

Ant + Ivy is rare but still in the wild. The lockfile-equivalent is `ivy.xml` itself (resolved versions live in `ivy-2.x.report.xml`):

```xml
<dependencies>
  <dependency org="org.apache.logging.log4j" name="log4j-core" rev="2.17.1" conf="default"/>
  <override org="org.apache.logging.log4j" module="log4j-core" rev="2.17.1"/>
</dependencies>
```

`<override>` is Ivy's transitive coercion. `ivy:resolve` re-resolves; `ivy:report` produces the per-configuration tree.

## SBT (Scala)

```scala
// build.sbt
libraryDependencies += "org.apache.logging.log4j" % "log4j-core" % "2.17.1"

// Transitive coercion via dependencyOverrides
dependencyOverrides += "org.apache.logging.log4j" % "log4j-core" % "2.17.1"

// Or per-configuration:
libraryDependencies ++= Seq(
  "org.apache.logging.log4j" % "log4j-core" % "2.17.1" force()
)
```

`dependencyOverrides` is SBT's `<dependencyManagement>`. The `force()` modifier is the equivalent of Gradle's `resolutionStrategy.force` — overrides any conflict. `sbt-dependency-graph` plugin's `dependencyTree` task produces the resolved graph; `whatDependsOn org.apache.logging.log4j log4j-core 2.14.1` answers the backward-walk question.

## Direct vs transitive triage — the Java decision tree

{{< decision >}}
Is the affected artefact declared directly in your build file (POM `<dependencies>` / Gradle `dependencies { }` / build.sbt `libraryDependencies`)?

  ├─ Yes (DIRECT)
  │    ├─ Is the version literal? → bump the literal in place (Mechanism 1).
  │    ├─ Is it `${property}`-driven? → bump the property (Mechanism 2 / 10).
  │    └─ Is it BOM-managed (no `<version>` on the declaration)?
  │         ├─ Spring Boot BOM property exposed? → set the property (Mechanism 5).
  │         └─ Otherwise → re-declare in dependencyManagement BEFORE the BOM import (Mechanism 4).
  │
  └─ No (TRANSITIVE)
       ├─ Is the parent dep itself updatable to a version that bumps the transitive?
       │    └─ Yes → bump the parent; verify with `mvn dependency:tree` that the transitive moved too.
       │
       ├─ Can the transitive be removed safely (alternative implementation exists)?
       │    └─ Yes → `<exclusions>` (Maven, Mechanism 6) or `dependencySubstitution` (Gradle, Mechanism 6).
       │
       └─ Otherwise → coerce via dependencyManagement (Maven, Mechanism 3) / constraints (Gradle, Mechanism 2).
            Verify the coercion took effect with `dependency:tree` / `dependencyInsight`.
            Add an Enforcer (Maven) / lockfile (Gradle) gate so a future bump can't regress (Mechanism 9 / 9).
{{< /decision >}}

## Reachability

Java reachability has three layers, each progressively tighter:

### Layer 1 — does the artefact even reach the runtime classpath?

```bash
# Maven
mvn dependency:tree -Dincludes=org.apache.logging.log4j:log4j-core
mvn dependency:tree -Dverbose -Dscope=runtime

# Gradle
./gradlew :app:dependencies --configuration runtimeClasspath | grep log4j

# Built JAR — what actually shipped?
jar tf target/myapp.jar | grep -i log4j
unzip -l build/libs/myapp-uber.jar | grep -i log4j

# Shaded? Check for relocations.
javap -cp target/myapp.jar org.apache.logging.log4j.core.lookup.JndiLookup 2>&1 || \
  echo "Class not present at original coordinate — possibly shaded or excluded"
```

If the class isn't in the runtime classpath, you have a build-time-only dependency — VEX justification `vulnerable_code_not_present`.

### Layer 2 — does any code in your build call the affected method?

```bash
# jdeps reports module-level dependencies on the built artefact
jdeps --multi-release 17 --print-module-deps target/myapp.jar

# Class-level: which classes in your code reference log4j core?
jdeps -v -cp $(mvn dependency:build-classpath -q -DincludeScope=runtime -Dmdep.outputFile=/dev/stdout) \
       target/myapp.jar \
  | grep "org.apache.logging.log4j.core"

# Method-level: which methods in your code reach a specific class?
jdeps -e org.apache.logging.log4j.core.lookup.JndiLookup target/myapp.jar
```

`jdeps` is fast, JDK-bundled, and answers "does my code's bytecode contain a reference to this class?" — necessary but not sufficient for VERIFIED_REACHABLE (a reference may be on a dead branch).

### Layer 3 — full call-graph analysis

When `jdeps` says "yes" and you need to prove that the call is on a *live* path, reach for a real call-graph tool. Each has different precision/coverage trade-offs:

- **[SootUp](https://soot-oss.github.io/SootUp/)** — modern Soot successor, produces an interprocedural call graph (CHA, RTA, VTA, or pointer-analysis-based). Query for an edge from your code's entry points to the affected method.
- **[WALA](https://github.com/wala/WALA)** — IBM-origin, very precise pointer analysis; steeper learning curve. Useful when SootUp's CHA over-approximates.
- **[OPAL](https://www.opal-project.de/)** — academic, very fast, good for whole-program analysis on uber-JARs.
- **[Tai-e](https://github.com/pascal-lab/Tai-e)** — newer, configurable analysis pipeline; supports both Java and Android (DEX).

For the Spring Boot + Log4Shell case: `jdeps -e org.apache.logging.log4j.core.lookup.JndiLookup` may report the reference because Spring's logging starter pulls in `log4j-core` for compatibility, but `JndiLookup` is only instantiated by `MessagePatternConverter` at format time — if your code never reaches a `Logger.info(<user-controlled-string>)` call site, the path is dead. A call-graph tool proves it.

### Layer 4 — runtime coverage

If static analysis is inconclusive, runtime coverage settles the question:

```bash
# JaCoCo via Maven Surefire
mvn -Pintegration-tests verify
# Then inspect target/site/jacoco/index.html — is the class red (uncovered)?

# JaCoCo via Gradle
./gradlew jacocoTestReport
# build/reports/jacoco/test/html/index.html

# Production-grade: java agent for live coverage
java -javaagent:jacocoagent.jar=destfile=jacoco.exec -jar myapp.jar
# Run a representative load, then dump and read.
```

If integration tests never cover the class, and a production trace (via a `-javaagent` agent during shadow traffic) also doesn't, that's evidence for `vulnerable_code_not_in_execute_path`.

## Shaded / uber JARs — the hidden reachability problem

Many distributions ship as fat JARs with their dependencies relocated. The affected class may live at `com.example.shaded.org.apache.logging.log4j.core.lookup.JndiLookup` instead of the original coordinate, which:

- breaks naïve `jar tf | grep` searches (search for the *relocated* path, not the original);
- breaks SBOM matching (the SBOM may list the artefact-coordinate but the bytecode lives at a different package path);
- means a `<dependency>` bump in your POM doesn't help — you need to rebuild the upstream artefact whose `maven-shade-plugin` config controls the relocation.

Detect with `unzip -p target/myapp.jar META-INF/MANIFEST.MF | grep Shaded` (some plugins record relocations) or by inspecting the actual class path layout: `unzip -l target/myapp.jar | grep -i "jndi\|log4j"`.

## GraalVM native-image specifics

Native-image AOT-compiles your app to a binary; reachability analysis happens at build time and only reachable classes get included. If the build's `--trace-class-initialization` report doesn't list `org.apache.logging.log4j.core.lookup.JndiLookup`, the class isn't in the native binary and the vulnerability isn't reachable in that artefact. Re-run with `--native-image-info` or inspect the build's `reachability-metadata.json` to confirm.

## Common gotchas

- **`<scope>provided</scope>`**: Maven Surefire's classpath includes `provided`-scope artefacts; the production WAR's runtime classpath usually doesn't. A scanner that reads `pom.xml` will flag the artefact; runtime reachability may be zero. VEX with `vulnerable_code_not_present` is honest if the deployed artefact really doesn't ship it.
- **Maven 4 dependency-management at the dependency level**: Maven 4 adds per-dependency dependencyManagement (`<dependency-management>` inside a `<dependency>`). New mechanism, not yet in widespread use, but appears in cutting-edge POMs.
- **Gradle's `compileOnly` vs `implementation`**: a `compileOnly` artefact is on the compile classpath but not the runtime classpath — same VEX angle as Maven's `provided`.
- **Spring Boot's repackaged JAR**: `spring-boot-maven-plugin`'s repackage goal nests dep JARs inside `BOOT-INF/lib/`. Native `jar tf` works; `unzip -l` works; but external SBOM tools sometimes only inspect the outer JAR and miss the nested ones. Verify with `unzip -l target/myapp.jar | grep BOOT-INF/lib/log4j-core`.
- **Kotlin's `kapt` / `ksp` / annotation processors**: artefacts on the `kapt`/`annotationProcessor` configuration only run at build time. Production reachability is zero.
- **Test-scope brought to runtime by a transitive**: `<scope>test</scope>` on your direct dep doesn't stop a *runtime*-scope transitive from also pulling it in. `mvn dependency:tree -Dscope=runtime` is the definitive check.

## Developer gotchas — written for people who live in the code

You write Java every day; you fight Maven once a quarter. These are the surprises that catch developers — not security engineers — when triaging an SCA finding.

- **Maven uses "nearest wins", not "highest wins".** If `your-app → A → log4j-core:2.14.1` and `your-app → B → log4j-core:2.17.1`, the resolved version isn't the safer 2.17.1 — it's whichever path is *shortest*. Tie goes to first-declared. `mvn dependency:tree -Dverbose` shows the omitted-due-to-conflict notes. This is why bumping a transitive direct-parent often doesn't help — the *shorter* path still wins. Use `<dependencyManagement>` to break ties decisively.

- **Your IDE classpath isn't your build classpath.** IntelliJ / Eclipse / VS Code do their own Maven/Gradle resolution and may show different versions than `mvn package` produces. The artefact you ship is what `mvn package` puts in `target/`; verify there, not in the IDE's "External Libraries" tree.

- **`target/` is the truth.** `target/myapp.jar` contains exactly what runs in production. Scanners that read `pom.xml` may flag artefacts that don't end up in the JAR (compile-only, test-only, provided-scope). Conversely, scanners that read the JAR may miss artefacts your code *intends* to use but the build accidentally dropped. Run both: `mvn dependency:tree -Dscope=runtime` for intent, `jar tf target/myapp.jar` for actuality.

- **The Maven local repo (`~/.m2/repository/`) caches forever.** A `mvn install` from six months ago still has `log4j-core-2.14.1.jar` on disk. `mvn clean install` rebuilds your project but doesn't redownload deps; `mvn -U` forces an update check; `rm -rf ~/.m2/repository/org/apache/logging` is the nuclear option. Containers built with a cached `.m2` mount will have whatever's in the cache, not what's in Central.

- **Spring Boot's auto-import BOM is invisible in your POM.** You wrote `<dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId></dependency>` (no version) and Maven resolved 2.14.1. You didn't pin that version anywhere. Source: `spring-boot-starter-parent`'s parent POM imports `spring-boot-dependencies`, which has a `<log4j2.version>2.14.1</log4j2.version>` in its properties. Look in `mvn help:effective-pom` to see the inherited dependencyManagement. Bumping requires overriding the property or re-declaring before the BOM import.

- **Kotlin / Scala source compiles against Java bytecode you don't write.** A CVE flagged in a Java library shows up on a Kotlin project's SCA scan because the Kotlin code calls the Java library. Reachability semantics are the same — `jdeps` works on the compiled `.class` regardless of source language.

- **Gradle constraints aren't dependencies.** Adding `constraints { implementation("log4j-core:2.17.1") }` doesn't add log4j to your build. It only pins the version *if* something else drags it in. If nothing else does, the constraint is silently no-op. Verify with `./gradlew dependencyInsight --dependency log4j-core`. If the answer is "Module not found in any of the configurations", the constraint isn't taking effect.

- **`./gradlew clean` doesn't clear the Gradle cache.** `~/.gradle/caches/modules-2/files-2.1/` holds resolved deps. `--refresh-dependencies` checks for newer; `./gradlew clean --refresh-dependencies build` is the cleanest run. Gradle daemons cache more aggressively; `./gradlew --stop` before a tricky refresh.

- **Snapshots silently change.** A `1.0-SNAPSHOT` artefact resolves to whatever's currently in your snapshot repo. Today's `1.0-SNAPSHOT` may have a different bytecode than yesterday's. CVE flags against snapshots are timing-dependent; bump to a release version before triaging.

- **`maven-failsafe-plugin` integration tests have their own classpath**. Test-scope deps + `provided`-scope deps + your runtime — Failsafe picks them up. If your scanner is reading the build's effective dependency list (which includes test scope), you'll see CVEs in test-only libs that don't ship. Filter by scope before triaging.

- **`<dependency>` in a parent POM with `<scope>import</scope>` *is* a BOM**, but `<scope>import</scope>` only works inside `<dependencyManagement>`. People sometimes copy-paste it into `<dependencies>` directly — Maven silently treats it as `scope=compile` and pulls in the BOM POM as a regular dep (which doesn't have a jar, so it just adds dependencyManagement to nothing). Symptom: your BOM has no effect. Fix: nest it inside `<dependencyManagement>`.

- **OSGi bundles ship with their own dependency declarations in `META-INF/MANIFEST.MF`.** A non-OSGi scanner reads `pom.xml`; OSGi runtime reads `MANIFEST.MF`'s `Import-Package`. They can disagree. Apache Karaf / Equinox containers may resolve differently than what your build said.

- **Multi-module reactor builds — a CVE flagged on one module isn't necessarily *that* module's responsibility.** If `module-a` declares the affected dep and `module-b` depends on `module-a`, the bytecode lands in `module-b`'s shaded build. Triage at the module that *declares* it, not the one that ships it.
