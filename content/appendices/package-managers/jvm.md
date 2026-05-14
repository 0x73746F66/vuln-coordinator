---
title: "JVM — Maven, Gradle"
description: "Dependency management for Java, Kotlin, and Scala via Maven and Gradle."
weight: 30
---

## Maven (`pom.xml`)

```xml
<!-- Coerce a transitive: declare it in dependencyManagement -->
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

```bash
mvn dependency:tree -Dincludes=org.apache.logging.log4j:log4j-core
mvn versions:display-dependency-updates
```

Maven has no native lockfile, but the `<dependencyManagement>` section in your root POM acts as one for versions. A BOM import (`<scope>import</scope>`) brings in a vetted set of versions from a vendor (Spring Boot's BOM is the common case). The `maven-enforcer-plugin` with `dependencyConvergence` makes inconsistent transitives fail the build.

Gotcha: a `<dependencyManagement>` pin only applies if the artifact is actually pulled in by a transitive — declare it as a direct `<dependency>` with the right scope if it isn't.

## Gradle (`gradle.lockfile`)

```kotlin
// build.gradle.kts
dependencyLocking {
    lockAllConfigurations()
}
dependencies {
    constraints {
        implementation("org.apache.logging.log4j:log4j-core:2.17.1") {
            because("CVE-2021-44228 mitigation")
        }
    }
    implementation(enforcedPlatform("org.springframework.boot:spring-boot-dependencies:3.2.0"))
}
```

```bash
./gradlew dependencies --write-locks
```

`dependencies.constraints` is the coercion mechanism — it forces a transitive to a specific version, with a `because` reason that appears in build reports. `enforcedPlatform()` imports a Maven BOM and overrides any other resolved version. `gradle.lockfile` records the resolved version per configuration.

Gotcha: locking is per-configuration; multi-project builds need locking enabled in each subproject.

## Reachability

- `mvn dependency:tree -Dincludes=group:artifact` shows the path from your project to the transitive.
- `jdeps --multi-release 17 --print-module-deps target/myapp.jar` reports class-level reachability against the built artefact.
- For full static analysis: SootUp or WALA produce a call graph; query for the vulnerable method's class + signature.
- Runtime: JaCoCo coverage on integration tests. If the class containing the vuln isn't covered, document it.
