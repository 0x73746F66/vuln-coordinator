---
title: ".NET — NuGet"
description: "packages.lock.json, Directory.Packages.props, Central Package Management."
weight: 70
---

## NuGet (`packages.lock.json`, `Directory.Packages.props`)

```xml
<!-- Directory.Packages.props — Central Package Management -->
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>
```

```xml
<!-- *.csproj -->
<PackageReference Include="Newtonsoft.Json" />
```

```bash
dotnet restore --locked-mode
```

Central Package Management (CPM) lets a single `Directory.Packages.props` pin every transitive across a solution; a `<PackageVersion>` there coerces a transitive even if no project declares it directly. `<RestoreLockedMode>true</RestoreLockedMode>` in a `.csproj` mandates `--locked-mode` behaviour.

Gotcha: pre-CPM solutions have versions scattered across each `.csproj` — migrating is a one-time effort but it dramatically simplifies upgrades.

## Developer gotchas — written for people who live in the code

- **`packages.lock.json` is opt-in.** New projects don't get one unless you set `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>`. Without a lockfile, `dotnet restore` re-resolves each build and the CVE you triaged yesterday may regress on a transitive bump tomorrow.
- **`bin/Debug/` and `bin/Release/` ship different artefacts.** Conditional compilation symbols (`#if DEBUG`) can compile in/out vulnerable code paths. Reachability of a CVE flagged on a dep depends on which configuration the deployed binary was built from. Check `csc.exe` invocation flags or `dotnet publish -c Release`.
- **`TargetFramework` matters.** `net6.0` vs `net8.0` vs `netstandard2.0` resolve different versions of the same package. A CVE in `System.Text.Json` for `net6.0` may not exist in the `net8.0` build of the same package. `dotnet list package --framework net8.0` filters by target.
- **`PrivateAssets="all"` hides a transitive from downstream.** Used on analyzers, source generators, build-time tools. CVE on a `PrivateAssets="all"` dep doesn't propagate to your package's consumers — but it still affects *your* build.
- **`global.json` pins the SDK, not packages.** A CVE in an SDK component (`dotnet-tools`) needs `dotnet --info` to identify, not package scans.
- **AssemblyLoadContext isolation in plugins.** Apps using `AssemblyLoadContext` (most plugin systems) can have two versions of the same DLL loaded simultaneously. CVE scanners may flag both; only the actually-invoked one is reachable.
- **Single-file publish (`dotnet publish -p:PublishSingleFile=true`) embeds deps.** The resulting binary contains compressed assemblies. Container scanners may not see them as separate packages. Use `dotnet list package` against the source project for an accurate inventory.
- **`<PackageReference>` with no `Version` attribute relies on CPM.** If CPM isn't set up, the package fails to restore. If CPM is set up but the `Directory.Packages.props` is missing the entry, you get the floor version (often a very old one). CVE flags may be against unexpectedly old versions.

## Reachability

- `dotnet list package --include-transitive` enumerates the graph.
- Roslyn analyzers (`Microsoft.CodeAnalysis`) can query for method calls; `dotnet build /p:RunAnalyzers=true`.
- Runtime: dotCover or `coverlet` integrated with `dotnet test`.
