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

## Reachability

- `dotnet list package --include-transitive` enumerates the graph.
- Roslyn analyzers (`Microsoft.CodeAnalysis`) can query for method calls; `dotnet build /p:RunAnalyzers=true`.
- Runtime: dotCover or `coverlet` integrated with `dotnet test`.
