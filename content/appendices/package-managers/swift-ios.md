---
title: "Swift / iOS — SwiftPM, CocoaPods, Carthage"
description: "Three competing dependency managers for the Apple ecosystem."
weight: 90
---

## SwiftPM (`Package.resolved`)

```swift
// Package.swift
.package(url: "https://github.com/apple/swift-nio.git", exact: "2.65.0"),

// Or for a version range:
.package(url: "...", .upToNextMajor(from: "2.0.0")),
```

```bash
swift package update
swift package resolve   # write Package.resolved without building
```

`exact()` is the strictest constraint; `upToNextMajor` and `upToNextMinor` give caret-style ranges. `Package.resolved` records the resolved git SHA per dep. Transitive coercion isn't a first-class feature — declare the package directly with `exact()`.

Gotcha: SwiftPM's resolver is slow on large graphs; consider committing `Package.resolved` to avoid re-resolving in CI.

## CocoaPods (`Podfile.lock`)

```ruby
# Podfile
pod 'Alamofire', '5.9.1'
pod 'Starscream', '~> 4.0'   # coerce transitive by declaring directly
```

```bash
pod update Alamofire
pod install --deployment   # frozen install
```

CocoaPods' lockfile records the resolved version per pod. Coercion follows the Bundler pattern — declare the transitive directly in the Podfile.

Gotcha: `pod install` vs `pod update` semantics — `install` honours the lockfile, `update` re-resolves.

## Carthage (`Cartfile.resolved`)

```bash
carthage update Alamofire --use-xcframeworks
```

Carthage is simpler than SwiftPM / CocoaPods — fewer features, less drift. Resolution is direct; coercion is by editing the `Cartfile`.

Gotcha: Carthage builds frameworks from source; an upgrade can break ABI compatibility with downstream consumers if the platform version is bumped.

## Developer gotchas — written for people who live in the code

- **Xcode and SwiftPM CLI use different caches.** Xcode caches in `~/Library/Developer/Xcode/DerivedData/`; CLI uses `.build/`. After a manifest bump, both need clearing.
- **`Package.resolved` lives in two places.** In an SwiftPM-only repo it's at the root. In an Xcode project it's nested at `<project>.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved`. Scanners that only look at the root may miss it.
- **CocoaPods and SwiftPM coexisting in the same project.** Some libs are only available on one. Scanners may flag a dep twice (once per resolver). Reconcile in your VEX by stating which resolver's artefact is actually linked.
- **Binary frameworks (`.xcframework`) are scanner-opaque.** Their contents aren't visible to source-level tooling. A CVE in a vendored xcframework requires the vendor to ship a fix; you can't bump it locally.
- **`#if canImport(Foo)` makes reachability conditional.** Compile-time module availability changes which Swift files are included. A CVE in a conditional import path may not be in your shipping binary.
- **iOS App Store distribution strips dead code.** Swift's `-Onone` debug builds keep more code than `-O` release builds. Reachability via runtime traces against debug builds over-estimates what ships.

## Reachability

- `swift package show-dependencies --format json | jq` for the resolved graph.
- The Xcode call graph instrument shows runtime call edges.
- Runtime: `xcodebuild -enableCodeCoverage YES`.
