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

## Reachability

- `swift package show-dependencies --format json | jq` for the resolved graph.
- The Xcode call graph instrument shows runtime call edges.
- Runtime: `xcodebuild -enableCodeCoverage YES`.
