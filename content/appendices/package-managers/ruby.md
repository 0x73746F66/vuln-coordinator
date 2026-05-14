---
title: "Ruby — Bundler"
description: "Gemfile, Gemfile.lock, transitive coercion via explicit declaration."
weight: 60
---

## Bundler / RubyGems (`Gemfile.lock`)

```ruby
# Gemfile
gem "rails", "~> 7.1.0"
gem "nokogiri", ">= 1.16.5"   # explicit pin to coerce transitive
```

```bash
bundle update nokogiri
bundle install --frozen
```

Bundler doesn't expose a separate transitive-coercion mechanism — to coerce a transitive, declare it explicitly in the `Gemfile`. The `BUNDLED WITH` line at the bottom of `Gemfile.lock` pins the Bundler version; mismatches across the team cause subtle resolution drift.

Gotcha: `bundle update` without args re-resolves everything; always pass the gem name.

## Developer gotchas — written for people who live in the code

- **`require` and `Gem` namespacing are loose.** `gem "nokogiri"` lets you `require "nokogiri"`; nothing prevents `require "nokogiri/xml"` from triggering autoloads of vulnerable submodules. Reachability requires reading the `lib/` tree of the gem, not just your `Gemfile`.
- **Native extensions are compiled on install.** A CVE in `libxml2` linked into the `nokogiri` gem isn't in `Gemfile.lock`. Scanners that read `Gemfile.lock` miss it; image scanners (Grype) catch it. Always pair Bundler scans with a container scan if you care about C dep CVEs.
- **`bundle install --deployment` vs `bundle install`.** Deployment mode installs gems into `vendor/bundle/` and refuses to update the lockfile. CI should use `--deployment`; dev iteration uses regular `bundle install`. CVE counts can differ if dev installs newer versions outside the lockfile.
- **`Gemfile.lock` group sections.** `group :development, :test do ... end` — gems in those groups don't ship to prod unless `BUNDLE_WITHOUT` is unset. CVE in `pry` is dev-only; runtime not-affected. `Bundler.require(:default)` in your `Gemfile.rb` boot sequence excludes test/dev groups.
- **Rails autoloading (Zeitwerk) makes reachability fuzzy.** Code in `app/services/` is only loaded when referenced. A CVE in a gem that's only used by one rarely-invoked controller may be loaded lazily — runtime reachability depends on traffic patterns.
- **`Gemfile.lock` `BUNDLED WITH` mismatch causes silent re-resolution.** If your CI installs Bundler 2.5.x and the lock says 2.4.x, Bundler re-resolves. Resolved versions may drift. Pin Bundler in CI.

## Reachability

- `bundle viz` produces a Graphviz of the gem graph.
- `bundle show --paths` lists every gem's source location.
- For call analysis: `ruby-static-analyzer`, or runtime tracing with `TracePoint`.
- Runtime: SimpleCov.
