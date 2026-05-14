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

## Reachability

- `bundle viz` produces a Graphviz of the gem graph.
- `bundle show --paths` lists every gem's source location.
- For call analysis: `ruby-static-analyzer`, or runtime tracing with `TracePoint`.
- Runtime: SimpleCov.
