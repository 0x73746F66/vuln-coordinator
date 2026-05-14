---
title: "PHP — Composer"
description: "composer.json, composer.lock, conflict declarations."
weight: 80
---

## Composer (`composer.lock`)

```bash
composer update guzzlehttp/guzzle

# Coerce a transitive: declare it directly in composer.json's require
composer update --lock
```

Composer's `composer.lock` carries per-package SHA-1 of the dist archive. To coerce a transitive, add it to `require` (production) or `require-dev` with the required version constraint — Composer resolves the constraint against the entire graph. Conflict declarations (`conflict` key in `composer.json`) make Composer refuse to install a specific (vulnerable) version range.

Gotcha: Composer's autoloader caches aggressively; `composer dump-autoload -o` after an upgrade if you see stale class resolutions.

## Reachability

- `composer show -t <pkg>` produces a tree.
- `phpcallgraph` for method-level reachability.
- Runtime: Xdebug code coverage.
