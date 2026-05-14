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

## Developer gotchas — written for people who live in the code

- **PHP runtime version constraints in `composer.json` aren't always enforced.** `"php": "^8.2"` is checked against the active PHP at install time; deploying to a different PHP version is up to your hosting. A CVE specific to PHP 7 may flag if your container still runs PHP 7 even though your `composer.json` says 8.2.
- **`require` vs `require-dev` — production install drops dev.** `composer install --no-dev` is the prod default; CVE in PHPUnit isn't reachable. CI test runs *do* install dev, so test-time CVE exposure is real but ephemeral.
- **Autoloader namespaces vs file paths.** PSR-4 maps namespaces to directories; PSR-0 was the old hyphen-to-slash convention. Mixed `composer.json` declarations cause silent dead code. A class that "isn't autoloaded" isn't reachable, even if its file is in `vendor/`.
- **Wordpress / Laravel / Symfony ecosystems have meta-packages.** `laravel/framework` pulls dozens of `symfony/*` packages. A CVE on a Symfony component flagged via `laravel/framework` requires you to either bump Laravel (chain bump) or override the Symfony component directly via a top-level `require`.
- **Composer scripts run on install.** `scripts: { "post-install-cmd": [...] }` execute `composer install`. CVEs on packages that contribute to `post-install` are install-time-reachable on every dev machine and CI runner.
- **`platform` overrides simulate other PHP versions.** `"config": { "platform": { "php": "7.4" } }` makes Composer resolve as if PHP 7.4 — even on a 8.3 host. CVEs may flag against the simulated version, not the real one.
- **Autoloader caching survives `composer update`.** `vendor/composer/autoload_classmap.php` is regenerated on each `composer dump-autoload`; if you bumped a dep but skipped that step, old class paths persist.

## Reachability

- `composer show -t <pkg>` produces a tree.
- `phpcallgraph` for method-level reachability.
- Runtime: Xdebug code coverage.
